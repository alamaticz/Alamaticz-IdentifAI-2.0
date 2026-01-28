import os
import json
import io
import time
import uuid
import re
import hashlib
from typing import Dict, List, Optional
import zipfile
import tempfile
import shutil
from dotenv import load_dotenv
from opensearchpy import OpenSearch, helpers

# Import normalization logic
from log_normalizer import normalize_error_pattern

# Load environment variables
load_dotenv(override=True)

# --- Configuration ---
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS")
# TARGET RAW LOGS INDEX
INDEX_NAME = "pega-logs"

# Tunable settings - FINAL SAFE CONFIG (t3.small)
CHUNK_SIZE = 1500
MAX_CHUNK_BYTES = 8 * 1024 * 1024  # 8 MB Safe
CLIENT_TIMEOUT = int(os.getenv("OPENSEARCH_TIMEOUT", "120"))
THREAD_COUNT = 3
MAX_RETRIES = 3
QUEUE_SIZE = 3
MAX_RETRY_QUEUE = 50000 


def get_opensearch_client():
    """Create and return OpenSearch client."""
    if not OPENSEARCH_URL:
        raise ValueError("OPENSEARCH_URL not set in .env")
        
    auth = (OPENSEARCH_USER, OPENSEARCH_PASS) if OPENSEARCH_USER else None
    
    return OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_auth=auth,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=CLIENT_TIMEOUT,

        max_retries=3,
        retry_on_timeout=True,
        retry_on_status=(500, 502, 503, 504), # REMOVE 429
    )

def retry_failed_docs(client, retry_docs):
    """
    Retry failed documents with exponential backoff.
    Returns (success_count, failed_docs).
    """
    backoff = 1
    current_docs = retry_docs
    total_retry_success = 0
    
    for attempt in range(MAX_RETRIES):
        if not current_docs:
            return total_retry_success, []
            
        print(f"[RETRY] Attempt {attempt+1}/{MAX_RETRIES} for {len(current_docs)} docs")
        next_retry_queue = []
        batch_success = 0
        
        # Sanitize docs
        safe_docs = []
        for doc in current_docs:
            if isinstance(doc, dict):
                if "_index" not in doc:
                    doc["_index"] = INDEX_NAME
                
                doc["_index"] = doc.get("_index", INDEX_NAME) 
                doc["_op_type"] = doc.get("_op_type", "index")
                
                if not any(k.startswith("_") for k in doc.keys()):
                     safe_docs.append({
                         "_index": INDEX_NAME,
                         "_op_type": "index",
                         "_source": doc
                     })
                     continue

            safe_docs.append(doc)
            
        try:
            results_iter = helpers.streaming_bulk(
                client,
                safe_docs,
                raise_on_error=False,
                request_timeout=120,
                chunk_size=500
            )
            
            for (success, info), original_doc in zip(results_iter, current_docs):
                if success:
                    batch_success += 1
                else:
                    action = info.get("create") or info.get("index") or {}
                    status = action.get("status")
                    
                    if status in (429, 500, 502, 503, 504):
                        next_retry_queue.append(original_doc)
                    else:
                        print(f"[RETRY ERROR] Permanent failure status {status}: {info}")
            
            total_retry_success += batch_success

        except Exception as e:
            print(f"[WARN] Exception during retry batch: {e}")
            next_retry_queue = current_docs
            
        current_docs = next_retry_queue
        
        if current_docs:
            time.sleep(backoff)
            backoff = min(backoff * 2, 10)
            
    return total_retry_success, current_docs

class OptimizeIndexSettings:
    """Context manager to optimize index settings for bulk ingestion."""
    def __init__(self, client, index_name):
        self.client = client
        self.index_name = index_name

    def __enter__(self):
        print(f"[INFO] Optimizing index settings for {self.index_name}...")
        try:
            self.client.indices.put_settings(index=self.index_name, body={
                "index": {
                    "refresh_interval": "-1",
                    "number_of_replicas": 0,
                    "translog.durability": "async",
                    "translog.sync_interval": "30s"
                }
            })
        except Exception as e:
            print(f"[WARN] Failed to optimize settings: {e}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print(f"[INFO] Restoring index settings for {self.index_name}...")
        try:
            self.client.indices.put_settings(index=self.index_name, body={
                "index": {
                    "refresh_interval": "1s",
                    "number_of_replicas": 1
                }
            })
            self.client.indices.refresh(index=self.index_name)
        except Exception as e:
            print(f"[WARN] Failed to restore settings: {e}")

# --- Pega Parsing Logic ---

def parse_generated_rule_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a single stack trace line containing 'com.pegarules.generated'."""
    line = line.strip()
    if "com.pegarules.generated" not in line:
        return None
    
    start_idx = line.find("com.pegarules.generated")
    if start_idx < 0:
        return None
    
    relevant_part = line[start_idx:]
    paren_idx = relevant_part.find("(")
    
    if paren_idx < 0:
        last_dot_idx = relevant_part.rfind(".")
        if last_dot_idx < 0:
            return None
        
        method_part = relevant_part[last_dot_idx + 1:]
        method_part = method_part.strip().split()[0] if method_part.strip() else ""
        
        class_generated = relevant_part[:last_dot_idx]
        function_invoked = method_part
    else:
        before_paren = relevant_part[:paren_idx].strip()
        last_dot_idx = before_paren.rfind(".")
        if last_dot_idx < 0:
            return None
        
        class_generated = before_paren[:last_dot_idx]
        function_invoked = before_paren[last_dot_idx + 1:].strip()
    
    last_dot_in_class = class_generated.rfind(".")
    if last_dot_in_class < 0:
        type_of_rule = ""
        rule_generated = class_generated
    else:
        type_of_rule = class_generated[:last_dot_in_class]
        rule_generated = class_generated[last_dot_in_class + 1:]
    
    rule_generated = re.sub(r'_[0-9a-fA-F]{32}$', '', rule_generated)
    class_generated = re.sub(r'_[0-9a-fA-F]{32}$', '', class_generated)
    
    class_name_in_parens = ""
    if paren_idx >= 0 and paren_idx < len(relevant_part) - 1:
        close_paren_idx = relevant_part.find(")", paren_idx + 1)
        if close_paren_idx > paren_idx:
            paren_content = relevant_part[paren_idx + 1:close_paren_idx].strip()
            if paren_content:
                if ".java:" in paren_content:
                    class_name_in_parens = paren_content.split(".java:")[0].strip()
                elif ":" in paren_content:
                    class_name_in_parens = paren_content.split(":")[0].strip()
                else:
                    class_name_in_parens = paren_content.strip()
    
    return {
        "ClassGenerated": class_generated,
        "FunctionInvoked": function_invoked,
        "TypeOfTheRule": type_of_rule,
        "RuleGenerated": rule_generated,
        "ClassNameInParens": class_name_in_parens,
    }

def extract_stacktrace_from_log_entry(log_entry: Dict) -> Optional[str]:
    """Extract stacktrace from a Pega log entry JSON."""
    log = log_entry.get("log", {}) or {}
    exc = log.get("exception", {}) or {}
    stack = exc.get("stacktrace") or log.get("stack")
    return stack if stack else None

def extract_exception_info_from_log_entry(log_entry: Dict) -> Dict[str, str]:
    """Extract and normalize exception information."""
    log = log_entry.get("log", {}) or {}
    exc = log.get("exception", {}) or {}
    
    exception_class = exc.get("exception_class", "").strip() or ""
    exception_message = exc.get("exception_message", "").strip() or ""
    message = log.get("message", "").strip() or ""
    
    if not exception_message:
        exception_message = message
    
    MAX_KEYWORD_LENGTH = 32000
    normalized_exception_message = normalize_error_pattern(exception_message)[:MAX_KEYWORD_LENGTH]
    normalized_message = normalize_error_pattern(message)[:MAX_KEYWORD_LENGTH]
    
    return {
        "exception_class": exception_class,
        "exception_message": exception_message,
        "message": message,
        "normalized_exception_message": normalized_exception_message,
        "normalized_message": normalized_message,
    }

def extract_sequence_from_stack_trace(stack_trace: str) -> List[Dict[str, str]]:
    """Extract the sequence of generated classes from a stack trace."""
    sequence = []
    lines = stack_trace.splitlines()
    
    pattern = re.compile(
        r'com\.pegarules\.generated[^\s(]+\.\w+\s*\([^)]*\)',
        re.MULTILINE
    )
    pattern_simple = re.compile(
        r'com\.pegarules\.generated[^\s]+\.\w+',
        re.MULTILINE
    )
    
    found_positions = []
    
    for match in pattern.finditer(stack_trace):
        match_text = match.group(0)
        match_line_num = stack_trace[:match.start()].count('\n') + 1
        found_positions.append((match_line_num, match.start(), match_text))
    
    for match in pattern_simple.finditer(stack_trace):
        already_found = any(
            abs(match.start() - pos) < 50 
            for _, pos, _ in found_positions
        )
        if not already_found:
            match_text = match.group(0)
            match_line_num = stack_trace[:match.start()].count('\n') + 1
            found_positions.append((match_line_num, match.start(), match_text))
    
    found_positions.sort(key=lambda x: x[1])
    
    sequence_order = 0
    for line_num, pos, match_text in found_positions:
        line = match_text.strip()
        if line.startswith("at "):
            line = line[3:].strip()
        
        parsed = parse_generated_rule_line(line)
        if parsed:
            sequence_order += 1
            parsed["SequenceOrder"] = sequence_order
            parsed["LineNumber"] = line_num
            # original_line = lines[line_num - 1] if line_num <= len(lines) else match_text
            # parsed["OriginalLine"] = original_line.strip()
            sequence.append(parsed)
            
    if not sequence:
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if not line: continue
            if line.startswith("at "): line = line[3:].strip()
            
            parsed = parse_generated_rule_line(line)
            if parsed:
                sequence_order += 1
                parsed["SequenceOrder"] = sequence_order
                parsed["LineNumber"] = line_num
                sequence.append(parsed)
                
    return sequence

# --- Ingestion Logic ---

def ensure_index(client):
    """Ensure OpenSearch index exists with correct mapping."""
    if not client.indices.exists(index=INDEX_NAME):
        index_body = {
            "settings": {
                "number_of_shards": 3, # Use 3 Shards
                "number_of_replicas": 0,
                "refresh_interval": "1s",
            },
            "mappings": {
                "properties": {
                    "date": {"type": "date"},
                    "time": {"type": "date"},
                    "log": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "level": {"type": "keyword"},
                            "thread_name": {"type": "keyword"},
                            "message": {"type": "text"},
                            "logger_name": {"type": "keyword"},
                            "source_host": {"type": "keyword"},
                        }
                    },
                    "exception_class": {"type": "keyword"},
                    "exception_message": {"type": "text"},
                    "normalized_exception_message": {"type": "keyword"},
                    "normalized_message": {"type": "keyword"},
                    "generated_rule_lines_found": {"type": "integer"},
                    "total_lines_in_stack": {"type": "integer"},
                    "input_length": {"type": "integer"},
                    "sequence_summary": {
                        "type": "text", # Single flattened field
                        "index": False,
                        # "store": True # optional if you need to retrieve it
                    },
                    "session_id": {"type": "keyword"},
                    "ingestion_timestamp": {"type": "date"},
                    "file_name": {"type": "keyword"},
                }
            },
        }
        client.indices.create(index=INDEX_NAME, body=index_body)
        print(f"Created index: {INDEX_NAME}")
    else:
        print(f"Index already exists: {INDEX_NAME}")

def ingest_log_stream(file_name: str, line_iterator):
    """
    Core ingestion logic that reads lines from an iterator (file or stream).
    """
    client = get_opensearch_client()
    ensure_index(client)
    
    session_id = str(uuid.uuid4())
    ingestion_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    ignored_local = 0
    skipped_safe = 0
    start_time_ref = time.time()
    
    def actions():
        nonlocal ignored_local, ingestion_ts, skipped_safe
        line_number = 0
        
        for raw_line in line_iterator:
                line_number += 1
                if line_number % 50000 == 0:
                     elapsed = time.time() - start_time_ref
                     print(f"[SCAN] Scanned {line_number:,} lines... ({elapsed:.1f}s) | Ignored Safe: {skipped_safe:,}")

                line = raw_line.strip()
                if not line:
                    continue

                try:
                    # --- FAST FILTER (Pre-JSON) ---
                    # Skips json.loads for 99% of logs (non-errors)
                    if "ERROR" not in line and "exception" not in line and "FATAL" not in line and "FAIL" not in line:
                         skipped_safe += 1
                         continue
                    # ------------------------------

                    log_entry = json.loads(line)
                    
                    extracted_ts = log_entry.get("@timestamp") or log_entry.get("log", {}).get("timestamp")
                    if extracted_ts:
                         ingestion_ts = extracted_ts
                    else:
                         ingestion_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

                    stack_trace = extract_stacktrace_from_log_entry(log_entry)
                    
                    # Log Level Check (fallback)
                    log_lvl = log_entry.get("level") or log_entry.get("log", {}).get("level") or ""
                    log_lvl = str(log_lvl).upper()
                    
                    is_error = "ERROR" in log_lvl or "FATAL" in log_lvl or "FAIL" in log_lvl
                    has_exception = stack_trace is not None or "exception" in log_entry.get("log", {})
                    
                    if not (is_error or has_exception):
                        skipped_safe += 1
                        continue 

                    extraction_sequence = []
                    # sequence_summary mapping changed to TEXT, so we prepare a string
                    sequence_summary_str = ""
                    
                    generated_rule_lines_found = 0
                    total_lines_in_stack = 0
                    input_length = 0
                    
                    if stack_trace:
                        extraction_sequence = extract_sequence_from_stack_trace(stack_trace)
                        input_length = len(stack_trace)
                        total_lines_in_stack = len(stack_trace.splitlines())
                        generated_rule_lines_found = len(extraction_sequence)
                        
                        # Collapse sequence mapping into one string
                        parts = []
                        for item in extraction_sequence:
                             val = f"{item['TypeOfTheRule']}->{item['RuleGenerated']}->{item['FunctionInvoked']}->{item['ClassGenerated']}"
                             parts.append(f"{item['SequenceOrder']}:{val}")
                        sequence_summary_str = " | ".join(parts)

                        # Remove massive stack fields
                        if "log" in log_entry:
                            if "exception" in log_entry["log"]:
                                log_entry["log"]["exception"].pop("stacktrace", None)
                            log_entry["log"].pop("stack", None)
                    
                    exc_info = extract_exception_info_from_log_entry(log_entry)
                    
                    log_entry.update({
                        "exception_class": exc_info["exception_class"],
                        "exception_message": exc_info["exception_message"],
                        "normalized_exception_message": exc_info["normalized_exception_message"],
                        "normalized_message": exc_info["normalized_message"],
                        "generated_rule_lines_found": generated_rule_lines_found,
                        "total_lines_in_stack": total_lines_in_stack,
                        "input_length": input_length,
                        "sequence_summary": sequence_summary_str, # Plain Text
                        
                        "session_id": session_id,
                        "ingestion_timestamp": ingestion_ts,
                        "file_name": file_name,
                    })

                    unique_string = f"{file_name}_{line_number}_{line.strip()}"
                    doc_id = hashlib.md5(unique_string.encode('utf-8')).hexdigest()

                    yield {
                        "_op_type": "index", # Efficient Upsert
                        "_index": INDEX_NAME,
                        "_id": doc_id,
                        "_source": log_entry,
                    }

                except json.JSONDecodeError:
                    ignored_local += 1
                except Exception as e:
                    print(f"Error processing line {line_number}: {e}")
                    ignored_local += 1
    
    success_count = 0
    failure = 0
    duplicates = 0
    retry_queue = []
    
    try:
        from tqdm import tqdm
        use_tqdm = True
    except ImportError:
        use_tqdm = False

    print(f"Starting ingestion for: {file_name}")
    print(f"Index: {INDEX_NAME}")
    
    try:
        iterator = actions()
        if use_tqdm:
            iterator = tqdm(iterator, unit="lines", desc="Ingesting (Errors Found)")
                        
        with OptimizeIndexSettings(client, INDEX_NAME):
            
            for success, info in helpers.parallel_bulk(
                client,
                iterator,
                thread_count=THREAD_COUNT,
                queue_size=QUEUE_SIZE, 
                chunk_size=CHUNK_SIZE,
                max_chunk_bytes=MAX_CHUNK_BYTES, 
                raise_on_error=False,
                raise_on_exception=False,
                request_timeout=CLIENT_TIMEOUT,

            ):
                if success:
                    success_count += 1
                else:
                    op_result = info.get('create') or info.get('index') or {}
                    status_code = op_result.get('status')
                    
                    # Backpressure Fix
                    if status_code == 429:
                        time.sleep(0.05) 

                    if status_code == 409:
                        duplicates += 1
                    elif status_code in (429, 500, 502, 503, 504):
                        # Retry
                        original_doc = op_result.get('data')
                        if original_doc:
                             if len(retry_queue) >= MAX_RETRY_QUEUE:
                                 if len(retry_queue) == MAX_RETRY_QUEUE:
                                     print("\n[WARN] Retry queue full! Flushing to disk.")
                                     with open("failed_docs.jsonl", "a", encoding="utf-8") as f:
                                         for d in retry_queue:
                                             f.write(json.dumps(d) + "\n")
                                     retry_queue = []
                                 
                                 with open("failed_docs.jsonl", "a", encoding="utf-8") as f:
                                     f.write(json.dumps(original_doc) + "\n")
                                 failure += 1
                             else:
                                 retry_queue.append(original_doc)
                        else:
                             failure += 1
                    else:
                        if failure < 5:
                             print(f"\n[ERROR] Failed doc (Status {status_code}): {info}")
                        failure += 1
                
                if not use_tqdm and (success_count + duplicates + failure) % 5000 == 0:
                    print(f"Processed {success_count + duplicates + failure} lines...", end='\r')
        
        if retry_queue:
            print(f"\n[INFO] Retrying {len(retry_queue)} failed documents...")
            retry_success, final_failed = retry_failed_docs(client, retry_queue)
            
            success_count += retry_success
            
            if final_failed:
                print(f"[WARN] {len(final_failed)} documents failed permanently after retries.")
                failure += len(final_failed)
                
                with open("failed_docs.jsonl", "a", encoding="utf-8") as f:
                    for doc in final_failed:
                        f.write(json.dumps(doc) + "\n")
            else:
                print(f"[INFO] All {retry_success} retries successful!")

    except Exception as e:
        print(f"Bulk indexing error: {e}")
        return {"status": "error", "message": str(e)}

    print(f"\nIngestion Complete for {file_name}")
    return {
        "status": "success",
        "session_id": session_id,
        "total_indexed": success_count,
        "failed": failure,
        "duplicates_skipped": duplicates,
        "ignored": ignored_local,
        "skipped_safe_logs": skipped_safe,
        "file_name": file_name
    }

def ingest_single_file(file_path: str):
    file_name = os.path.basename(file_path)
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return ingest_log_stream(file_name, f)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return {"status": "error", "message": str(e)}

def ingest_file(file_path: str):
    if file_path.lower().endswith(".zip"):
        print(f"Detected ZIP file: {file_path}")
        aggregated_result = {
            "status": "success",
            "session_id": str(uuid.uuid4()),
            "total_indexed": 0,
            "failed": 0,
            "duplicates_skipped": 0,
            "ignored": 0,
            "files_processed": []
        }
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                for zip_info in zip_ref.infolist():
                    if zip_info.is_dir(): continue
                    
                    print(f"Processing ZIP entry: {zip_info.filename}")
                    
                    with zip_ref.open(zip_info) as binary_file:
                        with io.TextIOWrapper(binary_file, encoding='utf-8', errors='ignore') as text_file:
                            # Read full content to support pretty-printed JSON or JSON Arrays
                            content = text_file.read()
                            
                            try:
                                # Attempt to parse the whole file as JSON (List or Single Dict)
                                parsed_data = json.loads(content)
                                
                                # If it's a list, treat it as a stream of logs
                                if isinstance(parsed_data, list):
                                    print(f"Detected JSON Array with {len(parsed_data)} items.")
                                    iterator = (json.dumps(item) for item in parsed_data)
                                    res = ingest_log_stream(zip_info.filename, iterator)
                                    
                                elif isinstance(parsed_data, dict):
                                    print("Detected Single JSON Object (Pretty Printed).")
                                    iterator = [json.dumps(parsed_data)]
                                    res = ingest_log_stream(zip_info.filename, iterator)
                                else:
                                    # Fallback for primitives? unlikely.
                                    raise ValueError("Not a list or dict")
                                    
                            except json.JSONDecodeError:
                                # Fallback to Line-by-Line (NDJSON or Raw Text)
                                iterator = content.splitlines()
                                res = ingest_log_stream(zip_info.filename, iterator)
                            
                            aggregated_result["total_indexed"] += res.get("total_indexed", 0)
                            aggregated_result["failed"] += res.get("failed", 0)
                            aggregated_result["duplicates_skipped"] += res.get("duplicates_skipped", 0)
                            aggregated_result["ignored"] += res.get("ignored", 0)
                            aggregated_result["files_processed"].append(zip_info.filename)
            
            print(f"ZIP Ingestion Complete.")
            return aggregated_result
            
        except Exception as e:
            print(f"Error processing ZIP: {e}")
            return {"status": "error", "message": str(e)}
    else:
        return ingest_single_file(file_path)

def ingest_failed_docs(file_path: str):
    print(f"Starting RETRY ingestion from: {file_path}")
    client = get_opensearch_client()
    ensure_index(client)
    
    def retry_actions():
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f):
                line = line.strip()
                if not line: continue
                try:
                    doc = json.loads(line)
                    source_doc = doc
                    if "_source" in doc and "_index" in doc:
                         source_doc = doc["_source"]

                    # Apply truncation fix to retried docs
                    if "normalized_exception_message" in source_doc:
                        source_doc["normalized_exception_message"] = source_doc["normalized_exception_message"][:32000]
                    if "normalized_message" in source_doc:
                        source_doc["normalized_message"] = source_doc["normalized_message"][:32000]

                    doc_str = json.dumps(source_doc, sort_keys=True)
                    doc_id = hashlib.md5(doc_str.encode('utf-8')).hexdigest()
                    
                    yield {
                        "_op_type": "index", 
                        "_index": INDEX_NAME,
                        "_id": doc_id,
                        "_source": source_doc
                    }
                except Exception as e:
                    print(f"Skipping bad line {line_num}: {e}")

    success_count = 0
    failure_count = 0
    duplicates = 0
    
    try:
        from tqdm import tqdm
        iterator = tqdm(retry_actions(), desc="Retrying")
    except ImportError:
        iterator = retry_actions()

    with OptimizeIndexSettings(client, INDEX_NAME):
        for success, info in helpers.parallel_bulk(
            client,
            iterator,
            thread_count=THREAD_COUNT,
            chunk_size=CHUNK_SIZE,
            raise_on_error=False,
            raise_on_exception=False,
            request_timeout=CLIENT_TIMEOUT
        ):
            if success:
                success_count += 1
            else:
                action = info.get('create') or info.get('index') or {}
                status = action.get('status')
                if status == 409:
                    duplicates += 1
                else:
                    failure_count += 1

    print(f"\nRetry Complete.")
    return {
        "status": "success",
        "retried_indexed": success_count,
        "failed_again": failure_count,
        "duplicates_skipped": duplicates,
        "file": file_path
    }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingest Pega logs Optimized to raw-logs index")
    parser.add_argument("file", nargs="?", help="Path to log file (for standard ingestion)")
    parser.add_argument("--retry-file", help="Path to failed_docs.jsonl to retry ingestion")
    args = parser.parse_args()
    
    if args.retry_file:
         if os.path.exists(args.retry_file):
             ingest_failed_docs(args.retry_file)
    elif args.file:
        if os.path.exists(args.file):
            ingest_file(args.file)
        else:
            print(f"File not found: {args.file}")
    else:
        parser.print_help()
