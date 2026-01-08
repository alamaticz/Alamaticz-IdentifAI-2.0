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
INDEX_NAME = os.getenv("INDEX_NAME", "pega-logs")

# Tunable settings
# Optimized for stability and speed based on user request (t3.small)
CHUNK_SIZE = int(os.getenv("BULK_CHUNK_SIZE", "2500"))  # Aggressive batch size
MAX_CHUNK_BYTES = 20 * 1024 * 1024  # 20 MB limit
CLIENT_TIMEOUT = int(os.getenv("OPENSEARCH_TIMEOUT", "120"))
THREAD_COUNT = int(os.getenv("INGESTION_THREADS", "8"))  # Aggressive threading
MAX_RETRIES = 3
QUEUE_SIZE = 6
MAX_RETRY_QUEUE = 50000  # Hard cap for memory safety


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

        max_retries=10,
        retry_on_timeout=True,
        retry_on_status=(429, 500, 502, 503, 504),
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
        
        # Sanitize docs: Ensure _index and _op_type are present
        safe_docs = []
        for doc in current_docs:
            if isinstance(doc, dict):
                # If doc is missing key metadata, re-add it
                if "_index" not in doc:
                    doc["_index"] = "pega-logs" # Assume default index
                
                doc["_index"] = doc.get("_index", "pega-logs") 
                doc["_op_type"] = doc.get("_op_type", "index")
                
                # Check if it's a raw source doc (no underscore keys)
                if not any(k.startswith("_") for k in doc.keys()):
                     # It is likely a source document. Wrap it.
                     safe_docs.append({
                         "_index": "pega-logs",
                         "_op_type": "index",
                         "_source": doc
                     })
                     continue

            safe_docs.append(doc)
            
        # We use streaming_bulk to match results to inputs (preserves order)
        try:
            results_iter = helpers.streaming_bulk(
                client,
                safe_docs,
                raise_on_error=False,
                request_timeout=120,
                chunk_size=500 # Smaller chunk for retries
            )
            
            # Iterate safely
            for (success, info), original_doc in zip(results_iter, current_docs):
                if success:
                    batch_success += 1
                else:
                    action = info.get("create") or info.get("index") or {}
                    status = action.get("status")
                    
                    if status in (429, 500, 502, 503, 504):
                        # Transient error, retry next time
                        next_retry_queue.append(original_doc)
                    else:
                        # Permanent error (400, 409 etc), log and drop
                        print(f"[RETRY ERROR] Permanent failure status {status}: {info}")
            
            total_retry_success += batch_success

        except Exception as e:
            print(f"[WARN] Exception during retry batch: {e}")
            # If batch fails hard, retry all current_docs (optimistic)
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
        self.original_settings = {}

    def __enter__(self):
        print(f"[INFO] Optimizing index settings for {self.index_name}...")
        try:
            # We minimize load by disabling refresh and replicas
            self.client.indices.put_settings(index=self.index_name, body={
                "index": {
                    "refresh_interval": "-1",
                    "number_of_replicas": 0
                }
            })
        except Exception as e:
            print(f"[WARN] Failed to optimize settings: {e}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        print(f"[INFO] Restoring index settings for {self.index_name}...")
        try:
            # Restore to standard production readiness
            self.client.indices.put_settings(index=self.index_name, body={
                "index": {
                    "refresh_interval": "1s",
                    "number_of_replicas": 1
                }
            })
            # Force a refresh so data is visible immediately after
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
    
    # Clean RuleGenerated by removing trailing 32-char hex hash
    rule_generated = re.sub(r'_[0-9a-fA-F]{32}$', '', rule_generated)
    # Clean ClassGenerated by removing trailing 32-char hex hash
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
    
    normalized_exception_message = normalize_error_pattern(exception_message)
    normalized_message = normalize_error_pattern(message)
    
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
    
    sequence_order = 0
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
    
    for line_num, pos, match_text in found_positions:
        line = match_text.strip()
        if line.startswith("at "):
            line = line[3:].strip()
        
        parsed = parse_generated_rule_line(line)
        if parsed:
            sequence_order += 1
            parsed["SequenceOrder"] = sequence_order
            parsed["LineNumber"] = line_num
            original_line = lines[line_num - 1] if line_num <= len(lines) else match_text
            parsed["OriginalLine"] = original_line.strip()
            sequence.append(parsed)
            
    if not sequence:
        for line_num, line in enumerate(lines, start=1):
            original_line = line
            line = line.strip()
            if not line: continue
            if line.startswith("at "): line = line[3:].strip()
            
            parsed = parse_generated_rule_line(line)
            if parsed:
                sequence_order += 1
                parsed["SequenceOrder"] = sequence_order
                parsed["LineNumber"] = line_num
                parsed["OriginalLine"] = original_line.strip()
                sequence.append(parsed)
                
    return sequence

# --- Ingestion Logic ---

def ensure_index(client):
    """Ensure OpenSearch index exists with correct mapping."""
    if not client.indices.exists(index=INDEX_NAME):
        index_body = {
            "settings": {
                "number_of_shards": 1,
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
                        "type": "object"
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
        # We might want to update mapping here if needed, but for now just assume it exists
        print(f"Index already exists: {INDEX_NAME}")

def ingest_log_stream(file_name: str, line_iterator):
    """
    Core ingestion logic that reads lines from an iterator (file or stream).
    """
    client = get_opensearch_client()
    ensure_index(client)
    
    session_id = str(uuid.uuid4())
    ingestion_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    total_indexed = 0
    ignored_local = 0
    
    def actions():
        nonlocal ignored_local, ingestion_ts
        line_number = 0
        
        for raw_line in line_iterator:
                line_number += 1
                if line_number % 50000 == 0:
                     print(f"[SCAN] Scanned {line_number} lines...", end='\r')

                line = raw_line.strip()
                if not line:
                    continue

                try:
                    # --- FAST FILTER (Pre-JSON) ---
                    # Optimization: Check for Error/Exception keywords in raw string first
                    # This saves expensive JSON parsing for 95% of INFO/DEBUG logs
                    raw_upper = line.upper()
                    if not ("ERROR" in raw_upper or "FATAL" in raw_upper or "FAIL" in raw_upper or "EXCEPTION" in raw_upper or "STACK" in raw_upper):
                         continue
                    # ------------------------------

                    # Attempt to parse as JSON
                    log_entry = json.loads(line)
                    
                    # Extract Timestamp from Log
                    # Priority: @timestamp (Pega standard) -> log.timestamp -> fallback to current ingestion time
                    extracted_ts = log_entry.get("@timestamp") or log_entry.get("log", {}).get("timestamp")
                    if extracted_ts:
                         # Use the log's own timestamp
                         ingestion_ts = extracted_ts
                    else:
                         # Fallback to current time if missing
                         ingestion_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

                    
                    # 1. Extract and Parse Stack Trace
                    stack_trace = extract_stacktrace_from_log_entry(log_entry)
                    
                    # --- FILTERING: Only Index Errors ---
                    # Logic: Check level or presence of exception/stacktrace
                    log_lvl = log_entry.get("level") or log_entry.get("log", {}).get("level") or ""
                    log_lvl = str(log_lvl).upper()
                    
                    is_error = "ERROR" in log_lvl or "FATAL" in log_lvl or "FAIL" in log_lvl
                    has_exception = stack_trace is not None or "exception" in log_entry.get("log", {})
                    
                    if not (is_error or has_exception):
                        continue # Skip non-error logs
                    # ------------------------------------

                    sequence_summary = {}
                    generated_rule_lines_found = 0
                    total_lines_in_stack = 0
                    input_length = 0
                    
                    if stack_trace:
                        sequence = extract_sequence_from_stack_trace(stack_trace)
                        input_length = len(stack_trace)
                        total_lines_in_stack = len(stack_trace.splitlines())
                        generated_rule_lines_found = len(sequence)
                        
                        # Simplify sequence for storage
                        for item in sequence:
                            val = f"{item['TypeOfTheRule']}->{item['RuleGenerated']}->{item['FunctionInvoked']}->{item['ClassGenerated']}"
                            sequence_summary[str(item['SequenceOrder'])] = val
                            
                        # Remove potentially large stack trace from source if desired?
                        # User said: "stack or stack trace should be removed"
                        if "log" in log_entry:
                            if "exception" in log_entry["log"]:
                                log_entry["log"]["exception"].pop("stacktrace", None)
                            log_entry["log"].pop("stack", None)
                    
                    # 2. Extract and Normalize Exception Info
                    exc_info = extract_exception_info_from_log_entry(log_entry)
                    
                    # 3. Enrich Log Entry
                    log_entry.update({
                        "exception_class": exc_info["exception_class"],
                        "exception_message": exc_info["exception_message"],
                        "normalized_exception_message": exc_info["normalized_exception_message"],
                        "normalized_message": exc_info["normalized_message"],
                        "generated_rule_lines_found": generated_rule_lines_found,
                        "total_lines_in_stack": total_lines_in_stack,
                        "input_length": input_length,
                        "sequence_summary": sequence_summary,
                        
                        "session_id": session_id,
                        "ingestion_timestamp": ingestion_ts,
                        "file_name": file_name,
                    })

                    # Generate Deterministic ID for Idempotency
                    # Hash(FileName + LineNumber + RawContent)
                    unique_string = f"{file_name}_{line_number}_{line.strip()}"
                    doc_id = hashlib.md5(unique_string.encode('utf-8')).hexdigest()

                    yield {
                        "_op_type": "create", # Only create if not exists
                        "_index": INDEX_NAME,
                        "_id": doc_id,
                        "_source": log_entry,
                    }

                except json.JSONDecodeError:
                    ignored_local += 1
                except Exception as e:
                    print(f"Error processing line {line_number}: {e}")
                    ignored_local += 1
    
    # Track stats
    success_count = 0
    failure = 0
    duplicates = 0
    retry_queue = []
    
    # Try to import tqdm for progress bar
    try:
        from tqdm import tqdm
        use_tqdm = True
    except ImportError:
        use_tqdm = False

    print(f"Starting ingestion for: {file_name}")
    print(f"Session ID: {session_id}")
    
    try:
        iterator = actions()
        if use_tqdm:
            iterator = tqdm(iterator, unit="lines", desc="Ingesting")
            
        # Use OptimizeIndexSettings for context
        with OptimizeIndexSettings(client, INDEX_NAME):
            
            # Adaptive backpressure variables
            backoff = 0.1
            
            # Switch to parallel_bulk for maximum throughput as requested
            # We rely on client-side max_retries=10 for reliability
            for success, info in helpers.parallel_bulk(
                client,
                iterator,
                thread_count=THREAD_COUNT,
                queue_size=THREAD_COUNT + 2, 
                chunk_size=CHUNK_SIZE,
                max_chunk_bytes=MAX_CHUNK_BYTES, 
                raise_on_error=False,
                raise_on_exception=False,
                request_timeout=CLIENT_TIMEOUT,

            ):
                if success:
                    success_count += 1
                else:
                    # info is like {'create': {'_index':..., 'status': 409, ...}}
                    op_result = info.get('create') or info.get('index') or {}
                    status_code = op_result.get('status')
                    
                    # No backoff/sleep here - firehose mode as requested

                    if status_code == 409:
                        duplicates += 1
                    elif status_code in (429, 500, 502, 503, 504):
                        # RETRY LOGIC
                        # With streaming_bulk, op_result often contains 'data' if error occurred?
                        # Or we are just iterating and can't easily peek 'original' from iterator unless we zip.
                        # However, for 429 errors from streaming_bulk, the 'data' field is usually populated.
                        original_doc = op_result.get('data')
                        if original_doc:
                             # Check queue size cap
                             if len(retry_queue) >= MAX_RETRY_QUEUE:
                                 if len(retry_queue) == MAX_RETRY_QUEUE:
                                     print("\n[WARN] Retry queue full! Flushing to disk to prevent OOM.")
                                     # Flush immediately to disk
                                     with open("failed_docs.jsonl", "a", encoding="utf-8") as f:
                                         for d in retry_queue:
                                             f.write(json.dumps(d) + "\n")
                                     retry_queue = [] # Clear memory
                                 
                                 # Write current one too
                                 with open("failed_docs.jsonl", "a", encoding="utf-8") as f:
                                     f.write(json.dumps(original_doc) + "\n")
                                 failure += 1
                             else:
                                 retry_queue.append(original_doc)
                        else:
                             print(f"[ERROR] Could not recover doc for retry (Status {status_code})")
                             failure += 1
                    else:
                        # Permanent failure
                        if failure < 5:
                             print(f"\n[ERROR] Failed doc (Status {status_code}): {info}")
                        failure += 1
                
                # Periodic print if no tqdm
                if not use_tqdm and (success_count + duplicates + failure) % 5000 == 0:
                    print(f"Processed {success_count + duplicates + failure} lines...", end='\r')
        
        # --- Stage 2: Retry Failed Docs ---
        if retry_queue:
            print(f"\n[INFO] Retrying {len(retry_queue)} failed documents...")
            retry_success, final_failed = retry_failed_docs(client, retry_queue)
            
            # Update stats logic:
            # Those that succeeded in retry are now successes.
            success_count += retry_success
            
            if final_failed:
                print(f"[WARN] {len(final_failed)} documents failed permanently after retries.")
                failure += len(final_failed)
                
                # Persist to disk
                with open("failed_docs.jsonl", "a", encoding="utf-8") as f:
                    for doc in final_failed:
                        f.write(json.dumps(doc) + "\n")
                print(f"[INFO] Written failed docs to failed_docs.jsonl")
            else:
                print(f"[INFO] All {retry_success} retries successful!")
                
            # IMPORTANT: We already captured duplicates/failures in the main loop differently.
            # But the 'retry_queue' items were originally counted as nothing (they were pending).
            # So adding success count is correct.
            # The failure count was NOT incremented for them yet.
            # So incrementing failure by len(final_failed) is correct.

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
        "file_name": file_name
    }

def ingest_single_file(file_path: str):
    """Ingest a single file from disk."""
    file_name = os.path.basename(file_path)
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return ingest_log_stream(file_name, f)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return {"status": "error", "message": str(e)}

def ingest_file(file_path: str):
    """Ingest a file (or ZIP of files) into OpenSearch."""
    # Check extension
    if file_path.lower().endswith(".zip"):
        print(f"Detected ZIP file: {file_path}")
        
        # Aggregate results
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
                # Iterate over files in the ZIP
                for zip_info in zip_ref.infolist():
                    if zip_info.is_dir():
                        continue
                    
                    # Optional: Filter for likely log files if needed
                    # if not (zip_info.filename.endswith('.log') or zip_info.filename.endswith('.json')): continue
                    
                    print(f"Processing ZIP entry: {zip_info.filename}")
                    
                    # Open the file as a stream
                    with zip_ref.open(zip_info) as binary_file:
                        # Wrap in TextIOWrapper to read as text (utf-8)
                        with io.TextIOWrapper(binary_file, encoding='utf-8', errors='ignore') as text_file:
                            res = ingest_log_stream(zip_info.filename, text_file)
                            
                            aggregated_result["total_indexed"] += res.get("total_indexed", 0)
                            aggregated_result["failed"] += res.get("failed", 0)
                            aggregated_result["duplicates_skipped"] += res.get("duplicates_skipped", 0)
                            aggregated_result["ignored"] += res.get("ignored", 0)
                            aggregated_result["files_processed"].append(zip_info.filename)
            
            print(f"ZIP Ingestion Complete. Processed {len(aggregated_result['files_processed'])} files.")
            return aggregated_result
            
        except Exception as e:
            print(f"Error processing ZIP: {e}")
            return {"status": "error", "message": str(e)}
    else:
        # Regular single file
        return ingest_single_file(file_path)

def ingest_failed_docs(file_path: str):
    """
    Ingest failed documents from a JSONL file with duplicate prevention.
    Generates deterministic IDs based on content hash.
    """
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
                    
                    # Sanitize: Ensure proper structure
                    # If it's a raw doc (no underscores), wrap it or treat as source
                    # But failed_docs.jsonl usually writes the raw doc OR the action structure?
                    # Let's inspect failed_docs.jsonl format from earlier code:
                    # It writes `json.dumps(original_doc)` where `original_doc` came from `op_result.get('data')`
                    # In `parallel_bulk` (which we use), `data` is usually the original source doc provided to it.
                    # So we treat it as the source doc.
                    
                    source_doc = doc
                    
                    # Remove internal fields if they exist from previous attempts (just in case)
                    # e.g. if we accidentally saved metadata wrapped docs
                    if "_source" in doc and "_index" in doc:
                         source_doc = doc["_source"]

                    # Deterministic ID for Idempotency
                    # Sort keys to ensure consistent string representation
                    doc_str = json.dumps(source_doc, sort_keys=True)
                    doc_id = hashlib.md5(doc_str.encode('utf-8')).hexdigest()
                    
                    yield {
                        "_op_type": "create", # 'create' ensures we don't overwrite if ID collision (though unlikely) or if already exists
                        "_index": INDEX_NAME,
                        "_id": doc_id,
                        "_source": source_doc
                    }
                except Exception as e:
                    print(f"Skipping bad line {line_num}: {e}")

    # Use parallel bulk for speed
    success_count = 0
    failure_count = 0
    duplicates = 0
    
    # Try to import tqdm
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
                    # print(f"[RETRY FAIL] {info}") # access denied often noisy for 409s if not handled

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
    parser = argparse.ArgumentParser(description="Ingest Pega logs with stack trace parsing")
    parser.add_argument("file", nargs="?", help="Path to log file (for standard ingestion)")
    parser.add_argument("--retry-file", help="Path to failed_docs.jsonl to retry ingestion")
    args = parser.parse_args()
    
    if args.retry_file:
         if os.path.exists(args.retry_file):
             start_time = time.time()
             result = ingest_failed_docs(args.retry_file)
             duration = time.time() - start_time
             print(f"Time taken: {duration:.2f} seconds")
             print(json.dumps(result, indent=2))
         else:
             print(f"Retry file not found: {args.retry_file}")
             
    elif args.file:
        if os.path.exists(args.file):
            start_time = time.time()
            result = ingest_file(args.file)
            duration = time.time() - start_time
            print(f"Time taken: {duration:.2f} seconds")
            print(json.dumps(result, indent=2))
        else:
            print(f"File not found: {args.file}")
    else:
        parser.print_help()
