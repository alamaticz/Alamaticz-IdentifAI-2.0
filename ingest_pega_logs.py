import os
import json
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
# Tunable settings
CHUNK_SIZE = int(os.getenv("BULK_CHUNK_SIZE", "2500")) # Increased for throughput
CLIENT_TIMEOUT = int(os.getenv("OPENSEARCH_TIMEOUT", "120"))
THREAD_COUNT = int(os.getenv("INGESTION_THREADS", "8"))
CLIENT_TIMEOUT = int(os.getenv("OPENSEARCH_TIMEOUT", "120"))

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
        max_retries=5,
        retry_on_timeout=True,
        retry_on_status=(429, 500, 502, 503, 504),
    )

# --- Optimization Helpers ---

class OptimizeIndexSettings:
    """Context manager to optimize index settings for bulk ingestion."""
    def __init__(self, client, index_name):
        self.client = client
        self.index_name = index_name
        self.original_settings = {}

    def __enter__(self):
        print(f"[INFO] Optimizing index settings for {self.index_name}...")
        try:
            # save current settings (refresh_interval, number_of_replicas)
            # We fetch all settings, but we only really care about these two being restored if they were explicitly set.
            # For simplicity, we assume we want to restore to '1s' and '1' (or '0' if single node) defaults if not found.
            settings = self.client.indices.get_settings(index=self.index_name)
            idx_settings = settings.get(self.index_name, {}).get('settings', {}).get('index', {})
            
            self.original_settings['refresh_interval'] = idx_settings.get('refresh_interval', '1s')
            self.original_settings['number_of_replicas'] = idx_settings.get('number_of_replicas', '1')
            
            # Apply optimizations
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
            # Restore
            self.client.indices.put_settings(index=self.index_name, body={
                "index": {
                    "refresh_interval": self.original_settings.get('refresh_interval', '1s'),
                    "number_of_replicas": self.original_settings.get('number_of_replicas', 1)
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

def ingest_single_file(file_path: str):
    """Ingest a single file into OpenSearch (internal helper)."""
    client = get_opensearch_client()
    ensure_index(client)
    
    file_name = os.path.basename(file_path)
    session_id = str(uuid.uuid4())
    ingestion_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    total_indexed = 0
    ignored_local = 0
    
    def actions():
        nonlocal ignored_local
        line_number = 0
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for raw_line in f:
                line_number += 1
                line = raw_line.strip()
                if not line:
                    continue

                try:
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
    duplicates = 0  # Track duplicates
    
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
            
        # Use parallel_bulk for high throughput
        with OptimizeIndexSettings(client, INDEX_NAME):
            for success, info in helpers.parallel_bulk(
                client,
                iterator,
                thread_count=THREAD_COUNT,
                queue_size=THREAD_COUNT * 2,
                chunk_size=CHUNK_SIZE,
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
                    
                    if status_code == 409:
                        duplicates += 1
                    else:
                        # Log sample errors even with tqdm
                        if failure < 5:
                             print(f"\n[ERROR] Failed doc (Status {status_code}): {info}")
                        failure += 1
                
                # Periodic print if no tqdm
                if not use_tqdm and (success_count + duplicates + failure) % 5000 == 0:
                    print(f"Processed {success_count + duplicates + failure} lines...", end='\r')

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
        
        # Create temp dir
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Walk through extracted files
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        # Skip hidden files or non-logs if desired, but we'll try everything that looks like text
                        # Or strictly: if file.endswith(".log") or file.endswith(".json") or file.endswith(".txt"):
                        
                        print(f"Processing extracted file: {file}")
                        res = ingest_single_file(full_path)
                        
                        aggregated_result["total_indexed"] += res.get("total_indexed", 0)
                        aggregated_result["failed"] += res.get("failed", 0)
                        aggregated_result["duplicates_skipped"] += res.get("duplicates_skipped", 0)
                        aggregated_result["ignored"] += res.get("ignored", 0)
                        aggregated_result["files_processed"].append(file)
                
                print(f"ZIP Ingestion Complete. Processed {len(aggregated_result['files_processed'])} files.")
                return aggregated_result
                
            except Exception as e:
                print(f"Error processing ZIP: {e}")
                return {"status": "error", "message": str(e)}
    else:
        # Regular single file
        return ingest_single_file(file_path)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingest Pega logs with stack trace parsing")
    parser.add_argument("file", help="Path to log file")
    args = parser.parse_args()
    
    if os.path.exists(args.file):
        start_time = time.time()
        result = ingest_file(args.file)
        duration = time.time() - start_time
        print(f"Time taken: {duration:.2f} seconds")
        print(json.dumps(result, indent=2))
    else:
        print(f"File not found: {args.file}")
