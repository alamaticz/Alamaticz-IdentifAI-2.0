#!/usr/bin/env python3
"""
Log Grouper Module
Connects to OpenSearch, streams raw logs, groups them using Waterfall Logic,
and stores aggregated results back to OpenSearch ('pega-analysis-results').
"""

import os
import json
import hashlib
import time
import argparse
import re
from datetime import datetime
from dotenv import load_dotenv
from opensearchpy import OpenSearch, helpers

# Import local modules

from log_normalizer import normalize_error_pattern

# Load environment variables
load_dotenv(override=True)

# Configuration
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS")
SOURCE_INDEX = "pega-logs"
DEST_INDEX = "pega-analysis-results"
CUSTOM_PATTERNS_FILE = "custom_patterns.json"

def load_custom_patterns():
    """Load custom regex patterns from JSON file."""
    if not os.path.exists(CUSTOM_PATTERNS_FILE):
        return []
    try:
        with open(CUSTOM_PATTERNS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load custom patterns: {e}")
        return []

def check_custom_patterns(message, patterns):
    """Check if message matches any custom pattern."""
    for p in patterns:
        try:
            if re.search(p['pattern'], message, re.IGNORECASE):
                return p
        except:
            continue
    return None

def get_opensearch_client():
    """Create and return OpenSearch client with robust retry logic."""
    if not OPENSEARCH_URL:
        raise ValueError("OPENSEARCH_URL not set in .env")
        
    auth = (OPENSEARCH_USER, OPENSEARCH_PASS) if OPENSEARCH_USER else None
    
    return OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_auth=auth,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=120,
        max_retries=5,
        retry_on_timeout=True,
        retry_on_status=(500, 502, 503, 504)
    )

def generate_group_id(signature_string):
    """Generate deterministic MD5 hash for a group signature."""
    return hashlib.md5(signature_string.encode('utf-8')).hexdigest()

def extract_csp_signature(message):
    """
    Extracts CSP violation details from the raw log message.
    Returns a signature string in the format:
    CSP Violation | Blocked: <src> | Violated: <violated> | Effective: <effective>
    Returns None if not a CSP violation.
    """
    if "A browser has reported a violation of your application's Content Security Policy" not in message:
        return None
    
    # Regex patterns
    blocked_pattern = r"Blocked Content Source:\s*(.+)"
    violated_pattern = r"Violated Directive:\s*(.+)"
    effective_pattern = r"Effective Directive:\s*(.+)"
    
    blocked_match = re.search(blocked_pattern, message)
    violated_match = re.search(violated_pattern, message)
    effective_match = re.search(effective_pattern, message)
    
    blocked = blocked_match.group(1).strip() if blocked_match else "Unknown"
    
    # Truncate URL to origin (scheme + domain) to group effectively
    # e.g. https://fonts.gstatic.com/s/foo -> https://fonts.gstatic.com
    if "://" in blocked:
        parts = blocked.split('/')
        if len(parts) >= 3:
            blocked = "/".join(parts[:3])

    violated = violated_match.group(1).strip() if violated_match else "Unknown"
    effective = effective_match.group(1).strip() if effective_match else "Unknown"
    
    return f"CSP Violation | Blocked: {blocked} | Violated: {violated} | Effective: {effective}"

def wait_for_connection(client, max_retries=10, delay=5):
    """Wait for OpenSearch to be available."""
    print(f"[INFO] Connecting to OpenSearch at {OPENSEARCH_URL}...")
    for i in range(max_retries):
        try:
            # client.info()
            client.transport.perform_request("GET", "/", timeout=60)
            print("[INFO] Connection established successfully.")
            return True
        except Exception as e:
            print(f"[WARN] Connection attempt {i+1}/{max_retries} failed: {e}")
            if i < max_retries - 1:
                print(f"[INFO] Retrying in {delay} seconds...")
                time.sleep(delay)
    return False

def get_last_checkpoint(client):
    """
    Retrieve the last processed timestamp from the checkpoint document.
    """
    try:
        response = client.get(index=DEST_INDEX, id="grouper_checkpoint")
        return response['_source'].get('last_processed_timestamp')
    except Exception:
        # If index doesn't exist or doc doesn't exist
        return None

def update_checkpoint(client, timestamp):
    """
    Update the checkpoint document with the latest timestamp.
    """
    doc = {
        "last_processed_timestamp": timestamp,
        "updated_at": datetime.utcnow().isoformat()
    }
    try:
        client.index(index=DEST_INDEX, id="grouper_checkpoint", body=doc)
        # print(f"[INFO] Checkpoint updated to {timestamp}")
    except Exception as e:
        print(f"[WARN] Failed to update checkpoint: {e}")

def safe_bulk(client, actions, retries=3, backoff=1.0):
    """
    Wrapper around helpers.bulk with retry logic for transient errors.
    """
    for attempt in range(retries):
        try:
            return helpers.bulk(
                client,
                actions,
                raise_on_error=False,
                raise_on_exception=False
            )
        except Exception as e:
            if attempt == retries - 1:
                raise
            time.sleep(backoff * (attempt + 1))

def process_logs(limit=None, batch_size=100):
    """
    Main processing loop.
    Scanning -> Grouping -> Bulk Indexing
    """
    client = get_opensearch_client()
    
    if not wait_for_connection(client):
        print("[ERROR] Could not connect to OpenSearch after multiple retries. Exiting.")
        return

    # Ensure destination index exists
    if not client.indices.exists(index=DEST_INDEX):
        print(f"[INFO] Creating destination index: {DEST_INDEX}")
        client.indices.create(index=DEST_INDEX, body={
            "mappings": {
                "properties": {
                    "group_signature": {"type": "text"},
                    "group_type": {"type": "keyword"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "count": {"type": "long"},
                    "raw_log_ids": {"type": "keyword"},
                    "exception_signatures": {"type": "keyword"},
                    "message_signatures": {"type": "keyword"},
                    "diagnosis.status": {"type": "keyword"}
                }
            }
        })



    # 1. Get Checkpoint
    last_checkpoint = get_last_checkpoint(client)
    start_filter = None
    
    if last_checkpoint:
        print(f"[INFO] Found checkpoint. Processing logs after: {last_checkpoint}")
        start_filter = last_checkpoint
    else:
        print("[INFO] No checkpoint found. Processing ALL logs.")

    # Load Custom Patterns
    custom_patterns = load_custom_patterns()
    if custom_patterns:
        print(f"[INFO] Loaded {len(custom_patterns)} custom grouping rules.")

    # Query: Fetch only ERROR logs

    # Query: Fetch only ERROR logs
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"log.level": "ERROR"}}
                ]
            }
        }
    }
    
    # Add Range Filter if checkpoint exists
    if start_filter:
        query["query"]["bool"]["filter"] = [
            {"range": {"ingestion_timestamp": {"gte": start_filter}}}
        ]

    print("[INFO] Starting scan...")
    scanner = helpers.scan(
        client,
        query=query,
        index=SOURCE_INDEX,
        scroll="2m",
        size=50
    )

    processed_count = 0
    bulk_actions = []
    
    # Track the latest timestamp seen in this batch
    latest_seen_timestamp = last_checkpoint
    
    for doc in scanner:
        if limit and processed_count >= limit:
            break
            
        source = doc['_source']
        doc_id = doc['_id']
        processed_count += 1
        
        # Track timestamp
        doc_ts = source.get('ingestion_timestamp')
        if doc_ts:
            if not latest_seen_timestamp or doc_ts > latest_seen_timestamp:
                latest_seen_timestamp = doc_ts
        
        # --- Extraction ---
        # 1. Sequence Summary (extract dict values and sort them to ensure deterministic signature)
        sequence_summary_dict = source.get("sequence_summary", {})
        sequence_signature = ""
        if sequence_summary_dict and isinstance(sequence_summary_dict, dict):
            # Sort by key (index) to maintain order: "1", "2", "3"...
            # Keys are strings in JSON, so sort by integer value
            sorted_keys = sorted(sequence_summary_dict.keys(), key=lambda k: int(k) if k.isdigit() else 999)
            sequence_parts = [sequence_summary_dict[k] for k in sorted_keys]
            sequence_signature = " | ".join(sequence_parts)
        
        # 2. Exception Info
        exc_message = source.get("exception_message") or ""
        norm_exc_message = source.get("normalized_exception_message") or normalize_error_pattern(exc_message)
        
        # 3. Log Message
        raw_message = source.get("log", {}).get("message") or ""
        norm_message = source.get("normalized_message") or normalize_error_pattern(raw_message)
        
        # 4. Logger / Class
        # 'logger_name' is often in 'log' -> 'logger_name' or top level depending on schema
        logger_name = source.get("log", {}).get("logger_name") or ""
        

        # --- Waterfall Grouping ---
        group_type = "Unanalyzed"
        group_signature_string = ""
        
        # Check for Custom Patterns First (Priority)
        custom_match = check_custom_patterns(raw_message, custom_patterns)
        
        # Check for CSP Violation first (Specific Raw Message Check)
        csp_signature = extract_csp_signature(raw_message)

        # Scenario 0: Custom Rule
        if custom_match:
            # Use user-defined Group Category (e.g. "CSP", "Infrastructure") or default to "Custom"
            raw_type = custom_match.get('group_type', 'Custom')
            # If user explicitly set "Custom", keep formatting "Custom: Name". 
            # If they set "CSP" or "Infrastructure", use that directly as the category.
            if raw_type == "Custom":
                group_type = f"Custom: {custom_match['name']}"
            else:
                group_type = raw_type
                
            group_signature_string = custom_match['name']
        
        # Scenario 1: CSP Violation
        elif csp_signature:
             group_type = "CSP Violation"
             group_signature_string = csp_signature

        # Scenario 2: Rule Sequence
        elif sequence_signature:
            group_type = "RuleSequence"
            group_signature_string = sequence_signature
        
        # Scenario 2: Exception Message
        elif norm_exc_message:
            group_type = "Exception"
            group_signature_string = norm_exc_message
            
        # Scenario 3: Log Message
        elif norm_message:
            group_type = "Message"
            group_signature_string = norm_message
            
        # Scenario 4: Logger / Class
        else:
            group_type = "Logger"
            group_signature_string = logger_name if logger_name else "Unknown"

        # Generate Deterministic ID
        group_id = generate_group_id(group_signature_string)
        now_ts = datetime.utcnow().isoformat()
        
        # Representative Log Structure
        rep_log = {
            "message": raw_message,
            "exception_message": exc_message,
            "logger_name": logger_name,
            # We preserve the IDs/Timestamp of the latest rep log
            "sample_log_id": doc_id 
        }

        # --- Aggregation Lists ---
        # We want to add ONLY unique signatures to the lists.
        # OpenSearch Set implementation in painless is easiest via checking contains.
        
        script_source = """
            // Initialize fields defensively (important for concurrency)
            if (ctx._source.count == null) ctx._source.count = 0;
            if (ctx._source.raw_log_ids == null) ctx._source.raw_log_ids = [];
            if (ctx._source.exception_signatures == null) ctx._source.exception_signatures = [];
            if (ctx._source.message_signatures == null) ctx._source.message_signatures = [];

            // Increment counters
            ctx._source.count += params.inc;
            // Update last_seen only if the new log is more recent (or if field is missing)
            if (ctx._source.last_seen == null || params.last_seen.compareTo(ctx._source.last_seen) > 0) {
                ctx._source.last_seen = params.last_seen;
            }

            // Add raw log ID (cap at 50)
            if (ctx._source.raw_log_ids.size() < 50 && !ctx._source.raw_log_ids.contains(params.new_id)) {
                ctx._source.raw_log_ids.add(params.new_id);
            }

            // Add unique normalized exception signature
            if (params.norm_exc != null && params.norm_exc != "") {
                if (!ctx._source.exception_signatures.contains(params.norm_exc)) {
                    ctx._source.exception_signatures.add(params.norm_exc);
                }
            }

            // Add unique normalized message signature
            if (params.norm_msg != null && params.norm_msg != "") {
                if (!ctx._source.message_signatures.contains(params.norm_msg)) {
                    ctx._source.message_signatures.add(params.norm_msg);
                }
            }

            // Always keep latest representative log
            ctx._source.representative_log = params.rep_log;

        """

        upsert_doc = {
            "group_signature": group_signature_string,
            "group_type": group_type,
            "first_seen": doc_ts if doc_ts else now_ts,
            "last_seen": doc_ts if doc_ts else now_ts,
            "count": 1,
            "raw_log_ids": [doc_id],
            "exception_signatures": [norm_exc_message] if norm_exc_message else [],
            "message_signatures": [norm_message] if norm_message else [],
            "representative_log": rep_log,
            "diagnosis": {
                "status": "PENDING"
            }
        }
        
        # Clean empty lists in upsert if preferred, but empty list is fine.
        
        action = {
            "_op_type": "update",
            "_index": DEST_INDEX,
            "_id": group_id,
            "retry_on_conflict": 5,
            "script": {
                "source": script_source,
                "lang": "painless",
                "params": {
                    "inc": 1,
                    "last_seen": doc_ts if doc_ts else now_ts,
                    "new_id": doc_id,
                    "rep_log": rep_log,
                    "norm_exc": norm_exc_message,
                    "norm_msg": norm_message
                }
            },
            "upsert": upsert_doc
        }
        
        bulk_actions.append(action)
        
        # Flush Bulk
        if len(bulk_actions) >= batch_size:
            success, errors = safe_bulk(client, bulk_actions)

            time.sleep(0.5)  # 500ms backoff

            if errors:
                conflict_count = 0
                other_errors = []

                for e in errors:
                    e_str = str(e)
                    if "version_conflict_engine_exception" in e_str:
                        conflict_count += 1
                    else:
                        other_errors.append(e_str)

                if conflict_count:
                    print(f"[WARN] {conflict_count} version conflicts (safe to ignore)")
                if other_errors:
                    print(f"[ERROR] {len(other_errors)} non-conflict bulk errors detected")
                    print("[ERROR] Sample error:")
                    print(other_errors[0])
            
            bulk_actions = []
            print(f"  Indexed {processed_count} logs...", end='\r')


    # Final Flush
    if bulk_actions:
        success, errors = safe_bulk(client, bulk_actions)

        time.sleep(0.5)  # 500ms backoff

        if errors:
            conflict_count = 0
            other_errors = []

            for e in errors:
                e_str = str(e)
                if "version_conflict_engine_exception" in e_str:
                    conflict_count += 1
                else:
                    other_errors.append(e_str)

            if conflict_count:
                print(f"[WARN] {conflict_count} version conflicts (safe to ignore)")
            if other_errors:
                print(f"[ERROR] {len(other_errors)} non-conflict bulk errors detected")
                print("[ERROR] Sample error:")
                print(other_errors[0])

    
    # Update Checkpoint if we processed anything
    if latest_seen_timestamp and latest_seen_timestamp != last_checkpoint:
        update_checkpoint(client, latest_seen_timestamp)
        print(f"[INFO] Checkpoint updated to: {latest_seen_timestamp}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pega Log Grouper (OpenSearch)")
    parser.add_argument("--limit", type=int, help="Limit number of logs to process", default=None)
    args = parser.parse_args()
    
    process_logs(limit=args.limit)