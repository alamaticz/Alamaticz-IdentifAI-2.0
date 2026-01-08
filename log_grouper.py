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
# THREAD_COUNT removed
CHUNK_SIZE = int(os.getenv("BULK_CHUNK_SIZE", "2500"))

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
            # Force a refresh
            self.client.indices.refresh(index=self.index_name)
        except Exception as e:
            print(f"[WARN] Failed to restore settings: {e}")


def load_custom_patterns(client):
    """Load custom regex patterns from OpenSearch index."""
    try:
        if not client.indices.exists(index="pega-custom-patterns"):
            print("[WARN] Custom patterns index not found. Skipping.")
            return []
            
        response = client.search(
            index="pega-custom-patterns",
            body={"query": {"match_all": {}}, "size": 1000}
        )
        patterns = [hit["_source"] for hit in response["hits"]["hits"]]
        return patterns
    except Exception as e:
        print(f"[WARN] Failed to load custom patterns from OpenSearch: {e}")
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
        retry_on_status=(429, 500, 502, 503, 504)
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
                raise_on_exception=False,
                start_response_length=True # Optimization? Removed threading but this is for helpers.bulk
            )
        except TypeError:
            # Fallback for start_response_length if not supported
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

def process_logs(limit=None, batch_size=5000, ignore_checkpoint=False, session_id=None):
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
    
    if last_checkpoint and not ignore_checkpoint:
        print(f"[INFO] Found checkpoint. Processing logs after: {last_checkpoint}")
        start_filter = last_checkpoint
    elif ignore_checkpoint:
        print("[INFO] Ignoring checkpoint. Processing ALL logs.")
    else:
        print("[INFO] No checkpoint found. Processing ALL logs.")

    # Load Custom Patterns
    custom_patterns = load_custom_patterns(client)
    if custom_patterns:
        print(f"[INFO] Loaded {len(custom_patterns)} custom grouping rules.")

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
    if start_filter and not ignore_checkpoint and not session_id:
        query["query"]["bool"]["filter"] = [
            {"range": {"ingestion_timestamp": {"gte": start_filter}}}
        ]

    # Add Session ID Filter if provided
    if session_id:
        # If filtering by session, we might want to ensure we don't accidentally filter by checkpoint?
        # User explicitly requested this session, so likely we ignore checkpoint for this run or combine?
        # Let's add it to the filter list.
        if "filter" not in query["query"]["bool"]:
            query["query"]["bool"]["filter"] = []
        
        query["query"]["bool"]["filter"].append(
            {"term": {"session_id": session_id}}
        )
        print(f"[INFO] Filtering by Session ID: {session_id}")

    print("[INFO] Starting scan...")
    scanner = helpers.scan(
        client,
        query=query,
        index=SOURCE_INDEX,
        scroll="5m", # Increased scroll context
        size=1000 # Increased batch size for reading
    )

    processed_count = 0
    actions_buffer = []
    
    # Track latest timestamp locally
    latest_seen_timestamp_local = last_checkpoint

    success_count = 0
    failure_count = 0
    
    print(f"[INFO] Processing logs...")

    with OptimizeIndexSettings(client, DEST_INDEX):
        try:
            # Use progress bar if available
            try:
                from tqdm import tqdm
                iterator = tqdm(scanner, unit="logs", desc="Grouping")
            except ImportError:
                iterator = scanner

            for doc in iterator:
                if limit and processed_count >= limit:
                    break
                    
                processed_count += 1
                source = doc['_source']
                doc_id = doc['_id']
                
                # Update local tracker
                doc_ts = source.get('ingestion_timestamp')
                if doc_ts:
                    if not latest_seen_timestamp_local or doc_ts > latest_seen_timestamp_local:
                        latest_seen_timestamp_local = doc_ts

                # --- Extraction & Grouping Logic (Inlined) ---
                sequence_summary_dict = source.get("sequence_summary", {})
                sequence_signature = ""
                if sequence_summary_dict and isinstance(sequence_summary_dict, dict):
                    sorted_keys = sorted(sequence_summary_dict.keys(), key=lambda k: int(k) if k.isdigit() else 999)
                    sequence_parts = [sequence_summary_dict[k] for k in sorted_keys]
                    sequence_signature = " | ".join(sequence_parts)
                
                exc_message = source.get("exception_message") or ""
                norm_exc_message = source.get("normalized_exception_message") or normalize_error_pattern(exc_message)
                raw_message = source.get("log", {}).get("message") or ""
                norm_message = source.get("normalized_message") or normalize_error_pattern(raw_message)
                logger_name = source.get("log", {}).get("logger_name") or ""
                
                group_type = "Unanalyzed"
                group_signature_string = ""
                
                custom_match = check_custom_patterns(raw_message, custom_patterns)
                csp_signature = extract_csp_signature(raw_message)

                if custom_match:
                    raw_type = custom_match.get('group_type', 'Custom')
                    if raw_type == "Custom":
                        group_type = f"Custom: {custom_match['name']}"
                    else:
                        group_type = raw_type
                    group_signature_string = custom_match['name']
                elif csp_signature:
                     group_type = "CSP Violation"
                     group_signature_string = csp_signature
                elif sequence_signature:
                    group_type = "RuleSequence"
                    group_signature_string = sequence_signature
                elif norm_exc_message:
                    group_type = "Exception"
                    group_signature_string = norm_exc_message
                elif norm_message:
                    group_type = "Message"
                    group_signature_string = norm_message
                else:
                    group_type = "Logger"
                    group_signature_string = logger_name if logger_name else "Unknown"

                group_id = generate_group_id(group_signature_string)
                now_ts = datetime.utcnow().isoformat()
                
                rep_log = {
                    "message": raw_message,
                    "exception_message": exc_message,
                    "logger_name": logger_name,
                    "sample_log_id": doc_id 
                }

                script_source = """
                    if (ctx._source.count == null) ctx._source.count = 0;
                    if (ctx._source.raw_log_ids == null) ctx._source.raw_log_ids = [];
                    if (ctx._source.exception_signatures == null) ctx._source.exception_signatures = [];
                    if (ctx._source.message_signatures == null) ctx._source.message_signatures = [];

                    ctx._source.count += params.inc;
                    if (ctx._source.last_seen == null || params.last_seen.compareTo(ctx._source.last_seen) > 0) {
                        ctx._source.last_seen = params.last_seen;
                    }

                    if (ctx._source.raw_log_ids.size() < 50 && !ctx._source.raw_log_ids.contains(params.new_id)) {
                        ctx._source.raw_log_ids.add(params.new_id);
                    }

                    if (params.norm_exc != null && params.norm_exc != "") {
                        if (!ctx._source.exception_signatures.contains(params.norm_exc)) {
                            ctx._source.exception_signatures.add(params.norm_exc);
                        }
                    }

                    if (params.norm_msg != null && params.norm_msg != "") {
                        if (!ctx._source.message_signatures.contains(params.norm_msg)) {
                            ctx._source.message_signatures.add(params.norm_msg);
                        }
                    }

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
                
                actions_buffer.append(action)
                
                if len(actions_buffer) >= batch_size:
                    # Flush Batch
                    try:
                        resp = safe_bulk(client, actions_buffer)
                        # safe_bulk returns (success, errors) from helpers.bulk
                        success, errors = resp
                        success_count += success
                        if errors:
                             failure_count += len(errors)
                    except Exception as e:
                        print(f"[ERROR] Batch failed: {e}")
                        failure_count += len(actions_buffer)
                        
                    actions_buffer = []

            # Flush remaining
            if actions_buffer:
                try:
                    success, errors = safe_bulk(client, actions_buffer)
                    success_count += success
                    if errors:
                         failure_count += len(errors)
                except Exception as e:
                    print(f"[ERROR] Final batch failed: {e}")
                    failure_count += len(actions_buffer)

        except Exception as e:
            print(f"\n[ERROR] Critical failure in scanning loop: {e}")

    print(f"\n[INFO] grouping complete.")
    print(f"  Processed: {processed_count}")
    print(f"  Updates/Upserts: {success_count}")
    print(f"  Failures: {failure_count}")

    # Update Checkpoint using local tracker
    if latest_seen_timestamp_local and latest_seen_timestamp_local != last_checkpoint:
        update_checkpoint(client, latest_seen_timestamp_local)
        print(f"[INFO] Checkpoint updated to: {latest_seen_timestamp_local}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pega Log Grouper (OpenSearch)")
    parser.add_argument("--limit", type=int, help="Limit number of logs to process", default=None)
    parser.add_argument("--ignore-checkpoint", action="store_true", help="Ignore checkpoint and process all logs")
    parser.add_argument("--session-id", type=str, help="Process specific session ID", default=None)
    parser.add_argument("--batch-size", type=int, help="Bulk indexing batch size", default=5000)
    args = parser.parse_args()
    
    # Pass the argument to process_logs.
    process_logs(limit=args.limit, ignore_checkpoint=args.ignore_checkpoint, session_id=args.session_id, batch_size=args.batch_size)