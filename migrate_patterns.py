import os
import json
from dotenv import load_dotenv
from opensearchpy import OpenSearch, helpers

# Load environment variables
load_dotenv(override=True)

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS")
INDEX_NAME = "pega-custom-patterns"
JSON_FILE = "custom_patterns.json"

def get_opensearch_client():
    if not OPENSEARCH_URL:
        print("Error: OPENSEARCH_URL not found in .env")
        return None
        
    auth = (OPENSEARCH_USER, OPENSEARCH_PASS) if OPENSEARCH_USER else None
    
    return OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_auth=auth,
        verify_certs=False,
        ssl_show_warn=False
    )

def migrate():
    client = get_opensearch_client()
    if not client:
        return

    # 1. Create Index if not exists
    if not client.indices.exists(index=INDEX_NAME):
        print(f"Creating index: {INDEX_NAME}")
        client.indices.create(index=INDEX_NAME, body={
             "mappings": {
                "properties": {
                    "name": {"type": "keyword"},
                    "pattern": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "group_type": {"type": "keyword"},
                    "created_at": {"type": "date"}
                }
            }
        })
    else:
        print(f"Index {INDEX_NAME} already exists.")

    # 2. Load JSON
    patterns = []
    if os.path.exists(JSON_FILE):
        try:
            with open(JSON_FILE, "r") as f:
                patterns = json.load(f)
            print(f"Loaded {len(patterns)} patterns from {JSON_FILE}")
        except Exception as e:
            print(f"Error loading JSON: {e}")
            return
    else:
        print(f"No {JSON_FILE} found. Nothing to migrate.")
        return

    if not patterns:
        print("No patterns to index.")
        return

    # 3. Index Documents
    actions = []
    for p in patterns:
        # Use name as ID for idempotency
        doc_id = p.get("name")
        if not doc_id:
            continue
            
        action = {
            "_index": INDEX_NAME,
            "_id": doc_id,
            "_source": p
        }
        actions.append(action)

    success, errors = helpers.bulk(client, actions)
    print(f"Successfully migrated {success} patterns.")
    if errors:
        print(f"Errors: {errors}")

if __name__ == "__main__":
    migrate()
