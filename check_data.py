import os
import json
from dotenv import load_dotenv
from opensearchpy import OpenSearch

# Load envs
load_dotenv()

def get_client():
    return OpenSearch(
        hosts=[os.getenv("OPENSEARCH_URL")],
        http_auth=(os.getenv("OPENSEARCH_USER"), os.getenv("OPENSEARCH_PASS")),
        verify_certs=False,
        ssl_show_warn=False
    )

def check_data():
    client = get_client()
    
    print("--- 1. Checking Raw Logs (pega-logs) ---")
    # Query for the specific timestamp or just latest
    query_logs = {
        "size": 5,
        "sort": [{"log.timestamp": "desc"}],
        "query": {
            "match_all": {}
        }
    }
    
    try:
        res = client.search(index="pega-logs", body=query_logs)
        hits = res['hits']['hits']
        print(f"Total Hits in 'pega-logs': {res['hits']['total']['value']}")
        if hits:
            print("Latest Log Found:")
            print(json.dumps(hits[0]['_source'], indent=2))
        else:
            print("No logs found in 'pega-logs'.")
    except Exception as e:
        print(f"Error checking pega-logs: {e}")

    print("\n--- 2. Checking Grouped Results (pega-analysis-results) ---")
    query_groups = {
        "size": 5,
        "sort": [{"last_seen": "desc"}],
        "query": {
            "match_all": {}
        }
    }
    
    try:
        res = client.search(index="pega-analysis-results", body=query_groups)
        hits = res['hits']['hits']
        print(f"Total Hits in 'pega-analysis-results': {res['hits']['total']['value']}")
        if hits:
            print("Latest Group Found:")
            print(json.dumps(hits[0]['_source'], indent=2))
        else:
            print("No groups found in 'pega-analysis-results'.")
    except Exception as e:
        print(f"Error checking pega-analysis-results: {e}")

if __name__ == "__main__":
    check_data()
