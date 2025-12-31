import os
import json
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection
import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType, initialize_agent
from dotenv import load_dotenv

# Load envs
load_dotenv()

def get_opensearch_client():
    OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL")
    OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER")
    OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS")
    CLIENT_TIMEOUT = int(os.environ.get("CLIENT_TIMEOUT", 60))

    if not OPENSEARCH_URL or not OPENSEARCH_USER or not OPENSEARCH_PASS:
        raise ValueError("Missing required OpenSearch environment variables: OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS")

    client = OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        verify_certs=False,
        ssl_show_warn=False,
        timeout=CLIENT_TIMEOUT,
        max_retries=5,
        retry_on_timeout=True,
        retry_on_status=(500, 502, 503, 504)
    )
    return client

def fetch_grouped_errors(client, size=5):
    """
    Fetch top grouped errors from pega-analysis-results.
    Prioritizes groups with 'PENDING' diagnosis or just largest counts.
    """
    index = "pega-analysis-results"
    
    # Check if index exists first
    if not client.indices.exists(index=index):
        print(f"Index {index} does not exist. Run log_grouper.py first.")
        return []

    query = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"term": {"diagnosis.status": "PENDING"}}
                ]
            }
        },
        "sort": [
            {"count": {"order": "desc"}}
        ]
    }
    
    response = client.search(body=query, index=index)
    hits = response['hits']['hits']
    
    results = []
    for hit in hits:
        doc = hit['_source']
        doc['_id'] = hit['_id']
        results.append(doc)
        
    return results



def update_diagnosis_in_opensearch(client, doc_id, diagnosis_text):
    """
    Update the grouped document with diagnosis results.
    """
    index = "pega-analysis-results"
    
    body = {
        "doc": {
            "diagnosis": {
                "status": "COMPLETED",
                "report": diagnosis_text,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    }
    
    try:
        client.update(index=index, id=doc_id, body=body)
        print(f"Updated diagnosis for group {doc_id}")
    except Exception as e:
        print(f"Failed to update diagnosis for {doc_id}: {e}")



async def run_diagnosis_workflow():
    print("Starting Log Diagnosis Workflow (LangChain)")
    client = get_opensearch_client()
    
    # 1. Fetch Grouped Errors
    grouped_errors = fetch_grouped_errors(client)
    print(f"Found {len(grouped_errors)} pending error groups to diagnose")
    
    if not grouped_errors:
        print("No pending error groups found. Make sure log_grouper.py has run.")
        return

    # 2. Define MCP Server URL
    mcp_server_config = {
        "opensearch": { 
            "url": "http://localhost:9900/sse",
            "transport": "sse",
            "headers": {
                "Content-Type": "application/json",
                "Accept-Encoding": "identity",
            }
        }
    }
    
    try:
        mcp_client = MultiServerMCPClient(mcp_server_config)
        tools = await mcp_client.get_tools() 
        print(f"Fetched {len(tools)} tools from MCP server")


        MODEL_NAME = "gpt-4o"
        llm = ChatOpenAI(model=MODEL_NAME)

        # 3. Initialize LangChain Agent
        agent = initialize_agent(
            tools=tools,
            llm=llm,
            agent=AgentType.OPENAI_FUNCTIONS,
            verbose=True,
            handle_parsing_errors=True
        )

        # 4. Process each group
        for group_doc in grouped_errors:
            group_id = group_doc['_id']
            
            # Construct Context
            # We explicitly exclude raw logs to save tokens and reduce noise as requested
            analysis_context = {
                "group_signature": group_doc.get('group_signature'),
                "group_type": group_doc.get('group_type'),
                "total_count": group_doc.get('count'),
                "representative_log": group_doc.get('representative_log'),
                "signature_details": group_doc.get('signature_details'),
                "exception_signatures": group_doc.get('exception_signatures', []),
                "message_signatures": group_doc.get('message_signatures', [])
            }
            
            context_str = json.dumps(analysis_context, indent=2)
            
            print(f"Diagnosing Group: {group_doc.get('group_signature')} (Count: {group_doc.get('count')})")

            # Define Prompt
            prompt = f'''
            You are a Senior Pega Lead System Architect (LSA) analyzing an error group from a Pega Application.
            
            Data Provided:
            {context_str}
            
            Perform a deep technical diagnosis and output a report in Markdown format with the following sections:

            ### 1. Executive Summary
            (One concise sentence describing the issue)

            ### 2. Severity Assessment
            (CRITICAL / MAJOR / MINOR) - Justify your choice based on the error type.

            ### 3. Error Flow & Point of Failure
            *   **Execution Path**: Analyze the `group_signature` (especially if it contains '->'). Reconstruct the call stack (e.g., "Activity A calls Activity B").
            *   **Point of Failure**: Identify the EXACT Rule or Step where the error occurred based on the signature and exception.

            ### 4. Root Cause Analysis
            Explain *why* this error happened. Connect the Exception message (e.g., NullPointer) to the specific Rule context.

            ### 5. Impact Analysis
            What functional part of the system is likely broken? (e.g., "User cannot open Portal", "Background processing failed").

            ### 6. Step-by-Step Resolution
            Provide concrete, Pega-specific steps for a developer to fix this.
            *   **Debugging**: Mention specific tools (e.g., "Run Tracer on Activity X", "Check Clipboard Page Y").
            *   **Fix**: Suggest code changes (e.g., "Add a null check in Step 2", "Update Data Transform").
            '''

            # Invoke Agent
            try:
                response = await agent.ainvoke({"input": prompt})
                diagnosis_text = response["output"]
                
                # Write back to OpenSearch
                update_diagnosis_in_opensearch(client, group_id, diagnosis_text)
                
            except Exception as exc:
                print(f"Failed to diagnose group {group_id}: {exc}")
            
    except Exception as e:
        print(f"Error in diagnosis workflow: {e}")

if __name__ == "__main__":
    asyncio.run(run_diagnosis_workflow())
