import os
import json
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection
import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType, initialize_agent
from langchain_community.callbacks import get_openai_callback
import re
from dotenv import load_dotenv

# Load envs
# Load envs
load_dotenv()

def clean_markdown(text):
    """
    Strips markdown formatting to return clean plain text.
    Removes: **bold**, ## Headers, `code`, and ```blocks```.
    """
    # Remove code block markers
    text = re.sub(r'```[a-zA-Z]*\n?', '', text)
    text = re.sub(r'```', '', text)
    
    # Remove inline code backticks
    text = re.sub(r'`', '', text)
    
    # Remove bold/italic markers (* or _)
    text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)  # **bold**
    text = re.sub(r'\*([^*]+)\*', r'\1', text)      # *italic*
    text = re.sub(r'__([^_]+)__', r'\1', text)      # __bold__
    text = re.sub(r'_([^_]+)_', r'\1', text)        # _italic_
    
    # Remove headers (### Header)
    text = re.sub(r'^#+\s*', '', text, flags=re.MULTILINE)
    
    return text.strip()

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



def update_diagnosis_in_opensearch(client, doc_id, diagnosis_text, token_usage=None):
    """
    Update the grouped document with diagnosis results.
    """
    index = "pega-analysis-results"
    
    body = {
        "doc": {
            "diagnosis": {
                "status": "COMPLETED",
                "report": diagnosis_text,
                "report": diagnosis_text,
                "timestamp": datetime.utcnow().isoformat(),
                "token_usage": token_usage or {}
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
            "url": os.getenv("MCP_SERVER_URL", "http://localhost:9900"),
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
            
            Perform a deep technical diagnosis and output a report in CLEAN PLAIN TEXT format. 
            DO NOT USE MARKDOWN (No #, *, or backticks). Use simple upper case for headers.

            Sections:

            1. EXECUTIVE SUMMARY
            (One concise sentence describing the issue)

            2. SEVERITY ASSESSMENT
            (CRITICAL / MAJOR / MINOR) - Justify your choice based on the error type.

            3. ERROR FLOW & POINT OF FAILURE
            Execution Path: Analyze the `group_signature`. Reconstruct the call stack (e.g., "Activity A calls Activity B").
            Point of Failure: Identify the EXACT Rule or Step where the error occurred.

            4. ROOT CAUSE ANALYSIS
            Explain *why* this error happened. Connect the Exception message to the specific Rule context.

            5. IMPACT ANALYSIS
            What functional part of the system is likely broken?

            6. STEP-BY-STEP RESOLUTION
            Provide concrete, Pega-specific steps for a developer to fix this.
            Debugging: Mention specific tools (e.g., "Run Tracer on Activity X").
            Fix: Suggest code changes (e.g., "Add a null check in Step 2").
            '''

            # Invoke Agent
            try:
                with get_openai_callback() as cb:
                    response = await agent.ainvoke({"input": prompt})
                    raw_text = response["output"]
                    diagnosis_text = clean_markdown(raw_text)
                    
                    token_usage = {
                        "total_tokens": cb.total_tokens,
                        "prompt_tokens": cb.prompt_tokens,
                        "completion_tokens": cb.completion_tokens,
                        "total_cost": cb.total_cost
                    }
                    print(f"  Diagnosis Cost: ${cb.total_cost:.4f} (Tokens: {cb.total_tokens})")

                # Write back to OpenSearch
                update_diagnosis_in_opensearch(client, group_id, diagnosis_text, token_usage)
                
            except Exception as exc:
                print(f"Failed to diagnose group {group_id}: {exc}")
            
    except Exception as e:
        print(f"Error in diagnosis workflow: {e}")
        import traceback
        traceback.print_exc()
        # Handle TaskGroup exceptions explicitly if present
        if hasattr(e, 'exceptions'):
            for sub_exc in e.exceptions:
                print(f"Sub-exception: {sub_exc}")

if __name__ == "__main__":
    asyncio.run(run_diagnosis_workflow())
