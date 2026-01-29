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
                "status": "DIAGNOSIS COMPLETED",
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



def construct_analysis_context(group_doc):
    """
    Helper to construct the analysis context dictionary from a group document.
    """
    return {
        "group_signature": group_doc.get('group_signature'),
        "group_type": group_doc.get('group_type'),
        "total_count": group_doc.get('count'),
        "representative_log": group_doc.get('representative_log'),
        "signature_details": group_doc.get('signature_details'),
        "exception_signatures": group_doc.get('exception_signatures', []),
        "message_signatures": group_doc.get('message_signatures', [])
    }

async def execute_diagnosis(agent, prompt):
    """
    Executes the diagnosis using the provided agent and prompt.
    Returns: (diagnosis_text, token_usage)
    """
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
            return diagnosis_text, token_usage
    except Exception as exc:
        print(f"Failed to execute diagnosis: {exc}")
        return None, None

async def diagnose_single_group(client, group_id, prompt_template=None):
    """
    Standalone function to diagnose a single group by ID.
    Used by the Dashboard for on-demand analysis.
    """
    try:
        # 1. Fetch Group Data
        group_doc = client.get(index="pega-analysis-results", id=group_id)
        if not group_doc or '_source' not in group_doc:
             return "Group not found or deleted.", {}
        
        source = group_doc['_source']
        analysis_context = construct_analysis_context(source)
        context_str = json.dumps(analysis_context, indent=2)

        # 2. Setup Agent (Re-using logic from main flow, could be optimized to pass agent in)
        mcp_server_config = {
            "opensearch": { 
                "url": os.getenv("MCP_SERVER_URL", "http://localhost:9900"),
                "transport": "sse",
                "headers": {"Content-Type": "application/json", "Accept-Encoding": "identity"}
            }
        }
        
        mcp_client = MultiServerMCPClient(mcp_server_config)
        tools = await mcp_client.get_tools()
        llm = ChatOpenAI(model="gpt-4o")
        agent = initialize_agent(
            tools=tools,
            llm=llm,
            agent=AgentType.OPENAI_FUNCTIONS,
            verbose=True,
            handle_parsing_errors=True
        )

        # 3. Construct Prompt
        if not prompt_template:
            # Default Prompt
            prompt = f'''You are a Senior Pega Lead System Architect (LSA). I will provide one or more error-group datasets (logs, aggregated error groups from Pega SmartBPM/PRPC, alert events, stack traces, rule/activity/flow names, node/environment, timestamps, counts, correlation IDs, related metrics).

            Data Provided:
            {context_str}

            Analyze the input and produce a technical incident report in CLEAN PLAIN TEXT only (no markdown, no HTML, no extra formatting). The report must contain exactly and only the following sections, in this order, as top-level headings (uppercase): EXECUTIVE SUMMARY, SEVERITY, ERROR FLOW, ROOT CAUSE, IMPACT, RESOLUTION.
            
            Think step by step. For each section, include the items requested below. Keep wording concise, factual, and actionable. Do not add extra sections or explanatory preamble. If data is missing, call it out under the appropriate section as an information gap and state what is needed to conclude.
            
            Required content for each section:
            
            1. EXECUTIVE SUMMARY
            
            - One-paragraph (2–4 sentences) high-level summary of what the error group is, scope (number of affected cases/transactions/sessions), time window, and immediate operational status (ongoing, mitigated, resolved, intermittent).
            - One-line recommended next immediate action (example: "apply mitigation X", "rollback changes", "scale nodes", "open CR").
            
            2. SEVERITY
            
            - A short classification: Critical / High / Medium / Low and a justification (one sentence) referencing impact drivers (customer-facing downtime, SLA breach, data loss, number of users/cases).
            - Quantitative indicators: total occurrences, percentage of total errors (if known), peak error rate (errors/min or errors/hour), number of unique flows/rulesets/nodes impacted, and time range of observations.
            - Confidence level for severity assignment (High/Medium/Low) and why.
            
            3. ERROR FLOW
            
            - A concise narrative of the observed error path: originating entry point (REST/API/Queue/Agent/UI), Pega flow/case type and flow shape where error appears, activities/services/rules involved, downstream systems called (HTTP, DB, JMS) and where failure manifests.
            - Timeline or sequence of notable events (timestamped or relative): first occurrence, peak, latest occurrence, any correlated deploys/config changes/maintenance windows.
            - Top 3 most frequent error messages or exception types and representative sample (error code/message, count).
            - Correlation identifiers or example log lines (one or two) that tie transactions to the error group (include correlation ID, case ID, node if available).
            
            4. ROOT CAUSE
            
            - Clear statement of the most likely root cause with evidence: configuration change, code/regression, data issue, external dependency, resource exhaustion, concurrency/deadlock, misrouted flow, rule resolution error, etc.
            - Contributing factors and why they increase likelihood (race condition, missing guardrails, high load, old ruleset version).
            - Reproducibility: steps to reproduce (if known and deterministic) or conditions required to reproduce.
            - If uncertain, list alternate hypotheses with brief rationale and what data would confirm each.
            
            5. IMPACT
            
            - Precise operational impact: number of customers/cases affected, SLA violations and count, business functions impacted, data integrity risk (yes/no), security risk (yes/no).
            - Short-term operational risk if left unaddressed (worsening error rate, data corruption, system instability).
            - Estimated exposure/time-to-failure if trend continues (example: error rate doubling in X hours; queue backlog will reach Y in Z hours).
            
            6. RESOLUTION
            
            - Immediate mitigations (short-term fixes) to stop or reduce impact, with step-by-step actions and safe rollback notes. Include command/config change examples or Pega admin actions where applicable (e.g., patch activity, change rule resolution to previous ruleset, disable agent, increase thread pool, scale-out service).
            - Recommended permanent fix(es) with implementation approach, required code/config changes, owner role (e.g., LSA, SRE, Integration team), estimated effort (S, M, L — hours/days), and priority.
            - Verification steps and monitoring: how to validate resolution (tests, queries, sample transactions), success criteria, and metrics to monitor post-fix (error rate, queue depth, CPU).
            - Post-mortem artefacts to produce (root cause ticket, RCA doc, regression test cases) and suggested timeline for completion.
            
            Formatting and tone rules
            
            - Use plain text only. Headings must be the exact uppercase words specified followed by a blank line and then the content.
            - Use short paragraphs and bullet-style lists where useful, but keep the content compact and actionable.
            - Include explicit evidence references (counts, timestamps, log snippets) from the provided data when drawing conclusions.
            - If data is insufficient for any conclusion, explicitly state what is missing and why it matters.
            '''
        else:
            # Inject context into user provided template if placeholder exists, else append
            if "{context_str}" in prompt_template:
                prompt = prompt_template.format(context_str=context_str)
            else:
                prompt = f"{prompt_template}\n\nData Provided:\n{context_str}"

        # 4. Execute
        diagnosis_text, token_usage = await execute_diagnosis(agent, prompt)
        
        # 5. Update OpenSearch
        if diagnosis_text:
             update_diagnosis_in_opensearch(client, group_id, diagnosis_text, token_usage)
             
        return diagnosis_text, token_usage

    except Exception as e:
        print(f"Error in diagnose_single_group: {e}")
        return f"Error: {str(e)}", {}



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
            analysis_context = construct_analysis_context(group_doc)
            
            context_str = json.dumps(analysis_context, indent=2)
            
            print(f"Diagnosing Group: {group_doc.get('group_signature')} (Count: {group_doc.get('count')})")

            # Define Prompt
            prompt = f'''You are a Senior Pega Lead System Architect (LSA). I will provide one or more error-group datasets (logs, aggregated error groups from Pega SmartBPM/PRPC, alert events, stack traces, rule/activity/flow names, node/environment, timestamps, counts, correlation IDs, related metrics).

            Data Provided:
            {context_str}

            Analyze the input and produce a technical incident report in CLEAN PLAIN TEXT only (no markdown, no HTML, no extra formatting). The report must contain exactly and only the following sections, in this order, as top-level headings (uppercase): EXECUTIVE SUMMARY, SEVERITY, ERROR FLOW, ROOT CAUSE, IMPACT, RESOLUTION.
            
            Think step by step. For each section, include the items requested below. Keep wording concise, factual, and actionable. Do not add extra sections or explanatory preamble. If data is missing, call it out under the appropriate section as an information gap and state what is needed to conclude.
            
            Required content for each section:
            
            1. EXECUTIVE SUMMARY
            
            - One-paragraph (2–4 sentences) high-level summary of what the error group is, scope (number of affected cases/transactions/sessions), time window, and immediate operational status (ongoing, mitigated, resolved, intermittent).
            - One-line recommended next immediate action (example: "apply mitigation X", "rollback changes", "scale nodes", "open CR").
            
            2. SEVERITY
            
            - A short classification: Critical / High / Medium / Low and a justification (one sentence) referencing impact drivers (customer-facing downtime, SLA breach, data loss, number of users/cases).
            - Quantitative indicators: total occurrences, percentage of total errors (if known), peak error rate (errors/min or errors/hour), number of unique flows/rulesets/nodes impacted, and time range of observations.
            - Confidence level for severity assignment (High/Medium/Low) and why.
            
            3. ERROR FLOW
            
            - A concise narrative of the observed error path: originating entry point (REST/API/Queue/Agent/UI), Pega flow/case type and flow shape where error appears, activities/services/rules involved, downstream systems called (HTTP, DB, JMS) and where failure manifests.
            - Timeline or sequence of notable events (timestamped or relative): first occurrence, peak, latest occurrence, any correlated deploys/config changes/maintenance windows.
            - Top 3 most frequent error messages or exception types and representative sample (error code/message, count).
            - Correlation identifiers or example log lines (one or two) that tie transactions to the error group (include correlation ID, case ID, node if available).
            
            4. ROOT CAUSE
            
            - Clear statement of the most likely root cause with evidence: configuration change, code/regression, data issue, external dependency, resource exhaustion, concurrency/deadlock, misrouted flow, rule resolution error, etc.
            - Contributing factors and why they increase likelihood (race condition, missing guardrails, high load, old ruleset version).
            - Reproducibility: steps to reproduce (if known and deterministic) or conditions required to reproduce.
            - If uncertain, list alternate hypotheses with brief rationale and what data would confirm each.
            
            5. IMPACT
            
            - Precise operational impact: number of customers/cases affected, SLA violations and count, business functions impacted, data integrity risk (yes/no), security risk (yes/no).
            - Short-term operational risk if left unaddressed (worsening error rate, data corruption, system instability).
            - Estimated exposure/time-to-failure if trend continues (example: error rate doubling in X hours; queue backlog will reach Y in Z hours).
            
            6. RESOLUTION
            
            - Immediate mitigations (short-term fixes) to stop or reduce impact, with step-by-step actions and safe rollback notes. Include command/config change examples or Pega admin actions where applicable (e.g., patch activity, change rule resolution to previous ruleset, disable agent, increase thread pool, scale-out service).
            - Recommended permanent fix(es) with implementation approach, required code/config changes, owner role (e.g., LSA, SRE, Integration team), estimated effort (S, M, L — hours/days), and priority.
            - Verification steps and monitoring: how to validate resolution (tests, queries, sample transactions), success criteria, and metrics to monitor post-fix (error rate, queue depth, CPU).
            - Post-mortem artefacts to produce (root cause ticket, RCA doc, regression test cases) and suggested timeline for completion.
            
            Formatting and tone rules
            
            - Use plain text only. Headings must be the exact uppercase words specified followed by a blank line and then the content.
            - Use short paragraphs and bullet-style lists where useful, but keep the content compact and actionable.
            - Include explicit evidence references (counts, timestamps, log snippets) from the provided data when drawing conclusions.
            - If data is insufficient for any conclusion, explicitly state what is missing and why it matters.
            '''

            # Invoke Agent
            diagnosis_text, token_usage = await execute_diagnosis(agent, prompt)
            
            if diagnosis_text:
                update_diagnosis_in_opensearch(client, group_id, diagnosis_text, token_usage)
            
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
