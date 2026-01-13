import streamlit as st
import pandas as pd
import plotly.express as px
import os
import time
import re
from datetime import datetime
from dotenv import load_dotenv
import asyncio
import chat_agent
from opensearchpy import OpenSearch, helpers
import json
from streamlit.runtime.scriptrunner import add_script_run_ctx, get_script_run_ctx

CHAT_HISTORY_FILE = "chat_history.json"

def load_chat_history():
    """Load chat history from a JSON file."""
    if os.path.exists(CHAT_HISTORY_FILE):
        try:
            with open(CHAT_HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            st.error(f"Error loading chat history: {e}")
            return []
    return []

def save_chat_history(messages):
    """Save chat history to a JSON file."""
    try:
        with open(CHAT_HISTORY_FILE, "w") as f:
            json.dump(messages, f, indent=4)
    except Exception as e:
        st.error(f"Error saving chat history: {e}")

# # Apply nest_asyncio to allow nested event loops in Streamlit
# nest_asyncio.apply()

# Load environment variables
load_dotenv(override=True)

# Page Configuration
st.set_page_config(
    page_title="Pega Log Analysis Dashboard",
    page_icon="🤖",
    layout="wide"
)

# --- Login Authentication ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

def login_page():
    # Centered container for login
    _, col2, _ = st.columns([1, 1, 1])
    with col2:
        if os.path.exists("assets/logo.jpg"):
            st.image("assets/logo.jpg", width="stretch")
        else:
            st.header("IdentifAI 2.0")
        
        st.markdown("<h3 style='text-align: center;'>Please Sign In</h3>", unsafe_allow_html=True)
        
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Login", type="primary", width="stretch"):
            env_user = os.getenv("APP_USERNAME", "alamaticz")
            env_pass = os.getenv("APP_PASSWORD", "Alamaticz#2024")
            
            if username == env_user and password == env_pass:
                st.session_state.logged_in = True
                st.rerun()
            else:
                st.error("Invalid credentials")

if not st.session_state.logged_in:
    login_page()
    st.stop()

# --- Custom CSS for Styling ---
st.markdown("""
    <style>
        /* Center Title */
        h1 {
            text-align: center;
            font-size: 2.5rem;
        }
        /* Reduce top padding, Add bottom padding */
        .block-container {
            padding-top: 2rem; 
            padding-bottom: 5rem;
        }
        /* Enlarge Tab Font */
        .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
            font-size: 20px;
        }
        /* Sidebar Styling */
        [data-testid="stSidebar"] {
            padding-top: 1rem;
        }
    </style>
""", unsafe_allow_html=True)

# sidebar logo
if os.path.exists("assets/logo.jpg"):
    st.sidebar.image("assets/logo.jpg", width="stretch")

st.sidebar.markdown("---")

# --- Configuration ---
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS")

@st.cache_resource
def get_opensearch_client():
    """Create and return OpenSearch client."""
    if not OPENSEARCH_URL:
        st.error("OPENSEARCH_URL not set in .env")
        return None
        
    auth = (OPENSEARCH_USER, OPENSEARCH_PASS) if OPENSEARCH_USER else None
    
    return OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_auth=auth,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=500
    )






def fetch_log_level_distribution(client):
    """Fetch distribution of log levels."""
    query = {
        "size": 0,
        "aggs": {
            "levels": {
                "terms": {"field": "log.level"}
            }
        }
    }
    try:
        response = client.search(body=query, index="pega-logs")
        buckets = response['aggregations']['levels']['buckets']
        return pd.DataFrame(buckets)
    except Exception as e:
        st.error(f"Error fetching log levels: {e}")
        return pd.DataFrame()

def fetch_top_error_groups(client, size=10):
    """Fetch top error groups."""
    query = {
        "size": size,
        "query": {"match_all": {}},
        "sort": [{"count": {"order": "desc"}}]
    }
    try:
        response = client.search(body=query, index="pega-analysis-results")
        hits = response['hits']['hits']
        data = []
        for hit in hits:
            source = hit['_source']
            
            # Parse Rule Name for display
            display_rule = "N/A"
            if source.get('group_type') == "RuleSequence":
                sig = source.get("group_signature", "")
                first_part = sig.split('|')[0].strip()
                tokens = first_part.split('->')
                if len(tokens) >= 2:
                    display_rule = tokens[1]
            elif source.get('representative_log'):
                # Fallback to logger name or exception for other types
                display_rule = source.get('representative_log', {}).get('logger_name', 'N/A')

            data.append({
                "Group Signature": source.get("group_signature"),
                "Count": source.get("count"),
                "Type": source.get("group_type"),
                "Rule Name": display_rule,
                "Diagnosis Status": source.get("diagnosis", {}).get("status", "N/A")
            })
        return pd.DataFrame(data)
    except Exception as e:
        st.error(f"Error fetching top groups: {e}")
        return pd.DataFrame()

def fetch_diagnosis_status_distribution(client):
    """Fetch distribution of diagnosis statuses."""
    try:
        query = {
            "size": 0,
            "aggs": {
                "statuses": {
                    "terms": {"field": "diagnosis.status", "size": 10}
                }
            }
        }
        res = client.search(index="pega-analysis-results", body=query)
        buckets = res['aggregations']['statuses']['buckets']
        return pd.DataFrame(buckets)
    except Exception as e:
        return pd.DataFrame()


def fetch_recent_errors(client):
    """Fetch recent errors (simulated trend) - aggregating by time."""
    # Using date_histogram for efficiency
    query = {
        "size": 0,
        "query": {
            "match": {"log.level": "ERROR"}
        },
        "aggs": {
            "errors_over_time": {
                "date_histogram": {
                    "field": "ingestion_timestamp",
                    "fixed_interval": "1h" 
                }
            }
        }
    }
    try:
        response = client.search(body=query, index="pega-logs")
        buckets = response['aggregations']['errors_over_time']['buckets']
        data = [{"Time": b['key_as_string'], "Count": b['doc_count']} for b in buckets]
        return pd.DataFrame(data)
    except Exception as e:
        st.error(f"Error fetching recent errors: {e}")
        return pd.DataFrame()


def fetch_detailed_table_data(client, size=1000):
    """Fetch detailed data for the table."""
    query = {
        "size": size,
        "sort": [{"count": {"order": "desc"}}]
    }
    try:
        response = client.search(body=query, index="pega-analysis-results")
        hits = response['hits']['hits']
        data = []
        for hit in hits:
            src = hit['_source']
            rep = src.get('representative_log', {})
            
            # Helper to join signatures nicely
            exc_sigs = src.get('exception_signatures', [])
            msg_sigs = src.get('message_signatures', [])
            
            # Use aggregation lists if available, otherwise fallback to representative
            display_exception = exc_sigs[0] if exc_sigs else rep.get('exception_message', 'N/A')
            if len(exc_sigs) > 1:
                display_exception += f" (+{len(exc_sigs)-1} others)"
            
            display_message = msg_sigs[0] if msg_sigs else rep.get('message', 'N/A')
            if len(msg_sigs) > 1:
                display_message += f" (+{len(msg_sigs)-1} others)"

            # Ruleset name parsing from group signature if it's a RuleSequence
            display_rule = "N/A"
            if src.get('group_type') == "RuleSequence":
                # Extract just the first rule path for display
                # Format: type->name->func->class | ...
                first_part = src.get('group_signature', '').split('|')[0].strip()
                tokens = first_part.split('->')
                if len(tokens) >= 2:
                    display_rule = tokens[1] # The Rule Name part
            
            data.append({
                "doc_id": hit['_id'],
                "last_seen": src.get('last_seen'),
                "group_signature": src.get('group_signature'),
                "group_type": src.get('group_type'),
                "count": src.get('count'),
                "diagnosis.status": src.get('diagnosis', {}).get('status', 'PENDING'),
                "display_rule": display_rule,
                "exception_summary": display_exception,
                "message_summary": display_message,
                "logger_name": rep.get('logger_name'),
                "diagnosis.report": src.get('diagnosis', {}).get('report')
            })
        df = pd.DataFrame(data)
        if not df.empty and 'last_seen' in df.columns:
            df['last_seen'] = pd.to_datetime(df['last_seen'], format='mixed')
        return df
    except Exception as e:
        st.error(f"Error fetching details: {e}")
        return pd.DataFrame()

def update_document_status(client, doc_id, new_status):
    """Update the diagnosis status of a document."""
    try:
        client.update(
            index="pega-analysis-results",
            id=doc_id,
            body={"doc": {"diagnosis": {"status": new_status}}}
        )
        return True
    except Exception as e:
        st.error(f"Error updating status: {e}")
        return False

def fetch_group_samples(client, group_id, max_samples=5):
    """Fetch sample raw logs for a group ID."""
    try:
        # 1. Get Group Doc to find raw IDs
        group_doc = client.get(index="pega-analysis-results", id=group_id)
        raw_ids = group_doc["_source"].get("raw_log_ids", [])
        
        if not raw_ids:
            return []
            
        # 2. Get Raw Logs
        # Slice to max_samples
        target_ids = raw_ids[:max_samples]
        
        # Using mget to retrieve docs by ID
        response = client.mget(index="pega-logs", body={"ids": target_ids})
        
        samples = []
        for doc in response.get("docs", []):
            if doc.get("found"):
                samples.append(doc["_source"])
                
        return samples
    except Exception as e:
        return []

@st.dialog("🔍 Detailed Group Inspection", width="large")
def show_inspection_dialog(group_id, row_data, client):
    """
    Dialog to show detailed inspection of a group with Diagnosis capabilities.
    """
    import asyncio
    from Analysis_Diagnosis import diagnose_single_group, construct_analysis_context

    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown(f"**Rule/Message**: `{row_data.get('display_rule', 'N/A')}`")
        st.markdown(f"**Group Type**: {row_data.get('group_type', 'N/A')}")
        st.markdown(f"**Signature**: `{row_data.get('group_signature', 'N/A')}`")
    with c2:
        st.metric("Total Count", row_data.get('count', 0))
        
        # Editable Status
        current_status = row_data.get('diagnosis.status', 'PENDING')
        status_options = ["PENDING", "IN PROCESS", "RESOLVED", "FALSE POSITIVE", "IGNORE", "COMPLETED"]
        
        # Ensure current status is in options
        if current_status not in status_options:
            status_options.append(current_status)
            
        new_status = st.selectbox("Status", options=status_options, index=status_options.index(current_status), key="dialog_status_select")
        
        if new_status != current_status:
            if update_document_status(client, group_id, new_status):
                st.success(f"Status updated to {new_status}")
                time.sleep(1)
                st.rerun()

    st.divider()

    # --- Diagnosis Section ---
    st.markdown("### 🧠 AI Diagnosis")
    
    # 1. Show Analysis Context (What data goes to LLM)
    with st.expander("ℹ️ View Analysis Context (Data sent to AI)", expanded=False):
        # We need to reconstruct the context (simplified) or fetch the doc again to be sure
        # Using row_data is a good approximation but construct_analysis_context expects the full _source format
        # Let's verify if row_data has enough or if we should just use what we have.
        # row_data is from the dataframe, which is flattened.
        # Ideally we fetch the "latest" document to get full non-truncated fields if needed, 
        # but for performance let's try to reconstruct from what we have or fetch light doc.
        try:
             # Fast fetch of single doc source for accurate context Preview
             fresh_doc = client.get(index="pega-analysis-results", id=group_id)
             if fresh_doc and '_source' in fresh_doc:
                 context_preview = construct_analysis_context(fresh_doc['_source'])
                 st.json(context_preview)
             else:
                 st.warning("Could not fetch fresh context.")
        except Exception as e:
            st.warning(f"Could not load context: {e}")

    # Defaults
    default_prompt = """You are a Senior Pega Lead System Architect (LSA). 
Analyze the provided error group data.
Output a report in CLEAN PLAIN TEXT (No markdown).
Sections: EXECUTIVE SUMMARY, SEVERITY, ERROR FLOW, ROOT CAUSE, IMPACT, RESOLUTION."""

    with st.expander("📝 Edit Diagnosis Prompt", expanded=False):
        user_prompt = st.text_area("Prompt Template", value=default_prompt, height=150, help="Use {context_str} to inject data, otherwise it's appended.")

    col_btn, col_res = st.columns([1, 4])
    
    with col_btn:
        if st.button("🚀 Analyze & Diagnose", type="primary"):
            with st.spinner("Analyzing... (This uses Live LLM tokens)"):
                try:
                    # Run async diagnosis in sync streamlit
                    diagnosis_text, usage = asyncio.run(diagnose_single_group(client, group_id, user_prompt))
                    
                    if diagnosis_text:
                        st.session_state[f"last_report_{group_id}"] = diagnosis_text
                        st.success("Diagnosis Complete!")
                        # Removed st.rerun() to keep dialog open
                    else:
                        st.error("Diagnosis returned empty.")
                except Exception as e:
                    st.error(f"Analysis failed: {e}")

    # Display Report (Persist via session state or database reload)
    # Check session state first for immediate feedback, then fall back to DB data
    report_text = st.session_state.get(f"last_report_{group_id}", row_data.get('diagnosis.report'))
    
    if report_text and report_text != 'N/A':
        st.markdown("#### 📄 Diagnosis Report")
        with st.container(border=True):
            st.text(report_text) # Using st.text for plain text as requested, or markdown if clean
    
    st.divider()

    # --- User Comments ---
    st.markdown("### 💬 User Comments")
    
    # Fetch existing comments (needs fresh fetch usually, or rely on row_data if we add it there)
    # Let's fetch fresh comments to be sure we don't overwrite with stale data
    current_comments = ""
    try:
        fresh_doc = client.get(index="pega-analysis-results", id=group_id)
        current_comments = fresh_doc['_source'].get('comments', "")
    except:
        pass

    new_comments = st.text_area("Add notes or implementation details...", value=current_comments, height=100)
    
    if st.button("💾 Save Comments"):
        if update_document_comments(client, group_id, new_comments):
             st.success("Comments saved!")
             time.sleep(1)
             st.rerun()
        else:
             st.error("Failed to save comments.")
    
    st.divider()

    # Fetch Samples
    st.markdown("### 📄 Sample Logs")
    with st.spinner("Fetching raw sample logs..."):
        samples = fetch_group_samples(client, group_id)
    
    if samples:
        tabs = st.tabs([f"Log {i+1}" for i in range(len(samples))])
        for i, sample in enumerate(samples):
            with tabs[i]:
                # Display pretty JSON or formatted message
                msg = sample.get('log', {}).get('message', 'N/A')
                exc = sample.get('exception_message', 'N/A')
                stack = sample.get('stack_trace', [])
                
                st.code(msg, language="text")
                if exc != 'N/A':
                    st.error(f"Exception: {exc}")
                
                if stack:
                    st.warning("Stack Trace Available")
                    with st.expander("View Stack Trace"):
                        st.code("\n".join(stack), language="java")
                        
                with st.expander("Full JSON Metadata"):
                    st.json(sample)
    else:
        st.warning("No raw sample logs found linked to this group (stats-only group or data retention issue).")

def update_document_comments(client, doc_id, comments):
    """Update the comments field of a document."""
    try:
        client.update(
            index="pega-analysis-results",
            id=doc_id,
            body={"doc": {"comments": comments}}
        )
        return True
    except Exception as e:
        st.error(f"Error updating comments: {e}")
        return False


def backup_analysis_status(client):
    """
    Backup diagnosis statuses before deletion.
    Returns a dict: {group_signature: {status: ..., report: ...}}
    Only backs up non-PENDING items.
    """
    backup = {}
    try:
        query = {
            "size": 10000,
            "query": {
                "bool": {
                     "should": [
                        {"bool": {"must_not": {"term": {"diagnosis.status": "PENDING"}}}},
                        {"exists": {"field": "comments"}} # Also matches if comments exist
                     ],
                     "minimum_should_match": 1
                }
            }
        }
        res = client.search(index="pega-analysis-results", body=query)
        for hit in res['hits']['hits']:
            src = hit['_source']
            sig = src.get('group_signature')
            diag = src.get('diagnosis', {})
            comments = src.get('comments', "")
            
            # Backup if we have a diagnosis OR comments
            if sig and (diag.get('status') != 'PENDING' or comments):
                backup[sig] = {
                    "diagnosis": diag,
                    "comments": comments
                }
        return backup
    except Exception as e:
        # Index might not exist
        return {}

def restore_analysis_status(client, backup_data):
    """
    Restore diagnosis statuses to the new analysis results.
    """
    if not backup_data:
        return 0
    
    restored_count = 0
    try:
        # Inefficient but simple: Scan new groups and check if they are in backup
        query = {"query": {"match_all": {}}}
        scan = helpers.scan(client, index="pega-analysis-results", query=query)
        
        bulk_updates = []
        
        for doc in scan:
            doc_id = doc['_id']
            sig = doc['_source'].get('group_signature')
            
            if sig in backup_data:
                # Restore
                saved = backup_data[sig]
                
                # Handle old format (just dict) vs new format (nested)
                if "diagnosis" in saved:
                     diag_val = saved["diagnosis"]
                     comments_val = saved.get("comments", "")
                else:
                     diag_val = saved # Old format was just the diagnosis dict
                     comments_val = ""
                
                update_body = {"doc": {"diagnosis": diag_val, "comments": comments_val}}
                
                # Add to bulk update
                action = {
                    "_op_type": "update",
                    "_index": "pega-analysis-results",
                    "_id": doc_id,
                    "doc": update_body["doc"]
                }
                bulk_updates.append(action)
                restored_count += 1
        
        if bulk_updates:
            helpers.bulk(client, bulk_updates)
            
    except Exception as e:
        print(f"Restore failed: {e}")
        
    return restored_count

# --- Custom CSS ---
def local_css():
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap');
        
        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }
        
        /* Metric Cards */
        div[data-testid="stMetric"] {
            background-color: #ffffff;
            border: 1px solid #e0e0e0;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            text-align: center;
        }
        
        div[data-testid="stMetricLabel"] {
            font-size: 14px;
            color: #666;
            font-weight: 600;
        }
        
        div[data-testid="stMetricValue"] {
            font-size: 24px;
            color: #1f77b4;
            font-weight: 700;
        }

        /* Headers */
        h1, h2, h3 {
            color: #2c3e50;
        }
        
        /* Plotly Chart Container */
        .js-plotly-plot {
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            padding: 10px;
            background: white;
        }
        
        /* Table Styling */
        div[data-testid="stDataFrame"] {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }

        /* Logout Button Red Styling */
        div[data-testid="stSidebar"] button[kind="primary"] {
            background-color: #FF4B4B;
            color: white;
            border: none;
        }
        div[data-testid="stSidebar"] button[kind="primary"]:hover {
            background-color: #FF0000;
            color: white;
        }
        
        </style>
    """, unsafe_allow_html=True)

def calculate_summary_metrics(client):
    """Calculate summary metrics for the dashboard."""
    metrics = {
        "total_errors": 0,
        "unique_issues": 0,
        "pending_issues": 0,
        "resolved_issues": 0
    }
    
    try:
        # Total Errors
        if client.indices.exists(index="pega-logs"):
             count_res = client.count(body={"query": {"match": {"log.level": "ERROR"}}}, index="pega-logs")
             metrics["total_errors"] = count_res["count"]
        
        # Unique Issues
        try:
             if client.indices.exists(index="pega-analysis-results"):
                unique_res = client.count(index="pega-analysis-results")
                metrics["unique_issues"] = unique_res["count"]
                
                # Pending Issues
                pending_res = client.count(
                    index="pega-analysis-results",
                    body={"query": {"term": {"diagnosis.status": "PENDING"}}}
                )
                metrics["pending_issues"] = pending_res["count"]
                
                # Resolved Issues (RESOLVED, FALSE POSITIVE, COMPLETED, IGNORE)
                resolved_res = client.count(
                    index="pega-analysis-results",
                    body={"query": {"terms": {"diagnosis.status": ["RESOLVED", "FALSE POSITIVE", "COMPLETED", "IGNORE"]}}}
                )
                metrics["resolved_issues"] = resolved_res["count"]
                
        except:
             metrics["unique_issues"] = 0
             metrics["pending_issues"] = 0
             metrics["resolved_issues"] = 0
            
    except Exception as e:
        # st.error(f"Error calculating metrics: {e}")
        pass
        
    return metrics

# --- Main Layout ---
st.title("Alamaticz IdentifAI 2.0")
local_css()

client = get_opensearch_client()

# Create Sidebar Navigation
# Initialize active page in session state
if "active_page" not in st.session_state:
    st.session_state.active_page = "Dashboard"

# Navigation Buttons
if st.sidebar.button("Dashboard", width="stretch"):
    st.session_state.active_page = "Dashboard"
    st.rerun()

if st.sidebar.button("Chat Agent", width="stretch"):
    st.session_state.active_page = "Chat Agent"
    st.rerun()

if st.sidebar.button("Upload Logs", width="stretch"):
    st.session_state.active_page = "Upload Logs"
    st.rerun()

if st.sidebar.button("Grouping Studio", width="stretch"):
    st.session_state.active_page = "Grouping Studio"
    st.rerun()


# --- Profile & Settings Logic ---
@st.dialog("👤 User Profile")
def show_profile_dialog():
    st.markdown("### Account Details")
    c1, c2 = st.columns([1, 2])
    with c1:
        if os.path.exists("assets/logo.jpg"):
             st.image("assets/logo.jpg", width=100)
        else:
             st.info("No Avatar")
    with c2:
        st.markdown(f"**Username:** `{st.session_state.get('username', 'Allowed User')}`")
        st.markdown("**Role:** `Administrator`")
        st.markdown(f"**Session Started:** `{datetime.now().strftime('%H:%M %p')}`")

    st.divider()
    st.markdown("### Security")
    with st.form("change_pwd"):
        st.text_input("New Password", type="password")
        st.text_input("Confirm Password", type="password")
        if st.form_submit_button("Update Password"):
            st.success("Password updated for this session.")

@st.dialog("⚙️ System Settings")
def show_settings_dialog():
    st.markdown("### 🔌 Connection Status")
    client = get_opensearch_client()
    if client and client.ping():
        st.success("OpenSearch: Connected (Healthy)")
    else:
        st.error("OpenSearch: Disconnected")
        
    st.divider()
    st.markdown("### 🛠️ Analysis Configuration")
    
    # Analysis Speed
    current_batch = st.session_state.get("config_batch_size", 1000)
    new_batch = st.slider("Grouping Batch Size (Speed vs Stability)", 
                          min_value=500, max_value=5000, value=current_batch, step=500,
                          help="Higher = Faster, but check for stability.")
    st.session_state.config_batch_size = new_batch
    
    # AI Model
    model = st.selectbox("AI Pattern Model", ["GPT-4o (Smartest)", "GPT-3.5-Turbo (Fastest)"], index=0)
    
    # Display Settings
    st.divider()
    st.markdown("### 🎨 Appearance")
    compact = st.toggle("Compact Table Mode", value=st.session_state.get("compact_mode", False))
    st.session_state.compact_mode = compact
    
    if st.button("Save Settings", type="primary"):
        st.rerun()

# --- Sidebar User Menu ---
st.sidebar.markdown("---")
with st.sidebar.expander(f"👤 {os.getenv('APP_USERNAME', 'Alamaticz User')}", expanded=False):
    if st.button("Profile", width="stretch"):
        show_profile_dialog()
    
    if st.button("Settings", width="stretch"):
        show_settings_dialog()
        
    st.divider()
    if st.button("Logout", type="primary", width="stretch"):
        st.session_state.logged_in = False
        st.rerun()

page = st.session_state.active_page

# --- PAGE 1: Dashboard ---
if page == "Dashboard":
    st.markdown("### 📊 Pega Log Analysis Dashboard")
    if client:
        # 1. Summary Metrics (Top)
        metrics = calculate_summary_metrics(client)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Errors", metrics["total_errors"])
        m2.metric("Unique Issues", metrics["unique_issues"])
        m3.metric("Pending Analysis", metrics["pending_issues"])
        m4.metric("Resolved Issues", metrics["resolved_issues"])

        
        st.markdown("---")

        # 2. Detailed Table
        c_tbl_head, c_tbl_btn = st.columns([3, 1])
        c_tbl_head.subheader("📋 Detailed Group Analysis")
        with c_tbl_btn:
            if st.button("✨ Analyse Top 5 Errors", help="Run AI Diagnosis on top pending error groups"):
                with st.spinner("Running AI Diagnosis... (This may take a minute)"):
                    try:
                        import subprocess
                        import sys
                        # Run the diagnosis script as a separate process
                        result = subprocess.run([sys.executable, "Analysis_Diagnosis.py"], capture_output=True, text=True)
                        if result.returncode == 0:
                            st.success("Diagnosis Complete!")
                            with st.expander("View Analysis Logs"):
                                st.text(result.stdout)
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Diagnosis Failed Check logs.")
                            st.text(result.stderr)
                    except Exception as e:
                        st.error(f"Failed to trigger analysis: {e}")
        df_details = fetch_detailed_table_data(client)
        
        if not df_details.empty:
            # Search Bar
            search_query = st.text_input("🔍 Search Logs", placeholder="Type to search by Rule Name, Exception, or Message...")
            
            # Filters
            f1, f2 = st.columns(2)
            with f1:
                statuses = df_details['diagnosis.status'].dropna().unique().tolist()
                selected_statuses = st.multiselect("Filter by Status", statuses, default=[])
            with f2:
                types = df_details['group_type'].dropna().unique().tolist()
                selected_types = st.multiselect("Filter by Type", types, default=[])
            
            # Filter Logic: Empty selection implies "All"
            if not selected_statuses:
                selected_statuses = statuses
            if not selected_types:
                selected_types = types
            
            # Base Filters
            mask = (
                (df_details['diagnosis.status'].isin(selected_statuses)) &
                (df_details['group_type'].isin(selected_types))
            )
            
            # Apply Search Query
            if search_query:
                # Case-insensitive string search across relevant columns
                search_mask = (
                    df_details['display_rule'].astype(str).str.contains(search_query, case=False, na=False, regex=False) |
                    df_details['exception_summary'].astype(str).str.contains(search_query, case=False, na=False, regex=False) |
                    df_details['message_summary'].astype(str).str.contains(search_query, case=False, na=False, regex=False) |
                    df_details['group_type'].astype(str).str.contains(search_query, case=False, na=False, regex=False)
                )
                mask = mask & search_mask

            filtered_df = df_details[mask]
            
            # Ensure all existing statuses are in the options
            standard_options = ["PENDING", "IN PROCESS", "RESOLVED", "FALSE POSITIVE", "IGNORE", "COMPLETED"]
            existing_statuses = df_details['diagnosis.status'].dropna().unique().tolist()
            # Merge and deduplicate, keeping standard options order preferred
            all_options = list(dict.fromkeys(standard_options + existing_statuses))

            # Add Inspect Column
            if "Inspect" not in filtered_df.columns:
                filtered_df.insert(0, "Inspect", False)

            # Table with editing
            edited_df = st.data_editor(
                filtered_df, 
                width="stretch",
                column_config={
                    "Inspect": st.column_config.CheckboxColumn(help="Check to inspect details", width="small", default=False),
                    "doc_id": None, 
                    "last_seen": st.column_config.DatetimeColumn("Last Seen", format="D MMM YYYY, h:mm a"),
                    "count": st.column_config.ProgressColumn("Count", format="%d", min_value=0, max_value=int(df_details['count'].max())),
                    "diagnosis.status": st.column_config.SelectboxColumn("Status", options=all_options, required=True),
                    "group_signature": st.column_config.TextColumn("Full Signature", width="small", help="Unique signature defining this group"),
                    "group_type": "Type",
                    "display_rule": "Rule Name",
                    "exception_summary": "Exception Info",
                    "message_summary": "Log Message",
                    "logger_name": "Logger",
                    "diagnosis.report": "Report"
                },
                disabled=["last_seen", "group_signature", "group_type", "count", "display_rule", 
                          "exception_summary", "message_summary", "logger_name", "diagnosis.report"],
                hide_index=True,
                key="detailed_table"
            )
            
            # --- POPUP LOGIC ---
            inspected_rows = edited_df[edited_df["Inspect"]]
            if not inspected_rows.empty:
                # Show dialog for the first selected
                row = inspected_rows.iloc[0]
                show_inspection_dialog(row['doc_id'], row, client)


            # Detect Changes
            if not filtered_df.equals(edited_df):
                diff = edited_df["diagnosis.status"] != filtered_df["diagnosis.status"]
                changed_rows = edited_df[diff]
                if not changed_rows.empty:
                    for index, row in changed_rows.iterrows():
                        doc_id = row['doc_id']
                        new_status = row['diagnosis.status']
                        update_document_status(client, doc_id, new_status)
                    st.success("Status updated successfully! Refreshing...")
                    st.rerun()
        else:
            st.info("No detailed data available.")

        st.markdown("---")
        
        # 3. Visualizations
        st.subheader("📊 Analytics")
        
        # Row 1: Log Level & Diagnosis Status
        c1, c2 = st.columns(2)
        with c1:
            st.caption("Log Level Distribution")
            df_levels = fetch_log_level_distribution(client)
            if not df_levels.empty:
                fig_levels = px.pie(df_levels, values='doc_count', names='key', hole=0.4)
                st.plotly_chart(fig_levels)
        with c2:
            st.caption("Diagnosis Status")
            df_status = fetch_diagnosis_status_distribution(client)
            if not df_status.empty:
                fig_status = px.pie(df_status, values='doc_count', names='key', hole=0.4)
                st.plotly_chart(fig_status)

        # Row 2: Top Groups (Full Width)
        st.caption("Top Error Groups")
        df_groups = fetch_top_error_groups(client, size=5)
        if not df_groups.empty:
            # Truncate long signatures for cleaner visualization
            df_groups['Display Name'] = df_groups['Group Signature'].apply(
                lambda x: str(x)[:60] + '...' if len(str(x)) > 60 else str(x)
            )
            fig_groups = px.bar(df_groups, y='Display Name', x='Count', orientation='h', 
                                hover_data=["Group Signature"])
            fig_groups.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig_groups)

        st.markdown("---")
        
        # 4. Trendline (Last)
        st.subheader("📈 Error Trend")
        df_trend = fetch_recent_errors(client)
        if not df_trend.empty:
            fig_trend = px.area(df_trend, x='Time', y='Count')
            st.plotly_chart(fig_trend)
        else:
            st.info("No recent error data found.")
    else:
        st.error("Failed to connect to OpenSearch.")

# --- PAGE 2: Chat Agent ---
elif page == "Chat Agent":
    st.header("💬 AI Assistant")
    # Chat History
    # Chat History - In-Memory Only
    if "messages" not in st.session_state:
        st.session_state.messages = []
        
        # Add Welcome Message if history is empty
        welcome_msg = {
            "role": "assistant", 
            "content": "Welcome to Pega Log Analysis Assistant! I can help you analyze errors, find specific logs, or summarize issues. What would you like to know?"
        }
        st.session_state.messages.append(welcome_msg)

    # Determine avatar
    if os.path.exists("assets/agent_logo.png"):
        assistant_avatar = "assets/agent_logo.png"
    elif os.path.exists("assets/logo.jpg"):
        assistant_avatar = "assets/logo.jpg"
    else:
        assistant_avatar = None

    # Display chat messages
    for message in st.session_state.messages:
        avatar = assistant_avatar if message["role"] == "assistant" else None
        with st.chat_message(message["role"], avatar=avatar):
            st.markdown(message["content"])

    # User Input
    if prompt := st.chat_input("What would you like to know?"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        if os.path.exists("assets/agent_logo.png"):
             avatar_img = "assets/agent_logo.png"
        elif os.path.exists("assets/logo.jpg"):
             avatar_img = "assets/logo.jpg"
        else:
             avatar_img = None

        with st.chat_message("assistant", avatar=avatar_img):
            # Wrapper for async execution
            try:
                # Get or create event loop for this thread
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                async def run_agent_async(user_input):
                    # Manage Memory in Session State
                    if "agent_memory" not in st.session_state:
                         # Lazy import to avoid circular dep if any
                         from langchain.memory import ConversationBufferMemory
                         st.session_state.agent_memory = ConversationBufferMemory(
                            memory_key="chat_history",
                            return_messages=True,
                            input_key="input",
                            output_key="output"
                        )
                    
                    # Initialize Agent
                    agent_executor = await chat_agent.initialize_agent_executor(memory=st.session_state.agent_memory)

                    # Create a placeholder for status updates
                    status_placeholder = st.empty()
                    status_placeholder.markdown("🧠 *Thinking...*")
                    full_response = ""
                    try:
                        # Stream events
                        async for event in agent_executor.astream_events({"input": user_input}, version="v1"):
                            kind = event["event"]
                            
                            if kind == "on_tool_start":
                                tool_input = event["data"].get("input")
                                status_placeholder.markdown(f"🛠️ **Executing**: `{event['name']}`\nInput: `{tool_input}`")
                            elif kind == "on_tool_end":
                                 # Clear or update status, but don't print persistently
                                 status_placeholder.markdown(f"✅ **Finished**: `{event['name']}`")
                            elif kind == "on_chat_model_stream":
                                content = event["data"]["chunk"].content
                                if content:
                                    full_response += content
                                    yield content
                    except GeneratorExit:
                        pass
                    except Exception as e:
                        status_placeholder.error(f"Stream Error: {e}")
                    
                    status_placeholder.empty() # Clear status
                    
                    # Store result in session state for saving
                    st.session_state.temp_last_response = full_response
                
                # Define a synchronous wrapper to drive the async generator
                def sync_stream_wrapper(async_gen):
                    while True:
                        try:
                            # Fetch next chunk from async generator using the loop
                            chunk = loop.run_until_complete(async_gen.__anext__())
                            yield chunk
                        except StopAsyncIteration:
                            break
                        except Exception as e:
                            err_msg = f"Streaming error: {e}"
                            if hasattr(e, 'exceptions'):
                                for idx, sub_e in enumerate(e.exceptions):
                                    err_msg += f"\nSub-exception {idx+1}: {sub_e} (Type: {type(sub_e).__name__})"
                            st.error(err_msg)
                            break

                # Execute streaming using the wrapper
                st.write_stream(sync_stream_wrapper(run_agent_async(prompt)))
                
                # Save history
                final_res = st.session_state.get("temp_last_response")
                if final_res:
                    st.session_state.messages.append({"role": "assistant", "content": final_res})
                    del st.session_state.temp_last_response
                    
            except Exception as e:
                st.error(f"An error occurred: {e}")
                import traceback
                st.text(traceback.format_exc())

# --- PAGE 3: Upload Logs ---
elif page == "Upload Logs":
    st.header("📤 Upload Pega Logs")
    st.markdown("Upload a `.log` or `.json` file to ingest into OpenSearch with stack trace parsing.")
    
    uploaded_file = st.file_uploader("Choose a file", type=["log", "json", "txt"])
    
    if uploaded_file is not None:
        if st.button("Start Ingestion", type="primary"):
            with st.spinner("Ingesting logs..."):
                try:
                    # Save to temp file
                    import tempfile
                    from ingest_pega_logs import ingest_file
                    from log_grouper import process_logs
                    
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp_file:
                        tmp_file.write(uploaded_file.getvalue())
                        tmp_path = tmp_file.name
                    
                    # Run ingestion
                    result = ingest_file(tmp_path)
                    
                    # Clean up
                    os.remove(tmp_path)
                    
                    if result.get("status") == "success":
                        st.success("Ingestion Complete!")
                        st.json(result)
                        
                        # Trigger Grouping for this session
                        if result.get("session_id"):
                            st.info("Analyzing and grouping imported logs... (This may take a moment)")
                            with st.spinner("Running Grouping Logic..."):
                                try:
                                    process_logs(session_id=result.get("session_id"), ignore_checkpoint=True)
                                    st.success("Grouping Analysis Complete!")
                                except Exception as e:
                                    st.error(f"Grouping failed: {e}")
                                    
                        st.balloons()
                    else:
                        st.error(f"Ingestion failed: {result.get('message')}")
                except Exception as e:
                    st.error(f"Error during ingestion: {str(e)}")
                        
# --- PAGE 4: Grouping Studio ---
elif page == "Grouping Studio":
    st.header("🎨 Grouping Studio")
    st.info("Define custom grouping patterns based on examples.")
    
    # Imports for LLM
    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    
    st.subheader("1. Find Similar Groups")
    search_query = st.text_input("Search Logs / Groups", placeholder="Filter by Message, Exception or Rule...")
    
    if client:
        # Fetch detailed data (Same as Dashboard Page)
        df_details = fetch_detailed_table_data(client, size=1000)
        
        if not df_details.empty:
            # --- Selection State Management ---
            # Toggle for "Select All" / "Deselect All"
            if "grouping_editor_key" not in st.session_state:
                st.session_state.grouping_editor_key = 0
            if "select_all_state" not in st.session_state:
                 st.session_state.select_all_state = None # None, True, False

            # Buttons Row
            b1, b2, b3 = st.columns([1, 1, 6])
            with b1:
                if st.button("Select All", type="primary"):
                    st.session_state.select_all_state = True
                    st.session_state.grouping_editor_key += 1
                    st.rerun()
            with b2:
                if st.button("Deselect All"):
                    st.session_state.select_all_state = False
                    st.session_state.grouping_editor_key += 1
                    st.rerun()

            # Apply Bulk Selection State if triggered
            # We insert the column with the forced value if state was just toggled
            # Note: data_editor edits will override this on subsequent runs if key doesn't change
            # But we increment key on button click, so it re-initializes from this df.
            default_select = False
            if st.session_state.select_all_state is not None:
                default_select = st.session_state.select_all_state
                # Reset state so individual toggles work afterwards? 
                # Actually, if we keep reusing this DF logic, it might reset user edits on other interactions.
                # So we only want to force it when the key increments.
                # Since key increments ONLY on button click, this logic holds for that render.
                # For normal interactions (no button click), select_all_state persists but key is same.
                # Ideally, we should set it to None after use, but we need it for the render.
                # Let's just use the boolean. 
            
            # Add Select Column
            # If we are re-rendering with a new key, this column value effectively resets the editor state
            df_details.insert(0, "Select", default_select)

            # Client-side Filtering based on Search Query
            if search_query:
                # Case-insensitive string search across relevant columns
                mask = (
                    df_details['display_rule'].astype(str).str.contains(search_query, case=False, na=False, regex=False) |
                    df_details['exception_summary'].astype(str).str.contains(search_query, case=False, na=False, regex=False) |
                    df_details['message_summary'].astype(str).str.contains(search_query, case=False, na=False, regex=False) |
                    df_details['group_type'].astype(str).str.contains(search_query, case=False, na=False, regex=False)
                )
                filtered_df = df_details[mask]
            else:
                filtered_df = df_details

            # Ensure Status options are present for the Selectbox config (reuse logic)
            standard_options = ["PENDING", "IN PROCESS", "RESOLVED", "FALSE POSITIVE", "IGNORE", "COMPLETED"]
            existing_statuses = df_details['diagnosis.status'].dropna().unique().tolist()
            all_options = list(dict.fromkeys(standard_options + existing_statuses))

            # Render Table exactly like Dashboard but with Select column
            # Use dynamic key to force reset on Select All/Deselect All
            edited_df = st.data_editor(
                filtered_df,
                width="stretch",
                column_config={
                    "Select": st.column_config.CheckboxColumn(required=True),
                    "doc_id": None, 
                    "last_seen": st.column_config.DatetimeColumn("Last Seen", format="D MMM YYYY, h:mm a"),
                    "count": st.column_config.ProgressColumn("Count", format="%d", min_value=0, max_value=int(df_details['count'].max())),
                    "diagnosis.status": st.column_config.SelectboxColumn("Status", options=all_options, required=True),
                    "group_signature": st.column_config.TextColumn("Full Signature", width="small", help="Unique signature defining this group"),
                    "group_type": "Type",
                    "display_rule": "Rule Name",
                    "exception_summary": "Exception Info",
                    "message_summary": "Log Message",
                    "logger_name": "Logger",
                    "diagnosis.report": "Report"
                },
                disabled=["last_seen", "group_signature", "group_type", "count", "display_rule", 
                          "exception_summary", "message_summary", "logger_name", "diagnosis.report"],
                hide_index=True,
                key=f"grouping_selector_table_{st.session_state.grouping_editor_key}"
            )



            # Get Selected Rows
            selected_rows = edited_df[edited_df["Select"]]
            
            if not selected_rows.empty:
                st.divider()
                st.subheader("2. Analyze Pattern")
                
                # Prepare Safe Payload
                examples = []
                for index, row in selected_rows.iterrows():
                    # For Analysis Results, we prefer Exception Summary or full Signature
                    sig = row.get("group_signature")
                    exc = row.get("exception_summary")
                    msg = row.get("message_summary")
                    
                    # Heuristic: Send the most descriptive text
                    if exc and exc != "N/A":
                        examples.append(exc)
                    elif msg and msg != "N/A":
                        examples.append(msg)
                    else:
                        examples.append(sig)
                    
                st.write("Selected Candidates (Normalized):")
                st.code(json.dumps(examples, indent=2), language="json")
                
                if st.button("✨ Generate Regex Pattern", key="generate_regex_btn"):
                    with st.spinner("Analyzing patterns & checking existing rules..."):
                        try:
                            llm = ChatOpenAI(model="gpt-4o", temperature=0)
                            
                            # Fetch existing rules from OpenSearch
                            custom_patterns = []
                            try:
                                # Fetch all (up to 1000)
                                response = client.search(index="pega-custom-patterns", body={"query": {"match_all": {}}, "size": 1000})
                                custom_patterns = [hit["_source"] for hit in response["hits"]["hits"]]
                            except Exception as e:
                                # Index might not exist yet, which is fine
                                pass
                            
                            existing_rules_str = json.dumps(custom_patterns, indent=2) if custom_patterns else "[]"
                            
                            prompt = ChatPromptTemplate.from_template(
                                """
                                You are a regex expert for log grouping.
                                
                                **Task**:
                                1. Analyze the following log signatures/messages (represented by {count} examples).
                                2. Checks against these **EXISTING RULES**:
                                {existing_rules}
                                
                                **Decision Logic**:
                                - If the examples **match an existing rule** (or are a minor variation), suggest an **UPDATE** to that rule to cover these new cases.
                                - If the examples represent a **completely new pattern**, suggest a **NEW** rule.
                                
                                **Input Examples**:
                                {examples}
                                
                                Return strictly Valid JSON:
                                {{
                                    "action": "UPDATE" or "NEW",
                                    "rule_name": "Name of the existing rule OR a descriptive new name",
                                    "group_type": "The existing group category OR a new category",
                                    "regex_pattern": "The UPDATED python regex (matching old + new) OR a completely NEW regex"
                                }}
                                
                                **Critical Rules for Regex Generation**:
                                1. **Do NOT use placeholders** like `[DATE]`, `[FILE_PATH]`, or `[ID]`. You must use valid regex for them (e.g., `.*?`, `\d+`, `\d{{4}}-\d{{2}}-\d{{2}}`).
                                2. **Target Raw Logs**: The input examples you see might be "Normalized Signatures", but your regex must match the **RAW LOG LINES**.
                                   - Raw logs often start with a timestamp (e.g., `2024-01-01 10:00:00 ERROR...`).
                                   - **DO NOT** start your regex with `^` unless you explicitly include the timestamp pattern at the start.
                                   - Ideally, **start with `.*`** or just the unanchored text to match broadly within the message.
                                3. **Variable Parts**: Use `.*` or `[\d]+` for any dynamic values (IDs, Dates, Paths).
                                4. **Keep Static Parts Exact**: Match the constant error text precisely to avoid false positives.
                                """
                            )
                            chain = prompt | llm | StrOutputParser()
                            result_str = chain.invoke({
                                "count": len(examples), 
                                "examples": "\n".join(examples),
                                "existing_rules": existing_rules_str
                            })
                            
                            # Clean and Parse JSON
                            cleaned_json = result_str.replace("```json", "").replace("```", "").strip()
                            result = json.loads(cleaned_json)
                            
                            # Update Session State
                            st.session_state.generated_pattern = result.get("regex_pattern", "")
                            st.session_state.suggested_name = result.get("rule_name", "")
                            st.session_state.suggested_type = result.get("group_type", "Custom")
                            
                            if result.get("action") == "UPDATE":
                                st.info(f"💡 Merging with existing rule: **{result.get('rule_name')}**")
                            else:
                                st.success("✨ New Pattern Generated!")
                                
                        except Exception as e:
                            st.error(f"LLM Error: {e}")

                # 3. Save Section
                if "generated_pattern" in st.session_state:
                     st.divider()
                     st.subheader("3. Save Rule")
                     
                     with st.form("save_rule_form"):
                         # Use defaults if available
                         pat_val = st.session_state.generated_pattern
                         name_val = st.session_state.get("suggested_name", "")
                         type_val = st.session_state.get("suggested_type", "Custom")
                         
                         pat = st.text_input("Regex Pattern", value=pat_val)
                         c1, c2 = st.columns(2)
                         # Explicit key management to avoid conflicts if needed, but form isolates them
                         rule_name = c1.text_input("Rule Name", value=name_val, placeholder="e.g. Activity Timeouts")
                         group_cat = c2.text_input("Group Category", value=type_val, placeholder="e.g. CSP, Infrastructure")
                         
                         submitted = st.form_submit_button("Save Rule to Library")

                         if submitted:
                             if pat and rule_name:
                                 new_rule = {
                                     "name": rule_name,
                                     "pattern": pat,
                                     "group_type": group_cat
                                 }
                                 
                                 # Smart Save: Upsert to OpenSearch
                                 try:
                                     # Use rule name as ID for idempotency
                                     doc_id = rule_name
                                     
                                     # Add timestamp
                                     new_rule["created_at"] = datetime.utcnow().isoformat()
                                     
                                     client.index(
                                         index="pega-custom-patterns",
                                         id=doc_id,
                                         body=new_rule,
                                         refresh=True
                                     )
                                     
                                     st.success(f"Rule '{rule_name}' stored successfully! Index updated.")
                                     time.sleep(2)
                                     st.rerun()
                                 except Exception as e:
                                     st.error(f"Failed to save rule to OpenSearch: {e}")
                             else:
                                 st.warning("Please provide both name and pattern.")
            
            # 4. Automation: Run Grouper
            st.divider()
            st.subheader("4. Apply Changes")
            st.markdown("Run the grouping logic now to apply your new rules to existing logs.")
            
            if st.button("🚀 Apply Rules Now (Reset & Reprocess)", type="primary"):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    # 1. Backup
                    status_text.text("Step 1/4: Backing up manual analysis...")
                    backup_data = backup_analysis_status(client)
                    progress_bar.progress(25)
                    time.sleep(0.5)

                    # 2. Delete Index
                    status_text.text("Step 2/4: Resetting analysis index...")
                    client.indices.delete(index="pega-analysis-results", ignore=[400, 404])
                    progress_bar.progress(50)
                    time.sleep(0.5)


                    # 2a. RETRY FAILED DOCS (Enhancement)
                    # Check for failed_docs.jsonl and ingest if exists
                    failed_docs_path = "failed_docs.jsonl"
                    if os.path.exists(failed_docs_path):
                         status_text.text("Step 2.5/4: Retrying failed documents...")
                         try:
                             from ingest_pega_logs import ingest_failed_docs
                             retry_result = ingest_failed_docs(failed_docs_path)
                             
                             if retry_result.get("retried_indexed", 0) > 0:
                                 st.success(f"Successfully recovered {retry_result['retried_indexed']} failed documents!")
                             
                             # Optional: cleanup if successful? 
                             # Usually safer to keep until manual delete, or rename.
                             # But for now, we just retry.
                         except Exception as e:
                             st.warning(f"Retry step failed: {e}")
                         time.sleep(0.5)

                    # 3. Run Grouper (Optimized Parallel)
                    status_text.text("Step 3/4: Running new grouping analysis (Parallel x4)...")
                    
                    try:
                        import subprocess
                        import sys
                        
                        # Use subprocess to run the parallel version
                        # equivalent to: python log_grouper.py --ignore-checkpoint --workers 4
                        cmd = [
                            sys.executable, 
                            "log_grouper.py", 
                            "--ignore-checkpoint", 
                            "--workers", "4",
                            "--batch-size", "1000"
                        ]
                        
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        
                        if result.returncode != 0:
                             st.error(f"Grouping Script Failed:\n{result.stderr}")
                             # If it failed, we shouldn't continue to restore potentially
                             st.stop()
                        else:
                             # print(result.stdout) # Optional debug
                             progress_bar.progress(75)

                        # 4. Restore
                        status_text.text("Step 4/4: Restoring manual status labels...")
                        restored_count = restore_analysis_status(client, backup_data)
                        progress_bar.progress(100)
                        
                        status_text.text("Done!")
                        time.sleep(1)
                        st.success(f"Analysis Reset & Updated! (Restored {restored_count} manual labels)")
                        
                    except Exception as e:
                         st.error(f"Grouping Failed: {e}")
                         st.stop()
                        
                except Exception as e:
                     st.error(f"Workflow failed: {e}")
                finally:
                     # Clean up UI
                     time.sleep(2)
                     status_text.empty()
                     progress_bar.empty()

            else:
                pass 
                # st.warning("No logs found matching query.")
                        

