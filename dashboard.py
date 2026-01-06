import streamlit as st
import pandas as pd
import plotly.express as px
import os
from dotenv import load_dotenv
# import asyncio
# import nest_asyncio
# from langchain_mcp_adapters.client import MultiServerMCPClient
# from langchain_openai import ChatOpenAI
# from langchain.agents import create_tool_calling_agent, AgentExecutor
# from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
# from langchain.memory import ConversationBufferMemory
# from langchain_community.callbacks.streamlit import StreamlitCallbackHandler
from opensearchpy import OpenSearch
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
            if username == "alamaticz" and password == "Alamaticz#2024":
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
        "sort": [{"last_seen": {"order": "desc"}}]
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
            df['last_seen'] = pd.to_datetime(df['last_seen'])
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
        "most_frequent": "N/A",
        "last_incident": "N/A"
    }
    
    try:
        # Total Errors
        count_res = client.count(body={"query": {"match": {"log.level": "ERROR"}}}, index="pega-logs")
        metrics["total_errors"] = count_res["count"]
        
        # Unique Issues & Top Rule Error
        # We want the group with the highest 'count' field
        # Unique Issues
        try:
             unique_res = client.count(index="pega-analysis-results")
             metrics["unique_issues"] = unique_res["count"]
        except:
             metrics["unique_issues"] = 0

        # Top Rule Error
        rule_query = {
            "size": 1,
            "query": {"term": {"group_type": "RuleSequence"}},
            "sort": [{"count": {"order": "desc"}}]
        }
        rule_res = client.search(body=rule_query, index="pega-analysis-results")
        
        if rule_res["hits"]["hits"]:
            top_src = rule_res["hits"]["hits"][0]["_source"]
            sig = top_src.get("group_signature", "")
            
            # Parse Rule Name
            # Extract just the rule name from the first part of signature
            first_part = sig.split('|')[0].strip()
            tokens = first_part.split('->')
            if len(tokens) >= 2:
                metrics["most_frequent"] = tokens[1]
            else:
                metrics["most_frequent"] = sig[:30] + "..."
        else:
            metrics["most_frequent"] = "None"
            
        # Last Incident
        last_query = {
            "size": 1,
            "sort": [{"ingestion_timestamp": {"order": "desc"}}],
            "query": {"match": {"log.level": "ERROR"}}
        }
        last_res = client.search(body=last_query, index="pega-logs")
        if last_res["hits"]["hits"]:
            timestamp = last_res["hits"]["hits"][0]["_source"].get("ingestion_timestamp")
            try:
                dt = pd.to_datetime(timestamp)
                suffix = 'th' if 11 <= dt.day <= 13 else {1:'st', 2:'nd', 3:'rd'}.get(dt.day % 10, 'th')
                # explicit format: "31st dec 2026 , 7:06 am"
                date_part = f"{dt.day}{suffix} {dt.strftime('%b').lower()} {dt.year}"
                time_part = dt.strftime('%I:%M %p').lstrip('0').lower()
                metrics["last_incident"] = f"{date_part} , {time_part}"
            except Exception:
                metrics["last_incident"] = timestamp
            
    except Exception as e:
        st.error(f"Error calculating metrics: {e}")
        
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


st.sidebar.markdown("---")
if st.sidebar.button("Logout", type="primary", width="stretch"):
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
        m3.metric("Top Rule Failure", metrics["most_frequent"])
        m4.metric("Recent Ingestion", metrics["last_incident"])
        
        st.markdown("---")

        # 2. Detailed Table
        st.subheader("📋 Detailed Group Analysis")
        df_details = fetch_detailed_table_data(client)
        
        if not df_details.empty:
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

            filtered_df = df_details[
                (df_details['diagnosis.status'].isin(selected_statuses)) &
                (df_details['group_type'].isin(selected_types))
            ]
            
            # Ensure all existing statuses are in the options
            standard_options = ["PENDING", "IN PROCESS", "RESOLVED", "FALSE POSITIVE", "IGNORE", "COMPLETED"]
            existing_statuses = df_details['diagnosis.status'].dropna().unique().tolist()
            # Merge and deduplicate, keeping standard options order preferred
            all_options = list(dict.fromkeys(standard_options + existing_statuses))

            # Table with editing
            edited_df = st.data_editor(
                filtered_df, 
                width="stretch",
                column_config={
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
    st.info("Work in Progress")
    # st.markdown("Ask questions about your logs and analysis results.")

    # # Chat History
    # if "messages" not in st.session_state:
    #     st.session_state.messages = load_chat_history()
        
    #     # Add Welcome Message if history is empty
    #     if not st.session_state.messages:
    #         welcome_msg = {
    #             "role": "assistant", 
    #             "content": "Welcome to Pega Log Analysis Assistant! I can help you analyze errors, find specific logs, or summarize issues. What would you like to know?"
    #         }
    #         st.session_state.messages.append(welcome_msg)
    #         save_chat_history(st.session_state.messages)

    # # Determine avatar
    # if os.path.exists("assets/agent_logo.png"):
    #     assistant_avatar = "assets/agent_logo.png"
    # elif os.path.exists("assets/logo.jpg"):
    #     assistant_avatar = "assets/logo.jpg"
    # else:
    #     assistant_avatar = None

    # # Display chat messages
    # for message in st.session_state.messages:
    #     avatar = assistant_avatar if message["role"] == "assistant" else None
    #     with st.chat_message(message["role"], avatar=avatar):
    #         st.markdown(message["content"])

    # # User Input
    # if prompt := st.chat_input("What would you like to know?"):
    #     st.session_state.messages.append({"role": "user", "content": prompt})
    #     save_chat_history(st.session_state.messages)
    #     with st.chat_message("user"):
    #         st.markdown(prompt)

    #     if os.path.exists("assets/agent_logo.png"):
    #          avatar_img = "assets/agent_logo.png"
    #     elif os.path.exists("assets/logo.jpg"):
    #          avatar_img = "assets/logo.jpg"
    #     else:
    #          avatar_img = None

    #     with st.chat_message("assistant", avatar=avatar_img):
    #         # Wrapper for async execution
    #         try:
    #             # Get or create event loop for this thread
    #             try:
    #                 loop = asyncio.get_event_loop()
    #             except RuntimeError:
    #                 loop = asyncio.new_event_loop()
    #                 asyncio.set_event_loop(loop)

    #             async def run_agent_async(user_input):
    #                 # Manage Memory in Session State
    #                 if "agent_memory" not in st.session_state:
    #                      st.session_state.agent_memory = ConversationBufferMemory(
    #                         memory_key="chat_history",
    #                         return_messages=True,
    #                         input_key="input",
    #                         output_key="output"
    #                     )
                    
    #                 # Connect to OpenSearch MCP
    #                 mcp_server_config = {
    #                     "opensearch": { 
    #                         "url": "http://localhost:9900/sse",
    #                         "transport": "sse",
    #                         "headers": {
    #                             "Content-Type": "application/json",
    #                             "Accept-Encoding": "identity",
    #                         }
    #                     }
    #                 }
                    
    #                 client = MultiServerMCPClient(mcp_server_config)
    #                 tools = await client.get_tools() 
                    
    #                 model = ChatOpenAI(model="gpt-4o", streaming=True)
                    
    #                 prompt = ChatPromptTemplate.from_messages([
    #                     ("system", "You are a helpful Log Analysis Assistant. You have access to OpenSearch logs. You usually don't need to mention Tool names. IMPORTANT: When searching for errors or logs, ALWAYS search across 'log.message', 'exception_message', and 'log.exception.exception_message' fields. Do not rely on a single field."),
    #                     MessagesPlaceholder(variable_name="chat_history"),
    #                     ("human", "{input}"),
    #                     MessagesPlaceholder(variable_name="agent_scratchpad"),
    #                 ])

    #                 agent = create_tool_calling_agent(
    #                     llm=model,
    #                     tools=tools,
    #                     prompt=prompt
    #                 )

    #                 agent_executor = AgentExecutor(
    #                     agent=agent,
    #                     tools=tools,
    #                     verbose=True,
    #                     memory=st.session_state.agent_memory,
    #                     handle_parsing_errors=True,
    #                     return_intermediate_steps=True
    #                 )

    #                 # Create a placeholder for status updates
    #                 status_placeholder = st.empty()
    #                 status_placeholder.markdown("🧠 *Thinking...*")
    #                 full_response = ""
    #                 try:
    #                     # Stream events
    #                     async for event in agent_executor.astream_events({"input": user_input}, version="v1"):
    #                         kind = event["event"]
    #                         
    #                         if kind == "on_tool_start":
    #                             tool_input = event["data"].get("input")
    #                             status_placeholder.markdown(f"🛠️ **Executing**: `{event['name']}`\nInput: `{tool_input}`")
    #                         elif kind == "on_tool_end":
    #                              # Clear or update status, but don't print persistently
    #                              status_placeholder.markdown(f"✅ **Finished**: `{event['name']}`")
    #                         elif kind == "on_chat_model_stream":
    #                             content = event["data"]["chunk"].content
    #                             if content:
    #                                 full_response += content
    #                                 yield content
    #                 except GeneratorExit:
    #                     # Streamlit interrupted the stream
    #                     pass
    #                 except Exception as e:
    #                     # Log other errors
    #                     pass
    #                 
    #                 status_placeholder.empty() # Clear status
    #                 
    #                 # Store result in session state for saving
    #                 st.session_state.temp_last_response = full_response
    #             
    #             # Define a synchronous wrapper to drive the async generator
    #             def sync_stream_wrapper(async_gen):
    #                 while True:
    #                     try:
    #                         # Fetch next chunk from async generator using the loop
    #                         chunk = loop.run_until_complete(async_gen.__anext__())
    #                         yield chunk
    #                     except StopAsyncIteration:
    #                         break
    #                     except Exception as e:
    #                         st.error(f"Streaming error: {e}")
    #                         break

    #             # Execute streaming using the wrapper
    #             st.write_stream(sync_stream_wrapper(run_agent_async(prompt)))
    #             
    #             # Save history
    #             final_res = st.session_state.get("temp_last_response")
    #             if final_res:
    #                 st.session_state.messages.append({"role": "assistant", "content": final_res})
    #                 save_chat_history(st.session_state.messages)
    #                 del st.session_state.temp_last_response
    #                 
    #         except Exception as e:
    #             st.error(f"An error occurred: {e}")

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
    
    # 1. Search Interface
    st.subheader("1. Find Similar Logs")
    search_query = st.text_input("Search Pega Logs (Message / Exception)", placeholder="e.g. TimeoutException")
    
    if search_query:
        if client:
            # Flexible match query
            s_query = {
                "size": 20,
                "query": {
                    "bool": {
                        "should": [
                            {"match": {"log.message": search_query}},
                            {"match": {"exception_message": search_query}},
                            {"match": {"normalized_message": search_query}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
            res = client.search(index="pega-logs", body=s_query)
            hits = res['hits']['hits']
            
            if hits:
                # Prepare data for selection - Add "Select" column
                selection_data = []
                for hit in hits:
                    src = hit['_source']
                    selection_data.append({
                        "Select": False,
                        "_id": hit['_id'],
                        "Time": src.get("ingestion_timestamp"),
                        "Message": src.get("log", {}).get("message", "")[:200], # Truncate for UI
                        "Normalized Message": src.get("normalized_message", ""),
                        "Normalized Exception": src.get("normalized_exception_message", "")
                    })
                
                df_hits = pd.DataFrame(selection_data)
                
                # Editable Table
                edited_df = st.data_editor(
                    df_hits,
                    column_config={
                        "Select": st.column_config.CheckboxColumn(required=True),
                        "_id": None, # Hide ID
                        "Time": st.column_config.DatetimeColumn(format="D MMM HH:mm:ss"),
                        "Message": st.column_config.TextColumn("Log Message", width="large"),
                        "Normalized Message": None, # Hide detail columns
                        "Normalized Exception": None
                    },
                    hide_index=True,
                    use_container_width=True,
                    key="selector_table"
                )
                
                # Get Selected Rows
                selected_rows = edited_df[edited_df["Select"]]
                
                if not selected_rows.empty:
                    st.divider()
                    st.subheader("2. Analyze Pattern")
                    
                    # Prepare Safe Payload
                    examples = []
                    for index, row in selected_rows.iterrows():
                        # PREFER Exception if available, else Message
                        if row["Normalized Exception"]:
                            examples.append(row["Normalized Exception"])
                        else:
                            examples.append(row["Normalized Message"])
                    
                    st.write("Selected Candidates (Normalized):")
                    st.code(json.dumps(examples, indent=2), language="json")
                    
                    if st.button("✨ Generate Regex Pattern"):
                        with st.spinner("Asking LLM to extract pattern..."):
                            try:
                                llm = ChatOpenAI(model="gpt-4o", temperature=0)
                                prompt = ChatPromptTemplate.from_template(
                                    """
                                    You are a Regex Expert.
                                    Analyze these {count} log error strings.
                                    Goal: Create a SINGLE Python Regex that matches ALL of them.
                                    
                                    Rules:
                                    1. Use `.*` or `[\d]+` for variable parts.
                                    2. Keep static parts exact to ensure high precision.
                                    3. Return ONLY the Regex string. No markdown, no explanations.
                                    
                                    Examples:
                                    {examples}
                                    """
                                )
                                chain = prompt | llm | StrOutputParser()
                                pattern = chain.invoke({"count": len(examples), "examples": "\n".join(examples)})
                                
                                st.session_state.generated_pattern = pattern
                                st.success("Pattern Generated!")
                            except Exception as e:
                                st.error(f"LLM Error: {e}")

                    # 3. Save Section
                    if "generated_pattern" in st.session_state:
                         st.divider()
                         st.subheader("3. Save Rule")
                         
                         pat = st.text_input("Regex Pattern", value=st.session_state.generated_pattern)
                         c1, c2 = st.columns(2)
                         rule_name = c1.text_input("Rule Name", placeholder="e.g. Activity Timeouts")
                         group_type = c2.text_input("Group Category", value="Custom", placeholder="e.g. CSP, Infrastructure")
                         
                         if st.button("Save to Custom Patterns"):
                             if rule_name and pat:
                                 # Load existing
                                 existing = []
                                 if os.path.exists("custom_patterns.json"):
                                     with open("custom_patterns.json", "r") as f:
                                         try:
                                             existing = json.load(f)
                                         except: pass
                                 
                                 # Append
                                 new_rule = {
                                     "name": rule_name,
                                     "pattern": pat,
                                     "group_type": group_type if group_type else "Custom"
                                 }
                                 existing.append(new_rule)
                                 
                                 with open("custom_patterns.json", "w") as f:
                                     json.dump(existing, f, indent=2)
                                     
                                 st.success(f"Rule '{rule_name}' saved! It will be applied on next ingestion run.")
                                 del st.session_state.generated_pattern # Reset
                             else:
                                 st.warning("Please provide both Rule Name and Pattern.")
            
            # 4. Automation: Run Grouper
            st.divider()
            st.subheader("4. Apply Changes")
            st.markdown("Run the grouping logic now to apply your new rules to existing logs.")
            
            if st.button("🚀 Apply Rules Now (Run Grouper)", type="primary"):
                with st.spinner("Running Grouping Logic... This may take a minute."):
                    try:
                        import subprocess
                        # Run the script and capture output
                        result = subprocess.run(
                            ["python", "log_grouper.py"], 
                            capture_output=True, 
                            text=True, 
                            cwd=os.getcwd()
                        )
                        
                        if result.returncode == 0:
                            st.success("Grouping Completed Successfully!")
                            with st.expander("View Output Logs"):
                                st.code(result.stdout)
                        else:
                            st.error("Grouping Failed.")
                            with st.expander("View Error Logs"):
                                st.code(result.stderr)
                                st.code(result.stdout)
                                
                    except Exception as e:
                        st.error(f"Failed to execute script: {str(e)}")

            else:
                st.warning("No logs found matching query.")
                        

