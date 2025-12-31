# Dashboard & Chat Agent

The Dashboard is the user interface for the entire system, built with **Streamlit**. It provides visualizations of the analysis and a conversational interface to query the data.

## Script: `dashboard.py`

### Pages and Navigation
1.  **Dashboard (Main)**
    *   **Metrics**: Total Errors, Unique Issues, Top Rule Failure, Recent Ingestion.
    *   **Visualizations**:
        *   Log Level Distribution (Pie Chart).
        *   Diagnosis Status (Pie Chart).
        *   Top Error Groups (Horizontal Bar Chart).
        *   Error Trend Over Time (Area Chart).
    *   **Data Table**: Detailed view of error groups with "Expander" for full stack traces.

2.  **Chat Agent**
    *   **Purpose**: Natural language interface to the log data.
    *   **Engine**: LangChain Agent with `AgentType.OPENAI_FUNCTIONS`.
    *   **Streaming**: Implements a custom async event loop to provide real-time token streaming and tool execution logs to the UI.
    *   **Memory**: Persists chat history to `chat_history.json` so conversations survive page refreshes.

3.  **Upload Logs**
    *   Allows users to manually upload small log files via the browser (for quick checks without using the terminal).

## Key Components

### The Chat Agent
*   **Model**: GPT-4o (`chat-gpt-4o`).
*   **Tools**: Connects to the **MCP (Model Context Protocol) Server** to access OpenSearch tools (`SearchIndexTool`, `ListIndicesTool`, etc.).
*   **System Prompt**: Configured to check specific fields (`log.message`, `exception_message`) to ensure accurate retrieval.

### Metrics Calculation
*   **Top Rule Failure**: Explicitly queries for `group_type: "RuleSequence"` to show the most frequent *Pega Rule* error, filtering out generic infrastructure noise.
*   **Last Incident**: Shows the timestamp of the most recent error log.

## Configuration
*   **Theme**: Uses `assets/` for branding (logos).
*   **Asyncio**: Uses `nest_asyncio` to handle Streamlit's event loop compatibility with LangChain's async agents.
