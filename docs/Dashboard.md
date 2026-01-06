# Dashboard & Chat Agent

The Dashboard is the user interface for the entire system, built with **Streamlit**. It provides visualizations of the analysis and a conversational interface to query the data.

## Script: `dashboard.py`

### Authentication
*   **Login Page**: The application is protected by a login screen.
*   **Credentials**: Default `alamaticz` / `Alamaticz#2024`.
*   **Logout**: A red "Logout" button is available in the sidebar to end the session.

### Pages and Navigation
1.  **Dashboard (Main)**
    *   **Metrics**: Total Errors, Unique Issues, Top Rule Failure, Recent Ingestion.
    *   **Visualizations**:
        *   Log Level Distribution (Pie Chart).
        *   Diagnosis Status (Pie Chart).
        *   Top Error Groups (Horizontal Bar Chart).
        *   Error Trend Over Time (Area Chart).
    *   **Data Table**: Detailed view of error groups.
        *   **Columns**: Includes "Last Seen" timestamp, "Diagnosis Status" (Editable), "Count" (Progress Bar), and signatures.
        *   **Interactive**: Users can change the status (e.g., PENDING -> RESOLVED) directly in the table.

    *   **Status**: 🚧 **Work in Progress / Under Maintenance**
    *   **Purpose**: Natural language interface to the log data.
    *   **Engine**: LangChain Agent (Currently disabled/commented out in UI for refactoring).
    *   **Memory**: Persists chat history to `chat_history.json`.

3.  **Upload Logs**
    *   **Purpose**: Web-based upload for smaller log files (supports `.log`, `.json`, `.txt`).
    *   **Features**: Invokes the ingestion logic internally, creating unique session IDs for tracked uploads.

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
