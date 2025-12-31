# Identifai 2.0 - Pega Log Analysis System

This project is an automated AI-driven system for ingesting, analyzing, and diagnosing Pega application logs. It uses OpenSearch for storage and vector search, and LLMs (via LangChain) to identify root causes of errors.

## 🚀 Workflow Guide

Follow these steps to operate the system from end-to-end.

### 1. 📥 Ingestion
**Goal**: Load raw `.log` files into the `pega-logs` OpenSearch index.

**How to Run**:
Use the provided batch script to ingest large log files from the terminal.
```powershell
.\ingest_logs.bat <path_to_your_log_file.log>
```
*   **Script**: `ingest_pega_logs.py`
*   **Output**: Logs are stored in the `pega-logs` index.

---

### 2. 🧩 Grouping
**Goal**: Cluster millions of raw log entries into unique "Error Signatures" to reduce noise and LLM costs.

**How to Run**:
Execute the grouper script to process new logs in `pega-logs`.
```powershell
python log_grouper.py
```
*   **Logic**: Uses a "Waterfall" strategy (Rule Errors -> Logger Patterns -> Unanalyzed).
*   **Output**: Grouped results are stored in the `pega-analysis-results` index.

---

### 3. 🔌 OpenSearch MCP Server
**Goal**: Enable the AI Agent to query OpenSearch for Analysis and Diagnosis.
This is a **Prerequisite** for the Dashboard Chat and Analysis scripts.

**Step 1: Set Credentials**
Ensure your machine's Environment Variables are set for OpenSearch:
*   `OPENSEARCH_URL` (e.g., `https://search-domain.us-east-1.es.amazonaws.com`)
*   `OPENSEARCH_USERNAME`
*   `OPENSEARCH_PASSWORD`

**Step 2: Install Module**
Install the OpenSearch MCP server package:
```powershell
pip install mcp-server-opensearch
```

**Step 3: Run Server**
Start the server in SSE mode (Server-Sent Events):
```powershell
python -m mcp_server_opensearch --transport sse
```
*   **Note**: Keep this terminal window **open**. The Dashboard connects to this running process.

---

### 4. 🧠 Analysis & Diagnosis
**Goal**: Use AI to analyze the grouped errors and determine the root cause.

**How to Run**:
Run the diagnosis workflow to process pending error groups.
```powershell
python Analysis_Diagnosis.py
```
*   **Logic**:
    1.  Fetches `PENDING` groups from `pega-analysis-results`.
    2.  Retrieves representative raw logs and stack traces.
    3.  Uses the MCP Server to query data.
    4.  Updates the index with `root_cause` and `recommendation`.

---

### 5. 📊 Dashboard
**Goal**: Visualize the insights and chat with the Log Analysis Agent.

**How to Run**:
Launch the Streamlit dashboard.
```powershell
streamlit run dashboard.py
```
*   **Features**:
    *   **Overview**: Pie charts of error distribution.
    *   **Top Errors**: Bar chart of widely occurring rule failures.
    *   **Chat Agent**: Real-time Q&A with your logs via the MCP connection.

---

## 📂 Documentation Structure
For detailed explanations of each component, see the `docs/` folder:
- [Ingestion Guide](docs/Ingestion.md) - Details on `ingest_pega_logs.py`.
- [Grouping Logic](docs/Grouping.md) - Deep dive into `log_grouper.py` strategies.
- [Log Normalization](docs/Normalization.md) - Regex patterns for signature generation.
- [Analysis & Diagnosis](docs/Analysis_Diagnosis.md) - How the AI diagnosis agent works.
- [Dashboard Architecture](docs/Dashboard.md) - Structure of the Streamlit app.
