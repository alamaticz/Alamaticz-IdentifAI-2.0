# Log Ingestion Documentation

This module handles the loading of Pega logs into the OpenSearch `pega-logs` index.

## Components

### 1. `ingest_pega_logs.py`
The primary Python script for local ingestion.

*   **Purpose**: Reads a text/log file line-by-line, parses Pega's JSON format (or raw text), and bulk indexes it into OpenSearch.
*   **Key Features**:
    *   **Idempotency**: Generates a deterministic `_id` (MD5 hash of the log content) for each document to prevent duplicate entries if the script is run multiple times.
    *   **Progress Tracking**: Uses `tqdm` to show a progress bar in the terminal.
    *   **Chunking**: Sends logs in batches (`BULK_CHUNK_SIZE`) to optimize network usage.
*   **Usage**:
    ```bash
    python ingest_pega_logs.py <filename>
    ```

### 2. `ingest_logs.bat`
A convenience wrapper for Windows users.

*   **Purpose**: Simplifies the command line execution.
*   **Content**:
    ```bat
    @echo off
    python ingest_pega_logs.py %1
    pause
    ```
*   **Usage**: Drag and drop a file onto this script, or run: `.\ingest_logs.bat data.log`.

### 3. `lambda.py` (Cloud Ingestion)
An AWS Lambda function for automated ingestion from S3.

*   **Trigger**: Fires whenever a new log file is uploaded to a specific S3 bucket.
*   **Process**:
    1.  Downloads the file stream from S3.
    2.  Uses `opensearch-py`'s `streaming_bulk` helper to index data directly to OpenSearch.
    3.  Sends an EventBridge event upon completion (success/failure).
*   **Configuration**: Relies on environment variables (`OPENSEARCH_HOST`, `OPENSEARCH_USER`, etc.).

## Data Schema (`pega-logs`)
Ingested logs are flattened but retain original JSON structure under the `log` object.
Key fields:
- `ingestion_timestamp`: Time of insertion.
- `log.message`: The main log event.
- `log.exception.stack`: Stack trace (if present).
- `log.level`: ERROR, INFO, WARN, etc.
