# Analysis & Diagnosis

This module uses Generative AI to move from "What happened?" (Grouping) to "Why did it happen?" (Diagnosis).

## Script: `Analysis_Diagnosis.py`

This script operates as a background worker. It does not ingest logs; it consumes the *output* of the Grouper.

### Workflow

1.  **Poll for Work**
    *   Queries `pega-analysis-results` in OpenSearch.
    *   Filter: `{"diagnosis.status": "PENDING"}`.
    *   This ensures we only pay for LLM calls on *new* or *unprocessed* error groups.

2.  **Context Assembly**
    *   For each pending group, the script fetches:
        *   The `representative_log` (full JSON).
        *   The `group_signature` (e.g., specific Rule Name).
        *   The `stack_trace` (if available).
    
3.  **LLM Diagnosis**
    *   Constructs a prompt for the AI Agent (OpenAI GPT-4o via LangChain).
    *   **Prompt Strategy**: "You are a Pega Expert. Analyze this stack trace. Identify the Root Cause and suggest a Fix."
    *   **Tools**: The agent has access to tools (via MCP) to search for similar past errors if needed (future state).

4.  **Update & Save**
    *   The LLM's response is parsed into a structured JSON:
        ```json
        {
          "root_cause": "NullPointer in Activity 'CalculateTax'",
          "recommendation": "Check if 'TaxRate' page is initialized before Step 3.",
          "status": "COMPLETED"
        }
        ```
    *   The script updates the document in `pega-analysis-results` with this new information.

## Dependencies

*   **LangChain**: Orchestrates the interaction with OpenAI.
*   **OpenAI API**: The underlying intelligence (GPT-4o).
*   **OpenSearch**: Reads PENDING groups, writes COMPLETED diagnoses.

## Concurrency
*   The script processes groups sequentially by default to avoid rate limits.
*   Future enhancements may add `asyncio` for parallel processing of multiple groups.
