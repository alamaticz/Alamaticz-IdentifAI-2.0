# Log Grouping & Normalization

This module transforms high-volume raw logs into manageable "Unique Error Groups". It solves the problem of "1 million logs, but only 5 actual bugs".

## Scripts

### 1. `log_grouper.py` (The Engine)
This script connects to OpenSearch, scrolls through `pega-logs`, and groups them into `pega-analysis-results`.

#### The "Waterfall" Logic
We use an exclusive grouping strategy. A log is checked against criteria from top to bottom; once matched, it stops.

1.  **Level 1: Rule Failures (Gold)**
    *   **Trigger**: Log contains `Exception`, `RuleName`, and `RuleType`.
    *   **Fingerprint**: `MD5(Exception_Class | RuleName | RuleType)`
    *   **Meaning**: We know exactly *which* Pega rule failed. This is the highest quality signal.

2.  **Level 2: Logger Patterns (Silver)**
    *   **Trigger**: Log has a `LoggerName` and a `Message`.
    *   **Fingerprint**: `MD5(Normalized_Message | LoggerName)`
    *   **Meaning**: A specific component (Logger) is throwing a specific error message.

3.  **Level 3: Unanalyzed (Bronze)**
    *   **Trigger**: Fallback for anything that doesn't match above.
    *   **Fingerprint**: `MD5(Normalized_Raw_Message)`
    *   **Meaning**: Catch-all for noise or unknown formats.

#### Checkpointing
*   The script saves `last_processed_timestamp` to OpenSearch to avoid re-processing old logs.
*   **LIMIT**: Default batch size is 500 logs per scroll.

### 2. `log_normalizer.py` (The Sanitizer)
This library provides regex patterns to remove dynamic data from log messages, ensuring that "Error at 10:00" and "Error at 10:01" are treated as the **same** error.

*   **Masks**:
    *   Dates/Times -> `<DATE>`
    *   IP Addresses -> `<IP>`
    *   UUIDs/GUIDs -> `<ID>`
    *   Hex Memory Addresses -> `<MEM>`
    *   Numbers -> `<NUM>`

## Output Schema (`pega-analysis-results`)
Each document represents a **Group**, not a single log.

```json
{
  "_id": "md5_hash_of_signature",
  "group_signature": "NullPointer | MyActivity | Activity",
  "count": 1420,  // How many raw logs belong to this group
  "first_seen": "2023-01-01T10:00:00",
  "last_seen": "2023-01-02T15:00:00",
  "example_logs": [ ...list of raw log IDs... ],
  "diagnosis": {
       "status": "PENDING", // Ready for A.I. analysis
       "root_cause": null
  }
}
```
