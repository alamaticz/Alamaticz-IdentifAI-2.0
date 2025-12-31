# Log Normalization Logic (`log_normalizer.py`)

The **Log Normalizer** is a critical component that sanitizes log messages before grouping. Its goal is to ensure that logs representing the *same error* but differing in dynamic values (like IDs, dates, or timestamps) result in the **same signature**.

## Why Normalization?
Without normalization, `Error at 10:00` and `Error at 10:01` would be treated as two different errors. With normalization, they both become `Error at [DATE]`.

## Normalization Patterns

The `normalize_error_pattern` function applies the following Regex replacements in order:

1.  **Array/List Indices**
    *   *Match*: `(123)` or `[123]`
    *   *Replace*: `(*)` or `[*]`
    *   *Example*: `.agreement(9)` -> `.agreement(*)`

2.  **Dates & Timestamps**
    *   *Match*: RFC 7231, ISO 8601, `YYYY-MM-DD`, `MM/DD/YYYY`
    *   *Replace*: `[DATE]`
    *   *Example*: `2025-12-31T15:00:00.123Z` -> `[DATE]`

3.  **UUIDs / GUIDs**
    *   *Match*: `8-4-4-4-12` hex characters
    *   *Replace*: `[UUID]`
    *   *Example*: `123e4567-e89b-12d3...` -> `[UUID]`

4.  **JSON IDs**
    *   *Match*: `"id":"..."` with alphanumeric values (10+ chars)
    *   *Replace*: `"id": "[JSON_ID]"`
    *   *Example*: `"id":"a5ZPY000000XX"` -> `"id":"[JSON_ID]"`

5.  **Case IDs**
    *   *Match*: `LETTERS-Numbers`
    *   *Replace*: `[CASE_ID]`
    *   *Example*: `CO-19577` -> `[CASE_ID]`

6.  **Numeric IDs**
    *   *Match*: 6+ distinct digits
    *   *Replace*: `[ID]`

7.  **Email & IP Addresses**
    *   *Match*: Standard Email and IPv4 patterns
    *   *Replace*: `[EMAIL]`, `[IP]`

8.  **File Paths**
    *   *Match*: Windows (`C:\...`) and Unix (`/...`) paths
    *   *Replace*: `[FILE_PATH]`

9.  **URLs & Query Parameters**
    *   *Match*: Session IDs, Hex IDs, Encoded Params in URLs
    *   *Replace*: `[SESSION_ID]`, `[HEX_ID]`, `[QUERY_VALUE]`, `[QUERY_PARAMS]`
    *   *Goal*: To group CSP violations or Web/API errors that differ only by request parameters.

10. **Object References (Memory Addresses)**
    *   *Match*: `ClassName@hex` or `[...;@hex`
    *   *Replace*: `[OBJECT_REF]`
    *   *Example*: `StackTraceElement@2554965d` -> `[OBJECT_REF]`

## Usage
This module is imported by `log_grouper.py` and used to normalize the `log.message` or `exception_message` before hasing it into a signature.

```python
from log_normalizer import normalize_error_pattern

raw = "Error processing case CO-12345 at 2025-01-01"
clean = normalize_error_pattern(raw)
# Result: "Error processing case [CASE_ID] at [DATE]"
```
