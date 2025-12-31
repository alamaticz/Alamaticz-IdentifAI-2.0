"""
Log Normalizer Module
Contains regex logic to normalize error messages by replacing variable parts 
(ids, dates, timestamps, memory addresses) with standard placeholders.
Used for grouping similar log entries.
"""

import re

def normalize_error_pattern(message):
    """
    Normalize error message patterns by replacing variable parts with placeholders.
    This groups similar errors that differ only in values (indices, dates, IDs, etc.).
    
    Args:
        message: Original error message string
        
    Returns:
        Normalized pattern string
    """
    if not message or not isinstance(message, str):
        return message
    
    normalized = message
    
    # Pattern 1: Array/list indices like .agreement(9), .agreement(10) -> .agreement(*)
    # Matches: .fieldName(number) or [number] patterns
    normalized = re.sub(r'\((\d+)\)', r'(*)', normalized)  # (9) -> (*)
    normalized = re.sub(r'\[(\d+)\]', r'[*]', normalized)  # [9] -> [*]
    
    # Pattern 2: Dates and timestamps
    # HTTP date format: Thu, 04 Dec 2025 11:34:44 GMT, Wed, 01 Jan 2025 12:00:00 UTC
    # Format: DayName, DD MMM YYYY HH:MM:SS TZ (RFC 7231 format)
    # Matches: "Thu, 04 Dec 2025 11:34:44 GMT" (with or without "Date: " prefix)
    # This will normalize dates like "Date: Thu, 04 Dec 2025 11:34:44 GMT" -> "Date: [DATE]"
    normalized = re.sub(r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+(?:GMT|UTC|EST|EDT|PST|PDT|[A-Z]{2,4})\b', '[DATE]', normalized)
    # ISO 8601 dates: 2025-04-18T14:23:09, 2025-04-18T14:23:09.123, etc.
    normalized = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', '[DATE]', normalized)
    # Date formats: 2025-04-18, 04/18/2025, etc.
    normalized = re.sub(r'\d{4}-\d{2}-\d{2}', '[DATE]', normalized)
    normalized = re.sub(r'\d{2}/\d{2}/\d{4}', '[DATE]', normalized)
    
    # Pattern 3: UUIDs and GUIDs
    # Format: 123e4567-e89b-12d3-a456-426614174000 or similar
    normalized = re.sub(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '[UUID]', normalized)
    
    # Pattern 3.5: JSON ID values (e.g., Salesforce IDs, API response IDs)
    # Matches: "id":"value" where value is an alphanumeric string (typically 15+ chars)
    # Examples: "id":"a5ZPY000000XXOb2AO", "id":"a5ZPY000000XXZt2AO"
    # This normalizes JSON IDs within JSON objects
    normalized = re.sub(r'"id"\s*:\s*"[A-Za-z0-9]{10,}"', '"id":"[JSON_ID]"', normalized)
    
    # Pattern 4: Case IDs and similar identifiers (e.g., CO-19577, T-12345)
    # Matches: Letters followed by dash and numbers
    normalized = re.sub(r'[A-Z]+-\d+', '[CASE_ID]', normalized)
    
    # Pattern 5: Long numeric IDs (6+ digits) - likely IDs, not counts
    # This is context-dependent, so we're conservative
    normalized = re.sub(r'\b\d{6,}\b', '[ID]', normalized)
    
    # Pattern 6: Email addresses
    normalized = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', normalized)
    
    # Pattern 7: IP addresses
    normalized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', normalized)
    
    # Pattern 8: File paths (Windows and Unix) - be conservative
    # Windows paths: C:\path\to\file
    normalized = re.sub(r'[A-Za-z]:\\[^\s<>"|?*]+', '[FILE_PATH]', normalized)  # Windows
    # Unix paths: /path/to/file (only if it looks like a real path, not just a single slash)
    normalized = re.sub(r'/[^\s<>"|?*]{2,}', '[FILE_PATH]', normalized)  # Unix (min 2 chars after /)
    
    # Pattern 9: URL normalization (preserve structure, normalize variable parts)
    # First, normalize session IDs in URLs (e.g., vp7fekgMMsTk-GvDl9g7Ysh7dqXia2EM*)
    # Matches alphanumeric strings with dashes/underscores, often ending with *
    normalized = re.sub(r'/[A-Za-z0-9_-]{15,}\*/', '/[SESSION_ID]*/', normalized)
    
    # Normalize query parameter values that are hex IDs (like pzHarnessID=HIDCE08144977FF8F248E9AAF845609F6DF)
    # Matches: param=HEXID where HEXID is 20+ hex characters (uppercase and lowercase)
    normalized = re.sub(r'([?&])([a-zA-Z_]+)=[A-Fa-f0-9]{20,}', r'\1\2=[HEX_ID]', normalized)
    
    # Normalize query parameter values that are long alphanumeric IDs (15+ chars, likely session/request IDs)
    # Matches: pzHarnessID=HIDCE08144977FF8F248E9AAF845609F6DF (contains non-hex but is still an ID)
    normalized = re.sub(r'([?&])([a-zA-Z_]+)=[A-Za-z0-9]{15,}', r'\1\2=[LONG_ID]', normalized)
    
    # Normalize query parameter values that are numeric IDs or timestamps (5+ digits)
    # Matches: time=60000, pzPostData=2025865476, etc.
    normalized = re.sub(r'([?&])([a-zA-Z_]+)=\d{5,}', r'\1\2=[NUM_PARAM]', normalized)
    
    # Normalize query parameter values that are encoded strings (like %40baseclass.ShowLogoffTimer)
    # Matches URL-encoded values (may include additional characters after encoded part)
    normalized = re.sub(r'([?&])([a-zA-Z_]+)=%[0-9A-Fa-f]{2,}[^\s&]*', r'\1\2=[ENCODED_PARAM]', normalized)
    
    # Normalize remaining query parameter values that are not common constants
    # Preserves: true, false, 1, 0, yes, no (case-insensitive)
    # Normalizes everything else (variable values like "LogOff", "pzRunActionWrapper", etc.)
    normalized = re.sub(r'([?&])([a-zA-Z_]+)=(?!(?:true|false|1|0|yes|no)(?=[&\s]|$))([A-Za-z0-9_-]+)(?=[&\s]|$)', r'\1\2=[QUERY_VALUE]', normalized)
    
    # For CSP violations and similar errors, normalize entire query strings in URLs to group them together
    # This normalizes query strings in URLs (https://...?params) when they contain normalized values
    # This helps group CSP violations that differ only in query parameters
    # Only match query strings that are part of URLs (preceded by http:// or https://)
    normalized = re.sub(r'(https?://[^\s?]+)\?[^\s]+', r'\1?[QUERY_PARAMS]', normalized)
    
    # Pattern 10: Java object references (memory addresses)
    # Format: ClassName@hexadecimal or [Ljava.lang.StackTraceElement;@2554965d
    # Matches: Any text ending with @ followed by 4+ hexadecimal digits (memory addresses)
    # Examples: "StackTraceElement@2554965d", "[Ljava.lang.StackTraceElement;@25d62fd1"
    # Note: Requires 4+ hex digits to avoid matching email addresses (which have dots after @)
    normalized = re.sub(r'[A-Za-z0-9_$\[\];\.]+@[0-9a-fA-F]{4,}\b', '[OBJECT_REF]', normalized)
    
    # Pattern 11: Hex values (like memory addresses or hashes)
    normalized = re.sub(r'\b0x[0-9a-fA-F]+\b', '[HEX]', normalized)
    
    return normalized
