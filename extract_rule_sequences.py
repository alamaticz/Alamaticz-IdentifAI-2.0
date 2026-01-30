"""
Pega Rule Sequence Extractor

This script extracts rule execution sequences from Pega log files.
It processes JSON log files and identifies the sequence of Pega rules
(activities, flows, data transforms, etc.) from error stacktraces.

Usage:
    python extract_rule_sequences.py

Output:
    - Console output showing extracted rule sequences
    - JSON file with detailed extraction results
"""

import sys
import json
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def clean_rule_name(rule_name):
    """
    Clean rule name by removing hash suffixes
    
    Args:
        rule_name: Raw rule name from stacktrace (may include hash)
        
    Returns:
        Cleaned rule name without hash suffix
    """
    # Remove hash suffix pattern: _[32 hex characters] followed by optional suffix (e.g. $1)
    # Example: fetchproviderinfo_71213544b84138fe0e99c30bed26f41e -> fetchproviderinfo
    # Example: processmodupdate_cdt_71138c510b03d4b704c6af6eda7b966f$2$1 -> processmodupdate_cdt
    rule_name = re.sub(r'_[a-f0-9]{32,}.*$', '', rule_name)
    
    # Remove numeric suffix pattern (often found in datatransforms or generated rules)
    # Example: pds_owlm_work_website_processmodupdate_cdt_1024929017 -> pds_owlm_work_website_processmodupdate_cdt
    rule_name = re.sub(r'_\d{10,}$', '', rule_name)
    
    return rule_name


def extract_class_and_name(full_rule_name):
    """
    Extract Class and Rule Name from the full rule string.
    
    Strategy: 
    1. Initial split at the last underscore.
    2. Heuristic: If name is short (<= 4 chars) and class ends with a verb/action,
       shift the split left (e.g., class_processmodupdate_cdt -> class | processmodupdate_cdt).
    3. Validation: Ignore if the 'class' part is in the ignore list.
    
    Args:
        full_rule_name: The cleaned rule name (e.g., "pds_fw_denovo_checklist_settasktime")
        
    Returns:
        tuple: (class_name, rule_name)
        If no valid class found, class_name is "NA" and rule_name is full_rule_name.
    """
    if '_' not in full_rule_name:
        return "NA", full_rule_name
        
    # Initial split at the last underscore
    parts = full_rule_name.rsplit('_', 1)
    class_candidate = parts[0]
    name_candidate = parts[1]
    
    # Heuristic: Rule names with underscores (e.g. processmodupdate_cdt)
    # If the extracted name is short (e.g. cdt, v1, p1) AND the previous token looks like an action/rule
    # then merge them.
    if len(name_candidate) <= 4 and '_' in class_candidate:
        # Check the last token of the class candidate
        class_parts = class_candidate.rsplit('_', 1)
        potential_rule_part = class_parts[1]
        remaining_class = class_parts[0]
        
        # List of common action suffixes/verbs that likely belong to the rule name
        # e.g. processmodupdate ends in "update"
        ACTION_SUFFIXES = (
            'update', 'create', 'delete', 'save', 'process', 'validate', 'check', 
            'load', 'fetch', 'retrieve', 'send', 'calc', 'calculate', 'notify',
            'execute', 'perform', 'run', 'open', 'close', 'add', 'remove', 'get', 'set'
        )
        
        # Check if potential_rule_part ends with an action word
        # or if it is exactly one of the known non-class tokens
        if potential_rule_part.lower().endswith(ACTION_SUFFIXES):
            # Shift the split
            class_candidate = remaining_class
            name_candidate = f"{potential_rule_part}_{name_candidate}"
    
    # Ignore list for common prefixes/non-classes
    # These are often part of the rule name itself (e.g., get_providerinfo)
    IGNORE_CLASSES = {
        'get', 'set', 'py', 'px', 'pz', 'step', 'my', 'test', 'ra', 
        'action', 'stream', 'model', 'do', 'call', 'invoke', 'create', 
        'update', 'delete', 'save', 'validate', 'check', 'na'
    }
    
    if class_candidate.lower() in IGNORE_CLASSES:
        return "NA", full_rule_name
        
    return class_candidate, name_candidate


def extract_rule_sequence(stacktrace_string):
    """
    Extract rule execution sequence from Pega stacktrace
    
    Args:
        stacktrace_string: Java stacktrace string (newline-separated) or pipe-separated from error log
        
    Returns:
        List of tuples: [(rule_type, class_name, rule_name), ...]
    """
    # Handle both pipe-separated and newline-separated stacktraces
    if '|' in stacktrace_string and '\n' not in stacktrace_string:
        # Pipe-separated format (from your sample)
        frames = stacktrace_string.split('|')
    else:
        # Newline-separated Java stacktrace format (from log files)
        frames = stacktrace_string.split('\n')
    
    rules = []
    seen = set()  # To avoid duplicates
    
    for frame in frames:
        frame = frame.strip()
        
        rule_type = None
        cleaned_name = None
        
        # Pattern 1: com.pegarules.generated.{type}.ra_action_{name}.{method}
        match = re.search(r'com\.pegarules\.generated\.(\w+)\.ra_action_(\w+)(?:_[a-f0-9]+)?\.', frame)
        if match:
            rule_type = match.group(1)
            cleaned_name = clean_rule_name(match.group(2))
        
        # Pattern 2: Arrow Notation
        if not rule_type:
            match = re.search(r'com\.pegarules\.generated\.(\w+)->ra_action_(\w+)->', frame)
            if match:
                rule_type = match.group(1)
                cleaned_name = clean_rule_name(match.group(2))
        
        # Pattern 3: Container-Based
        if not rule_type:
            match = re.search(r'com\.pegarules\.generated\.([\w]+)\.ra_[a-z]+_(.+?)\.', frame)
            if match:
                rule_type = match.group(1)
                cleaned_name = clean_rule_name(match.group(2))
                
        # Pattern 4: Generated Classes (NA type)
        if not rule_type:
            match = re.search(r'com\.pegarules\.generated\.([A-Za-z]\w+?)(?:_[0-9_]+)\.', frame)
            if match:
                full_name = match.group(1)
                cleaned_name = re.sub(r'_\d+.*$', '', full_name)
                rule_type = 'NA'
        
        # If a rule was found, process it
        if rule_type and cleaned_name:
            # Extract Class and Short Rule Name
            class_name, short_name = extract_class_and_name(cleaned_name)
            
            # Create unique key based on full components
            key = f"{rule_type}_{class_name}_{short_name}"
            
            if key not in seen:
                rules.append((rule_type, class_name, short_name))
                seen.add(key)
                
    return rules

def extract_rules_list(text):
    """
    Wrapper to extract rules and return them as a list of dictionaries.
    Used by external modules like log_grouper.
    """
    rules = extract_rule_sequence(text)
    return [{'type': r[0], 'class': r[1], 'name': r[2]} for r in rules]


def format_rule_sequence(rules):
    """Format rules as aligned text output"""
    if not rules:
        return ""
    
    # Format: type (class) -> name
    # Find max length for alignment
    max_type_len = max(len(r[0]) for r in rules)
    
    output = []
    for rule_type, class_name, rule_name in rules:
        if class_name != "NA":
            display_str = f"{rule_type.ljust(max_type_len)} ({class_name}) ->   {rule_name}"
        else:
            display_str = f"{rule_type.ljust(max_type_len)}    ->   {rule_name}"
        output.append(display_str)
    
    return "\n".join(output)


def process_log_file(log_file_path):
    """
    Process a single Pega log file and extract rule sequences from errors
    
    Args:
        log_file_path: Path to JSON log file
        
    Returns:
        List of extracted rule sequences with metadata
    """
    results = []
    
    print(f"\nProcessing: {log_file_path.name}")
    
    with open(log_file_path, 'r', encoding='utf-8') as f:
        line_num = 0
        for line in f:
            line_num += 1
            try:
                log_entry = json.loads(line)
                
                # Check if it's an error with exception
                if 'log' in log_entry and isinstance(log_entry['log'], dict):
                    log_data = log_entry['log']
                    
                    # Check for exception with stacktrace
                    if 'exception' in log_data and isinstance(log_data['exception'], dict):
                        exception = log_data['exception']
                        
                        if 'stacktrace' in exception:
                            stacktrace = exception['stacktrace']
                            
                            # Extract rule sequence
                            rules = extract_rule_sequence(stacktrace)
                            
                            if rules:
                                result = {
                                    'file': log_file_path.name,
                                    'line_number': line_num,
                                    'timestamp': log_entry.get('date', log_entry.get('time', '')),
                                    'error_message': log_data.get('message', ''),
                                    'exception_class': exception.get('exception_class', ''),
                                    'exception_message': exception.get('exception_message', ''),
                                    'rule_sequence_formatted': format_rule_sequence(rules),
                                    'rules': [{'type': r[0], 'class': r[1], 'name': r[2]} for r in rules],
                                    'rule_count': len(rules)
                                }
                                results.append(result)
                                
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"  Warning: Error processing line {line_num}: {str(e)}")
                continue
    
    print(f"  Found {len(results)} error(s) with rule sequences")
    return results


def process_logs_directory(logs_dir):
    """
    Process all log files in the logs directory
    
    Args:
        logs_dir: Path to logs directory
        
    Returns:
        Dictionary with all results organized by file
    """
    logs_path = Path(logs_dir)
    
    if not logs_path.exists():
        print(f"Error: Logs directory not found: {logs_dir}")
        return {}
    
    # Find all .log files
    log_files = list(logs_path.glob('*.log'))
    
    if not log_files:
        print(f"No .log files found in {logs_dir}")
        return {}
    
    print(f"Found {len(log_files)} log file(s) to process")
    
    all_results = {}
    total_sequences = 0
    
    for log_file in log_files:
        results = process_log_file(log_file)
        if results:
            all_results[log_file.name] = results
            total_sequences += len(results)
    
    print(f"\n{'='*80}")
    print(f"SUMMARY: Extracted {total_sequences} rule sequence(s) from {len(all_results)} file(s)")
    print(f"{'='*80}")
    
    return all_results


def save_results(results, output_file='rule_sequences_output.json'):
    """Save extraction results to JSON file"""
    output_path = Path(output_file)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_path.absolute()}")


def print_sample_results(results, max_samples=5):
    """Print sample results to console"""
    print(f"\n{'='*80}")
    print("SAMPLE RULE SEQUENCES")
    print(f"{'='*80}\n")
    
    sample_count = 0
    for file_name, file_results in results.items():
        for result in file_results:
            if sample_count >= max_samples:
                break
            
            print(f"File: {result['file']}")
            print(f"Timestamp: {result['timestamp']}")
            print(f"Error: {result['error_message'][:100]}...")
            print(f"Exception: {result['exception_class']}")
            print(f"\nRule Sequence ({result['rule_count']} rules):")
            print(result['rule_sequence_formatted'])
            print(f"\n{'-'*80}\n")
            
            sample_count += 1
        
        if sample_count >= max_samples:
            break
    

    if sample_count == 0:
        print("No rule sequences found in the logs.")


def main():
    """Main execution function"""
    print("="*80)
    print("Pega Rule Sequence Extractor")
    print("="*80)

    # Define logs directory - default to 'logs' or use command line argument
    if len(sys.argv) > 1:
        logs_dir = Path(sys.argv[1])
    else:
        logs_dir = Path(__file__).parent / 'logs'

    print(f"Scanning for logs in: {logs_dir}")

    if not logs_dir.exists():
        print(f"Error: Directory '{logs_dir}' does not exist.")
        return

    # Process all log files
    results = process_logs_directory(logs_dir)

    if results:
        # Save results to JSON
        save_results(results)
        
        # Print sample results
        print_sample_results(results, max_samples=5)
        
        # Print statistics
        print("\nSTATISTICS BY FILE:")
        print("-" * 80)
        for file_name, file_results in results.items():
            print(f"{file_name}: {len(file_results)} error(s) with rule sequences")
            
            # Count unique rule types
            rule_types = defaultdict(int)
            for result in file_results:
                for rule in result['rules']:
                    rule_types[rule['type']] += 1
            
            print(f"  Rule types: {dict(rule_types)}")
        
        print("\n" + "="*80)
        print("Extraction complete! Check 'rule_sequences_output.json' for full results.")
        print("="*80)
    else:
        print("\nNo rule sequences found in any log files.")


if __name__ == "__main__":
    main()
