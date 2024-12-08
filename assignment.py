import re
import csv
from collections import Counter

""" Extracts the IP address, endpoint, and status code from a log entry using regex patterns."""
def parse_log_entry(entry):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    endpoint_pattern = r'"(?:GET|POST|PUT|DELETE) (\/\S*)'
    status_code_pattern = r'" (\d{3})'
    
    """Extract IP, endpoint, and status code from the log line"""
    ip_address = re.search(ip_pattern, entry) 
    endpoint = re.search(endpoint_pattern, entry)
    status_code = re.search(status_code_pattern, entry)
    
    return {
        'ip': ip_address.group() if ip_address else None,
        'endpoint': endpoint.group(1) if endpoint else None,
        'status_code': int(status_code.group(1)) if status_code else None
    }

"""Reads a log file, parses each line, and returns a list of parsed log entries."""
def parse_log_file(file_path):
    log_entries = []
    with open(file_path, 'r') as file:
        for line in file:
            log_entries.append(parse_log_entry(line))  
    return log_entries

"""Counts the number of requests made by each IP address in a list of parsed log entries."""
def count_requests_by_ip(log_entries):
    ip_counter = Counter(entry['ip'] for entry in log_entries if entry['ip'])
    return ip_counter.most_common()

"""Identifies the most frequently accessed endpoint from the log entries."""
def most_frequent_endpoint(log_entries):
    endpoint_counter = Counter(entry['endpoint'] for entry in log_entries if entry['endpoint'])
    return endpoint_counter.most_common(1)[0] if endpoint_counter else (None, 0)

"""Detects IPs with failed login attempts exceeding the specified threshold."""
def detect_suspicious_activity(log_entries, threshold=10):
    failed_attempts = Counter(entry['ip'] for entry in log_entries if entry['status_code'] == 401)
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

# Save the results to a CSV file
def save_results_to_csv(ip_requests, most_common_endpoint, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        #Write IP request counts
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_requests)
        
        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow(most_common_endpoint)
        
        # Write suspicious IPs
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        writer.writerows(suspicious_ips.items())

if __name__ == '__main__':
    """
    Main entry point of the script. Performs log parsing, analysis, and saves results to a CSV file.
    """
    log_file_path = 'sample.log'  # Path to the log file
    output_csv = 'log_analysis_results.csv'  # Output CSV file
    
    # Parse the log file
    log_entries = parse_log_file(log_file_path)
    
    # Perform analysis
    ip_requests = count_requests_by_ip(log_entries) # Count request IP's
    most_common_endpoint = most_frequent_endpoint(log_entries) # Find most accessed endpoint 
    suspicious_ips = detect_suspicious_activity(log_entries) # Detect suspicious IP's
    
    # Display results
    print("IP Address       Request Count")
    for ip, count in ip_requests:
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_common_endpoint[0]} (Accessed {most_common_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")
    
    # Save results to CSV
    save_results_to_csv(ip_requests, most_common_endpoint, suspicious_ips, output_csv)
    print(f"\nResults saved to {output_csv}")
