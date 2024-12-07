import csv
from collections import defaultdict
import re

# Function to parse the log file
def parse_log_file(file_path):
    log_entries = []
    with open(file_path, 'r') as log_file:
        for line in log_file:
            log_entries.append(line.strip())
    return log_entries

# Function to count requests per IP
def count_requests_per_ip(log_entries):
    ip_request_count = defaultdict(int)
    ip_regex = r"(\d+\.\d+\.\d+\.\d+)"
    
    for entry in log_entries:
        ip_match = re.match(ip_regex, entry)
        if ip_match:
            ip_request_count[ip_match.group(1)] += 1

    return sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)

# Function to identify the most frequently accessed endpoint
def most_frequent_endpoint(log_entries):
    endpoint_count = defaultdict(int)
    endpoint_regex = r'"(GET|POST|PUT|DELETE) (\S+) HTTP'
    
    for entry in log_entries:
        match = re.search(endpoint_regex, entry)
        if match:
            endpoint_count[match.group(2)] += 1
    
    most_frequent = max(endpoint_count.items(), key=lambda x: x[1])
    return most_frequent

# Function to detect suspicious activity
def detect_suspicious_activity(log_entries, threshold=10):
    failed_attempts = defaultdict(int)
    failure_regex = r"(\d+\.\d+\.\d+\.\d+) .* \"POST /login HTTP/1.1\" 401"
    
    for entry in log_entries:
        match = re.search(failure_regex, entry)
        if match:
            failed_attempts[match.group(1)] += 1
            
    
    

    flagged_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return flagged_ips

# Function to save results to a CSV
def save_to_csv(results, file_name):
    with open(file_name, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        
        # Write requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in results['requests_per_ip']:
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([results['most_frequent_endpoint'][0], results['most_frequent_endpoint'][1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in results['suspicious_activity'].items():
            writer.writerow([ip, count])

# Main function
def main():
    log_file = './sample.log'
    log_entries = parse_log_file(log_file)
    # print(log_entries)
    
    # Analyze log entries
    requests_per_ip = count_requests_per_ip(log_entries)
    most_frequent = most_frequent_endpoint(log_entries)
    suspicious_activity = detect_suspicious_activity(log_entries)
    
    # Display results
    print("IP Address           Request Count")
    for ip, count in requests_per_ip:
        print(f"{ip:<25}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_frequent[0]} (Accessed {most_frequent[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20}{count}")
    
    # Save results to CSV
    results = {
        "requests_per_ip": requests_per_ip,
        "most_frequent_endpoint": most_frequent,
        "suspicious_activity": suspicious_activity
    }
    save_to_csv(results, 'log_analysis_results.csv')

if __name__ == "__main__":
    main()
