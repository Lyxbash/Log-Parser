import re
import csv
from collections import defaultdict, Counter

# log file and output CSV file
log_file = 'sample.log'
output_csv = 'log_analysis_results.csv'

# threshold for detecting suspicious activity
suspicion_threshold = 10

def log_parser(log_file):

    # parses the log file and extracts relevant information.
    log_data = []
    # regex pattern for matching log entries
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>/\S*) HTTP/\d\.\d" (?P<status>\d+) \d+'
    )
    try:
        with open(log_file, 'r') as file:
            for line in file:
                match = log_pattern.match(line)
                if match:
                    log_data.append(match.groupdict())
    except FileNotFoundError:
        print(f"Error: The file {log_file} was not found.")
    return log_data


def count_requests_per_ip(log_data):

    # counts the number of requests made by each IP address.
    ip_counter = Counter(entry['ip'] for entry in log_data)
    return sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)


def find_most_accessed_endpoint(log_data):

    # endpoint with the highest number of accesses.
    endpoint_counter = Counter(entry['endpoint'] for entry in log_data)
    most_accessed = endpoint_counter.most_common(1)
    return most_accessed[0] if most_accessed else (None, 0)

def detect_suspicious_activity(log_data):

    # detects suspicious activity based on 401 code
    failed_logins = defaultdict(int)
    for entry in log_data:
        if entry['status'] == '401':
            failed_logins[entry['ip']] += 1
    return [(ip, count) for ip, count in failed_logins.items() if count>suspicion_threshold]


def save_results_to_csv(ip_requests, most_accessed, suspicious_ips):

    # Saves analysis results to a CSV file.
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])

        writer.writerows(ip_requests)
        writer.writerow([])

        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])

        writer.writerow(most_accessed)
        writer.writerow([])

        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])

        writer.writerows(suspicious_ips)


def main():
    log_data = log_parser(log_file)

    if not log_data:
        print("No log data found. Exiting.")
        return

    ip_requests = count_requests_per_ip(log_data)
    most_accessed = find_most_accessed_endpoint(log_data)
    suspicious_ips = detect_suspicious_activity(log_data)

    print("Requests per IP:")
    for ip, count in ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips:
        print(f"{ip:<20} {count}")

    # save the results to a csv file
    save_results_to_csv(ip_requests, most_accessed, suspicious_ips)
    print(f"\nResults saved to {output_csv}")

if __name__ == "__main__":
    main()
