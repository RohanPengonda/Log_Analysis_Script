from collections import Counter
import csv
# Reading and Accessing data from data.log file
with open("data.log", "r") as file:
    log_data = file.readlines()

#Task 1:
# 1. Count Requests per IP Address:
# Parse the provided log file to extract all IP addresses.
# Calculate the number of requests made by each IP address.
# Sort and display the results in descending order of request counts.
# Example output:
# IP Address           Request Count
# 192.168.1.1          234
# 203.0.113.5          187
# 10.0.0.2             92

ips = [line.split()[0] for line in log_data]
ip_counts = Counter(ips)
sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

#Task 1 Result
print("IP Address | Request Count")
print("--------------------------")
for ip, count in sorted_ip_counts:
    print(f"{ip:<14} | {count}")

#  Task 2:
# 2. Identify the Most Frequently Accessed Endpoint:
# Extract the endpoints (e.g., URLs or resource paths) from the log file.
# Identify the endpoint accessed the highest number of times.
# Provide the endpoint name and its access count.
# Example output:
# Most Frequently Accessed Endpoint:
# /home (Accessed 403 times)

endpoints = [line.split()[6] for line in log_data]
endpoint_counts = Counter(endpoints)
most_accessed_endpoint, access_count = max(endpoint_counts.items(), key=lambda x: x[1])

#Task 2 Result
print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {access_count} times)")

# Task 3:
# 3. Detect Suspicious Activity:
# Identify potential brute force login attempts by:
# Searching for log entries with failed login attempts (e.g., HTTP status code 401 or a specific failure message like "Invalid credentials").
# Flagging IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
# Display the flagged IP addresses and their failed login counts.
# Example output:
# Suspicious Activity Detected:
# IP Address           Failed Login Attempts
# 192.168.1.100        56
# 203.0.113.34         12

FAILED_LOGIN_THRESHOLD = 10
failed_logins = [
    line.split()[0] for line in log_data
    if '401' in line or "Invalid credentials" in line
]
failed_login_counts = Counter(failed_logins)
suspicious_ips = {ip: count for ip, count in failed_login_counts.items() if count > FAILED_LOGIN_THRESHOLD}

# Task 3 Result
if suspicious_ips:
    print()
    print("Suspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    print("------------------------------------------")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
else:
    print("No suspicious activity detected.")


#Task 4
# 4. **Output Results**:
#     - Display the results in a clear, organized format in the terminal.
#     - Save the results to a CSV file named `log_analysis_results.csv` with the following structure:
#         - **Requests per IP**: Columns: `IP Address`, `Request Count`
#         - **Most Accessed Endpoint**: Columns: `Endpoint`, `Access Count`
#         - **Suspicious Activity**: Columns: `IP Address`, `Failed Login Count`

# Create and Save results to CSV File
with open("results.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    # Task 1 Results Added
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    for ip, count in ip_counts.items():
        writer.writerow([ip, count])

    writer.writerow([])  # Blank line

    # Task 2 Results Added
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint, access_count])

    writer.writerow([])  # Blank line

    # Task 3 Results Added
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_ips.items():
        writer.writerow([ip, count])

#Task 4 Completed
print("\nResults saved to 'results.csv'.")