### Regex for IPv6
```
A correct regex for matching basic IPv6 addresses would look like this:

\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b

Explanation:
\b: Word boundary to ensure the match is isolated.
(?: ... ): Non-capturing group to group repeated parts.
[0-9a-fA-F]{1,4}: Matches 1 to 4 hexadecimal characters (0–9, a–f, A–F).
:: Matches the colon separator between groups.
{7}: Ensures exactly 7 repetitions for the first 7 groups.
[0-9a-fA-F]{1,4}: Matches the final group after the 7 colons.
```

### Regex for IPv4
```
\b(?:\d{1,3}\.){3}\d{1,3}\b

Explanation:
\b: Ensures the match is a standalone word, preventing partial matches.
(?: ... ): Creates a non-capturing group to repeat the content inside.
\d{1,3}: Matches 1 to 3 digits (each octet in an IPv4 address).
\.: Matches the period (.) between octets. Escaped because . is a special character in regex.
{3}: Ensures the group (digits followed by a period) is repeated exactly three times.
\d{1,3}: Matches the final octet without a trailing period.
```

### Extract IP address from a file
```
import re

def extract_ip_addresses(log_file_path):
    # Regular expression pattern for matching IPv4 addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    ip_addresses = set()  # Use a set to avoid duplicate IPs

    with open(log_file_path, 'r') as file:
        for line in file:
            matches = ip_pattern.findall(line)
            ip_addresses.update(matches)

    return ip_addresses

if __name__ == "__main__":
    log_file_path = 'path/to/your/logfile.log'  # Replace with your log file path
    ip_addresses = extract_ip_addresses(log_file_path)

    print("Extracted IP Addresses:")
    for ip in ip_addresses:
        print(ip)
```

### Extract JSON row 1 and row 4
```
import json

def extract_rows(json_file_path):
    with open(json_file_path, 'r') as file:
        data = json.load(file)  # Load the JSON data

    # Check if data is a list and has enough elements
    if isinstance(data, list) and len(data) >= 4:
        output = [data[0], data[3]]  # Get the first and fourth entries
    else:
        output = []  # If there are not enough rows, return an empty list

    return output

if __name__ == "__main__":
    json_file_path = 'path/to/your/data.json'  # Replace with your JSON file path
    result = extract_rows(json_file_path)

    print("Extracted Rows:")
    for entry in result:
        print(entry)
```

### Manually Ping IP addresses
```
import subprocess
import platform

def ping_ip(ip):
    # Determine the ping command based on the operating system
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    
    try:
        # Execute the ping command
        subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except Exception:
        return False

def scan_network(ip_list):
    reachable_ips = []

    for ip in ip_list:
        if ping_ip(ip):
            reachable_ips.append(ip)

    return reachable_ips

if __name__ == "__main__":
    # Replace with your list of IP addresses to scan
    ip_addresses = [
        '192.168.1.1',
        '192.168.1.2',
        '192.168.1.3',
        # Add more IPs as needed
    ]

    print("Scanning network...")
    reachable = scan_network(ip_addresses)

    print("Reachable IPs:")
    for ip in reachable:
        print(ip)
```

### Convert CSV to JSON
```
import csv
import json

def csv_to_json(csv_file_path, json_file_path):
    # Read the CSV file
    with open(csv_file_path, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)  # Use DictReader to get rows as dictionaries
        log_entries = [row for row in csv_reader]  # Convert to a list of dictionaries

    # Write the JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(log_entries, json_file, indent=4)  # Pretty print with an indent of 4

if __name__ == "__main__":
    csv_file_path = 'path/to/your/logs.csv'  # Replace with your CSV file path
    json_file_path = 'path/to/your/logs.json'  # Replace with desired JSON output path
    csv_to_json(csv_file_path, json_file_path)
    print(f"Converted {csv_file_path} to {json_file_path}")
```

### Remove Special Chars
```
import re

def remove_special_characters(input_string):
    return re.sub(r'[^a-zA-Z0-9\s]', '', input_string)
```

### Requests Library
```
import requests

# Define the URL and condition
url = "http://example.com"  # Replace with your host URL
expected_content = "desired content"  # Replace with the text you're looking for

try:
    # Send GET request
    response = requests.get(url, timeout=10)
    
    # Check the response content
    if expected_content in response.text:
        print("Response contains the desired content:")
        print(response.text)
    else:
        print("Desired content not found in the response.")

except requests.RequestException as e:
    print(f"An error occurred: {e}")

```