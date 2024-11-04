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