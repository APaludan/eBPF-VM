#!/usr/bin/env python3

import json

# Read the JSON file
with open('counts_native.json', 'r') as f:
    data = json.load(f)

# Sum all values
total = sum(item['value'] for item in data)

# Print results
print("Native:")
print(f"Total sum: {total}")
print(f"Number of entries: {len(data)}\n")



# Read the JSON file
with open('counts_proton.json', 'r') as f:
    data = json.load(f)

# Sum all values
total = sum(item['value'] for item in data)

# Print results
print("Proton:")
print(f"Total sum: {total}")
print(f"Number of entries: {len(data)}")