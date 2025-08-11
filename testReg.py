import re

text = "My email is user@example.com"
pattern = r"(\w+)@(\w+\.\w+)"  # Capturing groups for username and domain

match = re.search(pattern, text)

if match:
    print(f"Full match: {match.group(0)}")
    print(f"Username: {match.group(1)}")
    print(f"Domain: {match.group(2)}")
