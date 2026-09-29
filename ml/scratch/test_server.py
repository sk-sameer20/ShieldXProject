import urllib.request
import json
import sys

endpoints = [
    "http://localhost:8000/health",
    "http://localhost:8000/alerts",
    "http://localhost:8000/stats",
    "http://localhost:8000/traffic"
]

for url in endpoints:
    print(f"--- {url} ---")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            print(json.dumps(data, indent=2))
    except Exception as e:
        print(f"Error: {e}")
