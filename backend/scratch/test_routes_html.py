import urllib.request
import re

routes = [
    "/console",
    "/console/incidents",
    "/console/traffic",
    "/console/detectors",
    "/console/system",
]

print("=== CHECKING CONSOLE ROUTES ===")
for r in routes:
    url = f"http://localhost:8080{r}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            html = resp.read().decode("utf-8")
            print(f"[PASS] {r:<20} HTTP {resp.status} (Length: {len(html)})")
    except Exception as e:
        print(f"[FAIL] {r:<20} Error: {e}")
