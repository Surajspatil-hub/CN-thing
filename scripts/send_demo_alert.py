#!/usr/bin/env python3
"""Send one harmless sample IDS alert to a local Ryu response endpoint."""
import json
import urllib.request

payload = {
    "type": "port_scan",
    "severity": "high",
    "source_ip": "10.0.0.3",
    "destination_ip": "10.0.0.2",
    "reason": "Demo alert only; no scan traffic is generated",
    "timestamp": "2026-10-25T12:00:00Z",
}
request = urllib.request.Request(
    "http://127.0.0.1:8080/ids/alert",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=5) as response:
    print(response.status, response.read().decode("utf-8"))
