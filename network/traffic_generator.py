
#!/usr/bin/env python3
"""Generate controlled TCP test traffic inside the SDN lab."""

import argparse
import json
import socket
import time
from datetime import datetime, timezone


def log_event(event, **details):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }
    print(json.dumps(record), flush=True)


def normal_test(host, port):
    """Make one normal TCP connection to the lab server."""
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.sendall(b"SDN lab normal test\n")
            log_event(
                "tcp_connection",
                scenario="normal",
                destination=host,
                port=port,
                result="connected",
            )
    except OSError as exc:
        log_event(
            "tcp_connection",
            scenario="normal",
            destination=host,
            port=port,
            result="failed",
            error=str(exc),
        )


def scan_test(host, ports, delay):
    """Test a limited list of ports on the lab server."""
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                result = "open"
        except OSError:
            result = "closed_or_filtered"

        log_event(
            "tcp_probe",
            scenario="controlled_scan",
            destination=host,
            port=port,
            result=result,
        )
        time.sleep(delay)


def rate_test(host, port, count, delay):
    """Generate a bounded burst of TCP connection attempts."""
    for attempt in range(1, count + 1):
        try:
            with socket.create_connection((host, port), timeout=1):
                result = "connected"
        except OSError:
            result = "failed"

        log_event(
            "tcp_connection",
            scenario="connection_rate_test",
            destination=host,
            port=port,
            attempt=attempt,
            result=result,
        )
        time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(
        description="Controlled TCP traffic generator for the local SDN lab"
    )
    parser.add_argument(
        "scenario",
        choices=["normal", "scan", "rate"],
    )
    parser.add_argument("--host", default="10.0.0.2")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    # Keep scanning limited to the intended lab destination.
    if args.host not in {"10.0.0.1", "10.0.0.2", "10.0.0.3"}:
        parser.error("--host must be one of the configured lab IPs")

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    if args.scenario == "normal":
        normal_test(args.host, args.port)
    elif args.scenario == "scan":
        scan_test(args.host, range(5000, 5010), 0.2)
    else:
        rate_test(args.host, args.port, count=20, delay=0.1)


if __name__ == "__main__":
    main()
