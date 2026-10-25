#!/usr/bin/env python3
"""Detect TCP port scans and connection bursts from newline-delimited JSON."""

import argparse
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone

WINDOW_SECONDS = 10
PORT_SCAN_THRESHOLD = 5
CONNECTION_BURST_THRESHOLD = 15
ALERT_COOLDOWN_SECONDS = WINDOW_SECONDS


def parse_timestamp(value):
    """Return a Unix timestamp for an ISO-8601 string or numeric timestamp."""
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class IntrusionDetector:
    """Small rolling-window detector suitable for live and offline JSONL input."""

    def __init__(self):
        self.port_events = defaultdict(deque)
        self.connection_events = defaultdict(deque)
        # Suppress repeat alerts during the cooldown, but allow later incidents.
        self.last_alerted = {}

    def _may_alert(self, alert_key, event_timestamp):
        last = self.last_alerted.get(alert_key)
        if last is not None and event_timestamp - last < ALERT_COOLDOWN_SECONDS:
            return False
        self.last_alerted[alert_key] = event_timestamp
        return True

    def process_event(self, event):
        """Process one event dict and return zero or more structured alerts."""
        if not isinstance(event, dict):
            return []

        event_type = event.get("event")
        if event_type not in {"tcp_syn", "tcp_probe", "tcp_connection"}:
            return []

        destination = event.get("dst_ip") or event.get("destination")
        source = event.get("src_ip")
        port = event.get("dst_port", event.get("port"))
        timestamp = parse_timestamp(event.get("timestamp"))

        if not destination or port is None or timestamp is None:
            return []
        try:
            port = int(port)
        except (ValueError, TypeError):
            return []
        if not 1 <= port <= 65535:
            return []

        # Live SYN packets must be attributable to a real source IP.
        if event_type == "tcp_syn" and not source:
            return []

        alerts = []
        key = (source or "unknown", destination)

        # Port-scan detection: distinct destination ports from one source.
        if event_type in {"tcp_syn", "tcp_probe"}:
            history = self.port_events[key]
            history.append((timestamp, port))
            while history and timestamp - history[0][0] > WINDOW_SECONDS:
                history.popleft()

            distinct_ports = {observed_port for _, observed_port in history}
            alert_key = ("port_scan", key)
            if (
                len(distinct_ports) >= PORT_SCAN_THRESHOLD
                and self._may_alert(alert_key, timestamp)
            ):
                alerts.append({
                    "type": "port_scan",
                    "reason": "Five or more distinct TCP destination ports were probed within the detection window.",
                    "severity": "high",
                    "source_ip": source,
                    "destination_ip": destination,
                    "distinct_ports": len(distinct_ports),
                    "window_seconds": WINDOW_SECONDS,
                    "timestamp": utc_now(),
                    "source_ip_status": "observed" if source else "unavailable_in_log",
                })

        # Connection-burst detection: TCP SYNs/attempts in the rolling window.
        if event_type in {"tcp_syn", "tcp_connection"}:
            history = self.connection_events[key]
            history.append(timestamp)
            while history and timestamp - history[0] > WINDOW_SECONDS:
                history.popleft()

            alert_key = ("connection_burst", key)
            if (
                len(history) >= CONNECTION_BURST_THRESHOLD
                and self._may_alert(alert_key, timestamp)
            ):
                alerts.append({
                    "type": "connection_burst",
                    "reason": "Fifteen or more TCP connection attempts were observed within the detection window.",
                    "severity": "high",
                    "source_ip": source,
                    "destination_ip": destination,
                    "connection_count": len(history),
                    "window_seconds": WINDOW_SECONDS,
                    "timestamp": utc_now(),
                    "source_ip_status": "observed" if source else "unavailable_in_log",
                })

        return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Detect suspicious TCP events from JSONL input."
    )
    parser.add_argument(
        "--input",
        help="Read JSONL events from a file; omit to read stdin.",
    )
    args = parser.parse_args()

    detector = IntrusionDetector()
    stream = open(args.input, encoding="utf-8") if args.input else sys.stdin
    try:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            for alert in detector.process_event(event):
                print(json.dumps(alert), flush=True)
    finally:
        if args.input:
            stream.close()


if __name__ == "__main__":
    main()
