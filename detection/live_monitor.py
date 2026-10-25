#!/usr/bin/env python3
"""Emit JSON events for IPv4 TCP SYN packets seen on an interface."""

import argparse
import json
import signal
import subprocess
import sys
from datetime import datetime, timezone

_child = None


def parse_tcpdump_line(line):
    """Parse one tcpdump `-tt -nn` IPv4 TCP line, or return None."""
    parts = line.split()
    # Typical format:
    # 1761372568.060447 IP 10.0.0.1.48060 > 10.0.0.2.5000: Flags [S], ...
    if len(parts) < 5 or parts[1] != "IP" or parts[3] != ">":
        return None
    try:
        packet_time = float(parts[0])
        source, source_port = parts[2].rsplit(".", 1)
        destination, destination_port = parts[4].rstrip(":").rsplit(".", 1)
        source_port = int(source_port)
        destination_port = int(destination_port)
        if not (1 <= source_port <= 65535 and 1 <= destination_port <= 65535):
            return None
    except (ValueError, IndexError):
        return None

    return {
        "timestamp": datetime.fromtimestamp(packet_time, timezone.utc).isoformat(),
        "event": "tcp_syn",
        "src_ip": source,
        "src_port": source_port,
        "dst_ip": destination,
        "dst_port": destination_port,
    }


def _stop_child(_signum=None, _frame=None):
    """Stop tcpdump when the monitor receives SIGINT/SIGTERM."""
    global _child
    if _child is not None and _child.poll() is None:
        _child.terminate()


def main():
    global _child
    parser = argparse.ArgumentParser(
        description="Monitor TCP SYN packets on a lab interface and emit JSONL."
    )
    parser.add_argument("--interface", required=True, help="e.g. h2-eth0")
    args = parser.parse_args()

    command = [
        "tcpdump", "-i", args.interface, "-nn", "-l", "-tt",
        "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
    ]

    try:
        _child = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print("Error: tcpdump is not installed or is not on PATH.", file=sys.stderr)
        return 1

    signal.signal(signal.SIGTERM, _stop_child)
    signal.signal(signal.SIGINT, _stop_child)

    print(json.dumps({
        "event": "monitor_started",
        "interface": args.interface,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), flush=True)

    try:
        assert _child.stdout is not None
        for line in _child.stdout:
            event = parse_tcpdump_line(line)
            if event is not None:
                print(json.dumps(event), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        _stop_child()
        if _child is not None:
            try:
                _child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                _child.kill()
                _child.wait()
            if _child.stdout is not None:
                _child.stdout.close()

    # A clean SIGTERM during runner shutdown is expected. A real tcpdump
    # failure (for example, an invalid interface) must not look like success.
    return 1 if _child is not None and _child.returncode not in (0, -15) else 0


if __name__ == "__main__":
    raise SystemExit(main())
