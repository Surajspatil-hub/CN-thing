#!/usr/bin/env python3
"""Small, quiet TCP service used only by the controlled Mininet test lab."""

import argparse
import json
import socketserver
from datetime import datetime, timezone


class QuietHandler(socketserver.BaseRequestHandler):
    """Accept and close lab TCP connections so attempts complete quickly."""

    def handle(self):
        # The service does not parse application data. Normal traffic may send
        # a short greeting; reading a little makes that test clean as well.
        self.request.settimeout(0.2)
        try:
            self.request.recv(4096)
        except (TimeoutError, OSError):
            pass


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description="Controlled TCP sink for the Mininet lab")
    parser.add_argument("--host", default="10.0.0.2")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    with ThreadedTCPServer((args.host, args.port), QuietHandler) as server:
        print(json.dumps({
            "event": "server_started",
            "host": args.host,
            "port": args.port,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
