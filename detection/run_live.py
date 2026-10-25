#!/usr/bin/env python3
"""Run live SYN capture and detection as one supervised process.

Run this inside the Mininet host namespace containing the capture interface.
It prints only JSON alerts to stdout; tcpdump diagnostics go to stderr.
"""

import argparse
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MONITOR = ROOT / "detection" / "live_monitor.py"
DETECTOR = ROOT / "detection" / "ids.py"


def stop_process(process, timeout=3):
    """Terminate a child cleanly, escalating only if it does not exit."""
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _handle_stop_signal(signum, _frame):
    # Raising lets Python execute the main try/finally cleanup block.
    raise SystemExit(0 if signum == signal.SIGTERM else 130)


def main():
    parser = argparse.ArgumentParser(
        description="Pipe live TCP SYN capture into the intrusion detector."
    )
    parser.add_argument("--interface", required=True, help="e.g. h2-eth0")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _handle_stop_signal)
    signal.signal(signal.SIGINT, _handle_stop_signal)

    monitor = None
    detector = None
    try:
        monitor = subprocess.Popen(
            [sys.executable, str(MONITOR), "--interface", args.interface],
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        assert monitor.stdout is not None
        detector = subprocess.Popen(
            [sys.executable, "-u", str(DETECTOR)],
            stdin=monitor.stdout,
        )
        # The detector owns the read descriptor now; close this duplicate.
        monitor.stdout.close()

        detector_code = detector.wait()
        monitor_code = monitor.wait()
        if detector_code:
            return detector_code
        # SIGTERM is expected only when this runner is shutting down.
        return 0 if monitor_code in (0, -15) else monitor_code
    finally:
        # Stop capture first: that closes the pipe and lets the detector exit.
        stop_process(monitor)
        stop_process(detector)


if __name__ == "__main__":
    raise SystemExit(main())
