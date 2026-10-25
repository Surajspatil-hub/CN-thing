#!/usr/bin/env python3
"""Run one automated live acceptance test of Segment 2 inside Mininet.

Run from the project root using system Python with root permissions:
    sudo /usr/bin/python3 scripts/run_mininet_acceptance.py

This script owns the Mininet network and all lab processes, so the user does
not need a second terminal, shell pipelines, or manual background-process cleanup.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY_SERVER = ROOT / "network" / "lab_server.py"
TRAFFIC_GENERATOR = ROOT / "network" / "traffic_generator.py"
LIVE_RUNNER = ROOT / "detection" / "run_live.py"
EVIDENCE_DIR = ROOT / "reports" / "live_acceptance"
SOURCE_IP = "10.0.0.3"
DESTINATION_IP = "10.0.0.2"
MONITOR_READY_TIMEOUT = 8.0
ALERT_TIMEOUT = 5.0


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def wait_for_text(path: Path, needle: str, timeout: float, process=None) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and needle in path.read_text(encoding="utf-8", errors="replace"):
            return True
        if process is not None and process.poll() is not None:
            return False
        time.sleep(0.1)
    return path.exists() and needle in path.read_text(encoding="utf-8", errors="replace")


def run_generator(host, scenario: str, output_path: Path, timeout: float = 30.0) -> None:
    command = [
        sys.executable,
        str(TRAFFIC_GENERATOR),
        scenario,
        "--host",
        DESTINATION_IP,
        "--port",
        "5000",
    ]
    with output_path.open("w", encoding="utf-8") as output:
        process = host.popen(command, stdout=output, stderr=subprocess.STDOUT, text=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError(f"traffic generator scenario '{scenario}' timed out")
    if code != 0:
        raise RuntimeError(
            f"traffic generator scenario '{scenario}' exited with code {code}; "
            f"see {output_path}"
        )

    records = read_jsonl(output_path)
    expected_count = {"normal": 1, "scan": 10, "rate": 20}[scenario]
    if len(records) != expected_count:
        raise RuntimeError(
            f"scenario '{scenario}' wrote {len(records)} events; expected {expected_count}. "
            f"See {output_path}"
        )
    if scenario in {"normal", "rate"}:
        failures = [row for row in records if row.get("result") != "connected"]
        if failures:
            raise RuntimeError(
                f"scenario '{scenario}' had {len(failures)} failed connection(s); "
                f"check the lab server. See {output_path}"
            )
    print(f"PASS: {scenario} traffic scenario completed ({len(records)} events; evidence: {output_path})")


def stop_process(process, timeout: float = 3.0) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


def main() -> int:
    if os.geteuid() != 0:
        print(
            "ERROR: Mininet acceptance must run as root. Start it with "
            "sudo /usr/bin/python3 scripts/run_mininet_acceptance.py",
            file=sys.stderr,
        )
        return 2

    # Imported only when live acceptance is requested, so unit tests and
    # static inspection work on machines without Mininet installed.
    try:
        from mininet.link import TCLink
        from mininet.log import setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSSwitch
    except ImportError as exc:
        print(f"ERROR: Mininet is not available to this Python: {exc}", file=sys.stderr)
        return 2

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    for old_file in EVIDENCE_DIR.glob("*"):
        if old_file.is_file():
            old_file.unlink()

    server_log = EVIDENCE_DIR / "server.jsonl"
    monitor_log = EVIDENCE_DIR / "monitor.log"
    alert_log = EVIDENCE_DIR / "alerts.jsonl"
    normal_log = EVIDENCE_DIR / "normal.jsonl"
    scan_log = EVIDENCE_DIR / "scan.jsonl"
    rate_log = EVIDENCE_DIR / "rate.jsonl"

    net = None
    server = None
    runner = None
    server_handle = server_log.open("w", encoding="utf-8")
    monitor_handle = monitor_log.open("w", encoding="utf-8")
    alert_handle = alert_log.open("w", encoding="utf-8")
    failure: str | None = None

    try:
        setLogLevel("warning")
        net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, build=False)
        h1 = net.addHost("h1", ip="10.0.0.1/24")
        h2 = net.addHost("h2", ip="10.0.0.2/24")
        h3 = net.addHost("h3", ip="10.0.0.3/24")
        switch = net.addSwitch("s1", protocols="OpenFlow13", failMode="standalone")
        for host in (h1, h2, h3):
            net.addLink(host, switch)

        print("Starting three-host Mininet topology...")
        net.build()
        net.start()
        loss = net.pingAll()
        if loss not in (0, 0.0):
            raise RuntimeError(f"Mininet connectivity test reported {loss}% packet loss")
        print("PASS: h1, h2, and h3 can reach one another (pingall 0% loss)")

        server = h2.popen(
            [sys.executable, str(TOPOLOGY_SERVER), "--host", DESTINATION_IP, "--port", "5000"],
            stdin=subprocess.DEVNULL,
            stdout=server_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if not wait_for_text(server_log, '"event": "server_started"', 5.0, server):
            raise RuntimeError(f"lab TCP server did not start; see {server_log}")

        runner = h2.popen(
            [sys.executable, str(LIVE_RUNNER), "--interface", "h2-eth0"],
            stdin=subprocess.DEVNULL,
            stdout=alert_handle,
            stderr=monitor_handle,
            text=True,
        )
        if not wait_for_text(monitor_log, "listening on h2-eth0", MONITOR_READY_TIMEOUT, runner):
            tail = monitor_log.read_text(encoding="utf-8", errors="replace") if monitor_log.exists() else ""
            raise RuntimeError(
                "live monitor failed to report readiness on h2-eth0. "
                f"See {monitor_log}. Diagnostic output: {tail[-1500:]}"
            )
        print("PASS: tcpdump is listening on h2-eth0; live detector pipeline started")

        run_generator(h1, "normal", normal_log)
        run_generator(h3, "scan", scan_log)
        run_generator(h3, "rate", rate_log)

        deadline = time.monotonic() + ALERT_TIMEOUT
        alerts = []
        while time.monotonic() < deadline:
            alerts = read_jsonl(alert_log)
            detected_types = {row.get("type") for row in alerts}
            if {"port_scan", "connection_burst"}.issubset(detected_types):
                break
            if runner.poll() is not None:
                break
            time.sleep(0.1)

        alerts = read_jsonl(alert_log)
        by_type = {}
        for alert in alerts:
            by_type.setdefault(alert.get("type"), alert)

        for required_type in ("port_scan", "connection_burst"):
            alert = by_type.get(required_type)
            if not alert:
                raise RuntimeError(
                    f"missing live {required_type} alert. Alert output: {alert_log}; "
                    f"monitor diagnostic: {monitor_log}"
                )
            if alert.get("source_ip") != SOURCE_IP or alert.get("destination_ip") != DESTINATION_IP:
                raise RuntimeError(
                    f"{required_type} alert has wrong endpoints: "
                    f"source={alert.get('source_ip')}, destination={alert.get('destination_ip')}"
                )
            if not alert.get("reason") or not alert.get("severity") or not alert.get("timestamp"):
                raise RuntimeError(f"{required_type} alert is missing required integration fields")
            if alert.get("source_ip_status") != "observed":
                raise RuntimeError(f"{required_type} alert does not mark the source as observed")
            print(
                f"PASS: live {required_type} alert: {SOURCE_IP} -> {DESTINATION_IP} "
                f"(evidence: {alert_log})"
            )

        print("\nSEGMENT 2 LIVE ACCEPTANCE: PASS")
        print(f"Alert JSONL: {alert_log}")
        print(f"Monitor diagnostics: {monitor_log}")
        print(f"Traffic logs: {EVIDENCE_DIR}")
        print("Note: this validates detection and alert formatting, not SDN blocking.")
        return 0

    except Exception as exc:  # Convert failures into a clear, useful acceptance report.
        failure = str(exc)
        print(f"\nSEGMENT 2 LIVE ACCEPTANCE: FAIL\n{failure}", file=sys.stderr)
        print(f"Evidence folder: {EVIDENCE_DIR}", file=sys.stderr)
        if monitor_log.exists():
            content = monitor_log.read_text(encoding="utf-8", errors="replace")
            if content:
                print("\n--- monitor diagnostics ---\n" + content[-3000:], file=sys.stderr)
        if alert_log.exists():
            content = alert_log.read_text(encoding="utf-8", errors="replace")
            if content:
                print("\n--- alerts captured ---\n" + content[-3000:], file=sys.stderr)
        return 1

    finally:
        stop_process(runner)
        stop_process(server)
        if net is not None:
            net.stop()
        alert_handle.close()
        monitor_handle.close()
        server_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
