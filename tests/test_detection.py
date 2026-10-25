import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from detection.ids import IntrusionDetector  # noqa: E402
from detection.live_monitor import parse_tcpdump_line  # noqa: E402


def event(ts, *, src="10.0.0.3", dst="10.0.0.2", port=5000, kind="tcp_syn"):
    return {
        "timestamp": ts,
        "event": kind,
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
    }


class DetectorTests(unittest.TestCase):
    def test_live_port_scan_has_source_and_controller_fields(self):
        detector = IntrusionDetector()
        alerts = []
        base = 1_800_000_000.0
        for port in range(5000, 5005):
            alerts.extend(detector.process_event(event(base + (port - 5000) * 0.2, port=port)))
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["type"], "port_scan")
        self.assertEqual(alert["source_ip"], "10.0.0.3")
        self.assertEqual(alert["destination_ip"], "10.0.0.2")
        self.assertEqual(alert["severity"], "high")
        self.assertTrue(alert["reason"])

    def test_live_connection_burst_triggers_on_fifteenth_syn(self):
        detector = IntrusionDetector()
        alerts = []
        base = 1_800_000_000.0
        for i in range(20):
            alerts.extend(detector.process_event(event(base + i * 0.1)))
        burst_alerts = [a for a in alerts if a["type"] == "connection_burst"]
        self.assertEqual(len(burst_alerts), 1)
        self.assertEqual(burst_alerts[0]["connection_count"], 15)
        self.assertEqual(burst_alerts[0]["source_ip"], "10.0.0.3")

    def test_old_events_expire_from_rolling_window(self):
        detector = IntrusionDetector()
        base = 1_800_000_000.0
        alerts = []
        for i in range(15):
            alerts.extend(detector.process_event(event(base + i * 2)))
        self.assertFalse(any(a["type"] == "connection_burst" for a in alerts))

    def test_repeated_incident_can_alert_after_cooldown(self):
        detector = IntrusionDetector()
        base = 1_800_000_000.0
        alerts = []
        for i in range(5):
            alerts.extend(detector.process_event(event(base + i * 0.1, port=5000 + i)))
        self.assertEqual(sum(a["type"] == "port_scan" for a in alerts), 1)
        for i in range(5):
            alerts.extend(detector.process_event(event(base + 12 + i * 0.1, port=6000 + i)))
        self.assertEqual(sum(a["type"] == "port_scan" for a in alerts), 2)

    def test_malformed_and_unrelated_events_are_ignored(self):
        detector = IntrusionDetector()
        self.assertEqual(detector.process_event(None), [])
        self.assertEqual(detector.process_event({"event": "monitor_started"}), [])
        self.assertEqual(detector.process_event(event("not-a-time")), [])

    def test_tcpdump_parser_extracts_ipv4_syn_event(self):
        line = "1761372568.060447 IP 10.0.0.1.48060 > 10.0.0.2.5000: Flags [S], seq 1, win 64240, length 0"
        parsed = parse_tcpdump_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["event"], "tcp_syn")
        self.assertEqual(parsed["src_ip"], "10.0.0.1")
        self.assertEqual(parsed["src_port"], 48060)
        self.assertEqual(parsed["dst_ip"], "10.0.0.2")
        self.assertEqual(parsed["dst_port"], 5000)

    def test_tcpdump_parser_skips_non_packet_output(self):
        self.assertIsNone(parse_tcpdump_line("listening on h2-eth0"))
        self.assertIsNone(parse_tcpdump_line(""))

    def test_existing_offline_logs_still_emit_both_alert_types(self):
        scan = subprocess.run(
            [sys.executable, str(ROOT / "detection/ids.py"), "--input", str(ROOT / "logs/scan.jsonl")],
            text=True, capture_output=True, check=True,
        )
        rate = subprocess.run(
            [sys.executable, str(ROOT / "detection/ids.py"), "--input", str(ROOT / "logs/rate.jsonl")],
            text=True, capture_output=True, check=True,
        )
        scan_alert = json.loads(scan.stdout.strip().splitlines()[-1])
        rate_alert = json.loads(rate.stdout.strip().splitlines()[-1])
        self.assertEqual(scan_alert["type"], "port_scan")
        self.assertEqual(rate_alert["type"], "connection_burst")
        self.assertIn("severity", scan_alert)
        self.assertIn("reason", rate_alert)


class LivePipelineSmokeTest(unittest.TestCase):
    def test_runner_pipes_mocked_tcpdump_packets_into_detector(self):
        """Exercise monitor -> detector -> alert JSON without needing Mininet."""
        import os
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as temp_dir:
            fake_tcpdump = Path(temp_dir) / "tcpdump"
            fake_tcpdump.write_text(
                "#!/usr/bin/env python3\n"
                "import sys, time\n"
                "print('listening on fake0, link-type EN10MB (Ethernet)', file=sys.stderr, flush=True)\n"
                "base = time.time()\n"
                "for i in range(20):\n"
                "    port = 5000 + i if i < 10 else 5000\n"
                "    line = f'{base + i * 0.1:.6f} IP 10.0.0.3.{44000 + i} > 10.0.0.2.{port}: Flags [S], seq 1, win 64240, length 0'\n"
                "    print(line, flush=True)\n",
                encoding="utf-8",
            )
            fake_tcpdump.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = temp_dir + os.pathsep + env.get("PATH", "")
            completed = subprocess.run(
                [sys.executable, str(ROOT / "detection/run_live.py"), "--interface", "fake0"],
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        alerts = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        alert_by_type = {alert["type"]: alert for alert in alerts}
        self.assertIn("port_scan", alert_by_type)
        self.assertIn("connection_burst", alert_by_type)
        for alert in alert_by_type.values():
            self.assertEqual(alert["source_ip"], "10.0.0.3")
            self.assertEqual(alert["destination_ip"], "10.0.0.2")
            self.assertEqual(alert["source_ip_status"], "observed")
            self.assertIn("reason", alert)
            self.assertIn("severity", alert)


if __name__ == "__main__":
    unittest.main()
