# Segment 2 — Live TCP Intrusion Detection for Mininet

This package contains the Segment 2 implementation: a three-host Mininet lab, controlled TCP traffic generator, TCP SYN packet monitor, rolling-window intrusion detector, automated live acceptance test, and offline unit tests.

**Scope boundary:** this segment detects suspicious traffic and emits structured JSON alerts. It does not install OpenFlow rules or block hosts; those are Segment 3 responsibilities.

## Lab topology

| Host | Address | Purpose |
|---|---|---|
| `h1` | `10.0.0.1/24` | Normal client |
| `h2` | `10.0.0.2/24` | Monitored server / detector |
| `h3` | `10.0.0.3/24` | Security-test client |
| `s1` | Open vSwitch | Connects the hosts |

The included connectivity topology uses standalone switching (`failMode="standalone"`). This makes the detection lab reachable without a controller; controller-driven forwarding and active blocking must be integrated with Segment 3.

## Files

- `network/topology.py` — interactive Mininet topology.
- `network/traffic_generator.py` — bounded `normal`, `scan`, and `rate` TCP scenarios; emits JSONL generator results.
- `network/lab_server.py` — minimal threaded TCP sink for repeatable tests on `h2:5000` (does not expose a directory listing).
- `detection/live_monitor.py` — captures IPv4 TCP SYN packets using `tcpdump` and emits JSONL events containing the observed source/destination IPs and ports.
- `detection/ids.py` — detects port scans and connection bursts in a rolling 10-second window.
- `detection/run_live.py` — supervised live pipeline from packet capture into the detector; stopping the runner also stops its children.
- `scripts/run_mininet_acceptance.py` — one-command end-to-end live acceptance test; owns and cleans up its Mininet network and child processes.
- `tests/test_detection.py` — unit, parser, and offline regression tests.
- `logs/*.jsonl` — example generator logs for offline tests. Offline logs may not have source IPs; live packet capture is the source of truth for attribution.
- `docs/SEGMENT2_REPORT.md` — implementation notes and verification matrix.
- `docs/SEGMENT3_INTEGRATION.md` — JSON alert interface and controller integration contract.

## Requirements

Run on Ubuntu/WSL with system packages installed:

- Mininet and Open vSwitch
- `tcpdump`
- Python 3 (standard library only for the Python code)

Start Mininet with **system Python**, because a normal project virtual environment often cannot import the system Mininet package.

## Recommended: run the complete live acceptance test

From this project directory, use one command in a normal Ubuntu terminal:

```bash
sudo /usr/bin/python3 scripts/run_mininet_acceptance.py
```

The script automatically:

1. creates the three-host topology and checks `pingall`;
2. starts a minimal TCP service on `h2:5000`;
3. starts capture and detection together inside `h2`'s network namespace;
4. generates normal traffic, a controlled 10-port scan, and 20 bounded connection attempts from `h3`;
5. checks for both `port_scan` and `connection_burst` alerts with the expected observed endpoints;
6. stops its processes and the Mininet network; and
7. saves traffic logs, detector alerts, and monitor diagnostics under `reports/live_acceptance/`.

A successful run ends with `SEGMENT 2 LIVE ACCEPTANCE: PASS`. If a requirement fails, the script prints a concrete reason and keeps the diagnostic files under `reports/live_acceptance/` for inspection. This acceptance script checks detection and alert formatting, **not** SDN blocking.

## Offline tests (do not require root, Mininet, or tcpdump)

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile detection/ids.py detection/live_monitor.py detection/run_live.py network/topology.py network/traffic_generator.py network/lab_server.py scripts/run_mininet_acceptance.py
```

Expected: all nine unit/regression tests pass and the syntax command exits without errors. The offline tests validate detector logic and packet-line parsing; only the live acceptance command verifies the monitor on the actual Mininet interface.

## Manual mode (optional)

Start the interactive topology:

```bash
sudo /usr/bin/python3 network/topology.py
```

Then use the Mininet prompt to run `pingall` and inspect the hosts with `nodes`. For the full live test, prefer the automated acceptance script above; it avoids fragile chained shell commands and owns cleanup.

## Detection rules

- **Port scan:** at least 5 distinct TCP destination ports from the same observed source to the same destination in 10 seconds.
- **Connection burst:** at least 15 TCP SYN/connection attempts from the same source to the same destination in 10 seconds.
- Repeat alerts for the same source/destination/type are throttled for 10 seconds, then may fire again for a later incident.

Alerts are one JSON object per line. They include `type`, `reason`, `severity`, `timestamp`, `source_ip`, `destination_ip`, `source_ip_status`, `window_seconds`, and the type-specific evidence (`distinct_ports` or `connection_count`).

## Limitations

- Live capture requires `tcpdump` and must run in the network namespace containing the interface being monitored.
- Thresholds are fixed for this project version.
- Do not describe connection-burst detection as live-verified until `scripts/run_mininet_acceptance.py` prints its PASS result on the target WSL/Mininet machine.
- This segment produces detections, not enforcement. Dynamic flow rules and verification of traffic blocking/recovery belong to Segment 3.
