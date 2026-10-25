# Start here: Segment 2 complete bundle

This ZIP is meant to be overlaid onto the existing `sdn-intrusion-detection` repository. It contains the whole Segment 2 source tree (not Git history and not a virtual environment).

## 1. Replace the project files

Copy this ZIP into the root of `~/sdn-intrusion-detection`, then in Ubuntu/WSL run:

```bash
cd ~/sdn-intrusion-detection
unzip -o sdn-segment2-complete.zip -d .
```

## 2. Verify the code offline

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile detection/ids.py detection/live_monitor.py detection/run_live.py network/topology.py network/traffic_generator.py network/lab_server.py scripts/run_mininet_acceptance.py
```

The unit suite should report `Ran 9 tests` and `OK`.

## 3. Verify Segment 2 live on Mininet

Use a normal Ubuntu shell, not a `mininet>` prompt:

```bash
sudo /usr/bin/python3 scripts/run_mininet_acceptance.py
```

This is the single live acceptance command. It starts and shuts down its own three-host topology, runs all three traffic scenarios, checks for live `port_scan` and `connection_burst` alerts, and saves evidence under `reports/live_acceptance/`.

The live implementation is not considered fully verified on your machine until this command prints:

```text
SEGMENT 2 LIVE ACCEPTANCE: PASS
```

If it fails, the command prints a reason and retains monitor/traffic logs for debugging. Do not run a second topology at the same time.

## What this package includes

- Live SYN packet capture and JSONL intrusion alerts.
- Port-scan and connection-burst rules with 10-second windows.
- Structured alert fields suitable for Segment 3.
- Offline regression tests and a one-command live acceptance harness.
- Documentation and a Segment 3 interface contract.

It intentionally does not include controller-driven blocking; that belongs to Segment 3.
