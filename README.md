
# SDN Network Intrusion Detection and Response

## Network and Traffic Simulation

This module provides a Mininet topology and controlled TCP traffic
scenarios for testing an SDN intrusion detection system.

## Topology

Three hosts connected to one Open vSwitch:

| Host | IP address | Role |
|---|---|---|
| h1 | 10.0.0.1 | Normal TCP client |
| h2 | 10.0.0.2 | Test server |
| h3 | 10.0.0.3 | Security-test client |

## Files

- `network/topology.py`: Creates the Mininet topology.
- `network/traffic_generator.py`: Generates controlled TCP test traffic.
- `logs/normal.jsonl`: Normal connection test results.
- `logs/scan.jsonl`: Port-scan test results.
- `logs/rate.jsonl`: Connection-rate test results.

## Requirements

- Ubuntu
- Mininet
- Open vSwitch
- Python 3

## Start the topology

From the project root:

```bash
sudo python3 network/topology.py
```

## Test connectivity

At the `mininet>` prompt:

```text
pingall
```

Expected result: `0% dropped`.

## Traffic scenarios

Start a TCP server on h2:

```text
h2 python3 -m http.server 5000 &
```

Run a normal connection test:

```text
h1 python3 /home/victus/sdn-intrusion-detection/network/traffic_generator.py normal
```

Run a controlled port scan:

```text
h3 python3 /home/victus/sdn-intrusion-detection/network/traffic_generator.py scan
```

Run a bounded connection-rate test:

```text
h3 python3 /home/victus/sdn-intrusion-detection/network/traffic_generator.py rate
```

Exit Mininet:

```text
exit
```

## Integration contract

- Network hosts use the IP addresses listed above.
- The traffic generator writes JSON events to standard output.
- Detection must observe actual network traffic or receive events from
  a live collector. Generator logs alone do not establish live detection.
- The detection module should emit structured alerts containing the
  source IP, reason, severity, and timestamp.

## Limitations

The initial topology uses standalone switching for connectivity tests.
Controller-driven forwarding and dynamic blocking must be integrated
and verified separately.
