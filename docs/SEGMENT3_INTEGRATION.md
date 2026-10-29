# Segment 2 → Segment 3 Integration Contract

Segment 2 emits newline-delimited JSON alerts. Segment 3 expects one alert per HTTP POST to `/ids/alert`.

Required:
- `type`: `port_scan` or `connection_burst`
- `source_ip`: valid IPv4 address

Optional:
- `destination_ip`
- `severity`: `low`, `medium`, `high`, or `critical`
- `reason`
- `timestamp`

Example:
```json
{
  "type": "port_scan",
  "severity": "high",
  "source_ip": "10.0.0.3",
  "destination_ip": "10.0.0.2",
  "reason": "5 distinct destination ports in 10 seconds",
  "timestamp": "2026-10-25T12:00:00Z"
}
```

The controller installs a temporary IPv4 source drop flow with priority 50000 and a 60-second hard timeout. The block is installed on every connected switch. An HTTP 200 response confirms the controller accepted the alert and sent flow-mod messages; it does not itself prove the switch applied the rule. Verify using Mininet traffic and OpenFlow flow-table inspection.
