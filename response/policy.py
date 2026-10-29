"""Dependency-free validation helpers for the IDS response policy."""
import ipaddress

SUPPORTED_ALERTS = {"port_scan", "connection_burst"}

def validate_alert(payload):
    """Return normalized alert data or raise ValueError."""
    if not isinstance(payload, dict):
        raise ValueError("JSON body must be an object")
    alert_type = payload.get("type")
    if alert_type not in SUPPORTED_ALERTS:
        raise ValueError("unsupported alert type")
    source = payload.get("source_ip")
    try:
        source = str(ipaddress.IPv4Address(source))
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError("source_ip must be a valid IPv4 address")
    severity = str(payload.get("severity", "high")).lower()
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "high"
    return {
        "type": alert_type,
        "source_ip": source,
        "destination_ip": payload.get("destination_ip"),
        "severity": severity,
        "reason": str(payload.get("reason", ""))[:500],
        "timestamp": payload.get("timestamp"),
    }
