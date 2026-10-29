import unittest
from response.policy import validate_alert


class AlertPolicyTests(unittest.TestCase):
    def test_valid_port_scan(self):
        result = validate_alert({
            "type": "port_scan", "source_ip": "10.0.0.3",
            "severity": "high"
        })
        self.assertEqual(result["source_ip"], "10.0.0.3")
        self.assertEqual(result["type"], "port_scan")

    def test_valid_connection_burst(self):
        result = validate_alert({
            "type": "connection_burst", "source_ip": "192.168.1.8"
        })
        self.assertEqual(result["severity"], "high")

    def test_reject_invalid_ip(self):
        with self.assertRaises(ValueError):
            validate_alert({"type": "port_scan", "source_ip": "bad-ip"})

    def test_reject_unknown_alert_type(self):
        with self.assertRaises(ValueError):
            validate_alert({"type": "malware", "source_ip": "10.0.0.3"})

    def test_reject_ipv6_for_ipv4_rule(self):
        with self.assertRaises(ValueError):
            validate_alert({"type": "port_scan", "source_ip": "2001:db8::1"})


if __name__ == "__main__":
    unittest.main()
