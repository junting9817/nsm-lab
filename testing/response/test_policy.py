#!/usr/bin/env python3
"""Unit tests for response/webhook/policy.py.   python3 testing/response/test_policy.py"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "response", "webhook"))
import policy  # noqa: E402
from policy import Decision, History, decide, parse_networks  # noqa: E402

NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
NEVER = parse_networks([
    "# comment line",
    "35.235.240.0/20 IAP TCP forwarding",
    "203.0.113.7/32 our own sensor  # trailing comment",   # TEST-NET-3: fixture, not the real address
])
ATTACKER = "45.135.232.10"


class PolicyTest(unittest.TestCase):
    def test_block_with_base_ttl(self):
        d = decide(ATTACKER, "honeypot", NOW, NEVER, History())
        self.assertEqual(d, Decision("block", "honeypot", NOW + timedelta(hours=24)))

    def test_rejects_invalid_private_ipv6_and_unknown_trigger(self):
        for ip, reason in [("not-an-ip", "invalid"), ("10.178.0.2", "not a public"), ("192.0.2.7", "not a public"),
                           ("169.254.169.254", "not a public"), ("2001:4860::1", "not IPv4")]:
            d = decide(ip, "suricata", NOW, NEVER, History())
            self.assertEqual(d.action, "reject", ip)
            self.assertIn(reason, d.reason, ip)
        self.assertEqual(decide(ATTACKER, "bogus", NOW, NEVER, History()).action, "reject")

    def test_never_block_list(self):
        for ip in ("35.235.241.9", "203.0.113.7"):
            # test_net_ok because the fixture uses a TEST-NET-3 address instead of the sensor's real one; without it
            # the policy rejects it as non-public before the never-block list is ever consulted.
            d = decide(ip, "honeypot", NOW, NEVER, History(), test_net_ok=True)
            self.assertEqual(d.action, "reject")
            self.assertTrue(d.reason.startswith("never-block: "), d.reason)

    def test_release_suppresses_and_expires(self):
        h = History(suppressed_until=NOW + timedelta(hours=2))
        self.assertIn("suppressed", decide(ATTACKER, "suricata", NOW, NEVER, h).reason)
        h = History(suppressed_until=NOW - timedelta(seconds=1))
        self.assertEqual(decide(ATTACKER, "suricata", NOW, NEVER, h).action, "block")

    def test_active_is_skipped(self):
        self.assertEqual(decide(ATTACKER, "suricata", NOW, NEVER, History(active=True)).action, "skip")

    def test_observe_only_trigger_never_blocks_even_at_caps(self):
        d = decide(ATTACKER, "scanner", NOW, NEVER, History(active_total=10_000, new_blocks_in_window=10_000))
        self.assertEqual(d.action, "observe")

    def test_repeat_offender_escalation_is_capped(self):
        ttls = [decide(ATTACKER, "suricata", NOW, NEVER, History(earlier_blocks=n)).expires_at - NOW for n in range(4)]
        self.assertEqual(ttls, [timedelta(hours=6), timedelta(hours=24), timedelta(hours=96), timedelta(days=7)])
        self.assertIn("repeat offender ×4", decide(ATTACKER, "suricata", NOW, NEVER, History(earlier_blocks=1)).reason)

    def test_caps(self):
        d = decide(ATTACKER, "honeypot", NOW, NEVER, History(active_total=policy.MAX_ACTIVE_BLOCKS))
        self.assertTrue(d.action == "reject" and "active blocks" in d.reason)
        d = decide(ATTACKER, "honeypot", NOW, NEVER, History(new_blocks_in_window=policy.MAX_NEW_BLOCKS_PER_WINDOW))
        self.assertTrue(d.action == "reject" and "new blocks per 10 min" in d.reason)

    def test_manual_requested_ttl(self):
        d = decide(ATTACKER, "manual", NOW, NEVER, History(), requested_ttl=timedelta(minutes=30))
        self.assertEqual(d.expires_at, NOW + timedelta(minutes=30))

    def test_test_net_only_in_test_mode(self):
        self.assertEqual(decide("203.0.113.9", "suricata", NOW, NEVER, History()).action, "reject")
        self.assertEqual(decide("203.0.113.9", "suricata", NOW, NEVER, History(), test_net_ok=True).action, "block")
        self.assertEqual(decide("198.51.100.9", "suricata", NOW, NEVER, History(), test_net_ok=True).action, "reject")

    def test_never_block_parse_rejects_host_bits(self):
        with self.assertRaises(ValueError):
            parse_networks(["35.235.240.1/20 bad"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
