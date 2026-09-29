"""Block decision policy for the NSM responder (Phase 6). Pure functions, no I/O — tested by testing/response/test_policy.py.

A decision answers: given an alert about one source IP, do we block it, for how long, or why not?

Order of checks (the first match wins):
  1. the address must be a single public IPv4 address           → reject "invalid" / "not public"
  2. it must not be on the never-block list                     → reject "never-block: <reason>"
  3. an analyst release may suppress re-blocking until a time   → reject "suppressed by release until …"
  4. already actively blocked                                   → skip (no new row; Grafana repeats notifications)
  5. the trigger must be enforced                               → observe (recorded, never pushed to the firewall)
  6. caps: active blocks and new blocks per window              → reject "cap: …"
  7. block, TTL = base × 4^(earlier blocks in 30 days), capped at 7 days
"""
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta

HOUR = timedelta(hours=1)

# enforce=False records what would have happened without touching the firewall.
TRIGGERS = {
    # Logged in to Cowrie and ran commands, or hammered it with failed logins: hostile intent on another network.
    "honeypot": {"enforce": True, "base_ttl": 24 * HOUR},
    # Suricata severity 1 against the sensor: exploit attempts and brute force (docs/detection-catalog.md RSP-002).
    "suricata": {"enforce": True, "base_ttl": 6 * HOUR},
    # Port/host scanners: the traffic the sensor exists to observe. Blocking them would blind it, so observe only.
    "scanner": {"enforce": False, "base_ttl": 1 * HOUR},
    # Analyst decision through response/firewall/nsm-response.sh block (TTL given explicitly).
    "manual": {"enforce": True, "base_ttl": 24 * HOUR},
}

REPEAT_WINDOW = timedelta(days=30)
REPEAT_FACTOR = 4
MAX_TTL = timedelta(days=7)
MAX_ACTIVE_BLOCKS = 200
MAX_NEW_BLOCKS_PER_WINDOW = 20
NEW_BLOCK_WINDOW = timedelta(minutes=10)


@dataclass(frozen=True)
class Decision:
    action: str  # block | observe | reject | skip
    reason: str
    expires_at: datetime | None = None


@dataclass(frozen=True)
class History:
    """What the responder knows about the IP and the current block list, loaded from nsm.response_actions."""

    active: bool = False                   # latest block/release row is an unexpired block
    suppressed_until: datetime | None = None  # latest release row carries a future expires_at
    earlier_blocks: int = 0                # blocks for this IP within REPEAT_WINDOW
    active_total: int = 0                  # size of the active block list
    new_blocks_in_window: int = 0          # blocks created within NEW_BLOCK_WINDOW (all IPs)


def parse_networks(lines):
    """Parses never-block lines ("<cidr> <reason…>", '#' comments) into [(network, reason)]."""
    networks = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        cidr, _, reason = line.partition(" ")
        networks.append((ipaddress.ip_network(cidr, strict=True), reason.strip() or "listed"))
    return networks


def ttl_for(trigger, earlier_blocks, requested=None):
    base = requested if requested is not None else TRIGGERS[trigger]["base_ttl"]
    ttl = base * (REPEAT_FACTOR ** max(0, earlier_blocks))
    return min(ttl, MAX_TTL)


# TEST-NET-3, accepted as "public" only by the validation harness (RESPONDER_MODE=test), so synthetic attackers are never real hosts.
TEST_NET = ipaddress.ip_network("203.0.113.0/24")


def decide(ip_text, trigger, now, never_block, history, requested_ttl=None, test_net_ok=False):
    if trigger not in TRIGGERS:
        return Decision("reject", f"unknown trigger {trigger!r}")
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return Decision("reject", "invalid address")
    if ip.version != 4:
        return Decision("reject", "not IPv4 (the sensor has no IPv6 address)")
    if not ip.is_global and not (test_net_ok and ip in TEST_NET):
        return Decision("reject", "not a public address")
    for network, reason in never_block:
        if ip in network:
            return Decision("reject", f"never-block: {reason} ({network})")
    if history.suppressed_until is not None and history.suppressed_until > now:
        return Decision("reject", f"suppressed by an analyst release until {history.suppressed_until:%Y-%m-%d %H:%M} UTC")
    if history.active:
        return Decision("skip", "already blocked")

    expires_at = now + ttl_for(trigger, history.earlier_blocks, requested_ttl)
    if not TRIGGERS[trigger]["enforce"]:
        return Decision("observe", f"trigger {trigger} is observe-only", expires_at)
    if history.active_total >= MAX_ACTIVE_BLOCKS:
        return Decision("reject", f"cap: {MAX_ACTIVE_BLOCKS} active blocks")
    if history.new_blocks_in_window >= MAX_NEW_BLOCKS_PER_WINDOW:
        minutes = int(NEW_BLOCK_WINDOW.total_seconds() // 60)
        return Decision("reject", f"cap: {MAX_NEW_BLOCKS_PER_WINDOW} new blocks per {minutes} min")
    repeat = f", repeat offender ×{REPEAT_FACTOR ** history.earlier_blocks}" if history.earlier_blocks else ""
    return Decision("block", f"{trigger}{repeat}", expires_at)
