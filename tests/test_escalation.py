from datetime import datetime, timedelta

from ssh_bfd.detector import Detection, Level
from ssh_bfd.escalation import EscalationEngine
from ssh_bfd.firewall.dryrun import DryRunBackend
from ssh_bfd.reputation import Blacklist, Whitelist

T0 = datetime(2026, 7, 5, 12, 0, 0)
ATTACKER = "45.33.32.156"  # a genuinely public IP


class FakeAlerter:
    def __init__(self):
        self.messages = []

    def notify(self, message):
        self.messages.append(message)


def detection(ip=ATTACKER, level=Level.BLOCK, weighted_count=8.0, users=("root",)):
    return Detection(
        ip=ip,
        level=level,
        weighted_count=weighted_count,
        usernames=frozenset(users),
        first_seen=T0,
        last_seen=T0,
    )


def build_engine(whitelist_entries=None, base=100, mult=2.0, state_path=None):
    return EscalationEngine(
        whitelist=Whitelist(whitelist_entries),
        firewall=DryRunBackend(),
        blacklist=Blacklist(),
        alerter=FakeAlerter(),
        base_block_seconds=base,
        block_multiplier=mult,
        state_path=state_path,
    )


# --- basic actions ---

def test_block_detection_blocks_and_records():
    eng = build_engine()
    eng.handle(detection(), now=T0)
    assert ATTACKER in eng.firewall.list_blocked()
    assert eng.blacklist.times_blocked(ATTACKER) == 1
    assert any("BLOCKED" in m for m in eng.alerter.messages)


def test_whitelisted_ip_is_never_acted_on():
    eng = build_engine(whitelist_entries=[ATTACKER])
    eng.handle(detection(), now=T0)
    assert eng.firewall.list_blocked() == set()
    assert eng.blacklist.times_blocked(ATTACKER) == 0
    assert any("whitelisted" in m for m in eng.alerter.messages)


def test_alert_level_does_not_touch_firewall():
    eng = build_engine()
    eng.handle(detection(level=Level.ALERT, weighted_count=3.0), now=T0)
    assert eng.firewall.list_blocked() == set()
    assert eng.blocked_ips()[ATTACKER]["stage"] == Level.ALERT


def test_rate_limit_sets_expiry():
    eng = build_engine(base=100)
    eng.handle(detection(level=Level.RATE_LIMIT, weighted_count=5.0), now=T0)
    entry = eng.blocked_ips()[ATTACKER]
    assert entry["stage"] == Level.RATE_LIMIT
    assert entry["expires_at"] == T0 + timedelta(seconds=100)


# --- escalation-only ---

def test_repeat_block_at_same_stage_is_noop():
    eng = build_engine()
    eng.handle(detection(), now=T0)                       # BLOCK
    eng.handle(detection(), now=T0 + timedelta(minutes=1))  # BLOCK again
    # record_block must have run only once: the second was suppressed.
    assert eng.blacklist.times_blocked(ATTACKER) == 1


def test_escalation_climbs_stages():
    eng = build_engine()
    eng.handle(detection(level=Level.ALERT, weighted_count=3.0), now=T0)
    eng.handle(detection(level=Level.RATE_LIMIT, weighted_count=5.0), now=T0)
    eng.handle(detection(level=Level.BLOCK, weighted_count=8.0), now=T0)
    assert ATTACKER in eng.firewall.list_blocked()
    assert eng.blocked_ips()[ATTACKER]["stage"] == Level.BLOCK


# --- auto-expiry ---

def test_tick_unblocks_after_expiry():
    eng = build_engine(base=100)
    eng.handle(detection(), now=T0)
    eng.tick(now=T0 + timedelta(seconds=50))   # too soon
    assert ATTACKER in eng.firewall.list_blocked()
    eng.tick(now=T0 + timedelta(seconds=150))  # expired
    assert eng.firewall.list_blocked() == set()
    assert ATTACKER not in eng.blocked_ips()


def test_tick_leaves_alert_entries_alone():
    eng = build_engine()
    eng.handle(detection(level=Level.ALERT, weighted_count=3.0), now=T0)
    eng.tick(now=T0 + timedelta(days=365))  # alerts never expire (no rule to lift)
    assert ATTACKER in eng.blocked_ips()


# --- repeat-offender escalation ---

def test_repeat_offender_duration_doubles():
    eng = build_engine(base=100, mult=2.0)
    eng.handle(detection(), now=T0)                        # 1st block: 100s
    first_expiry = eng.blocked_ips()[ATTACKER]["expires_at"]
    assert first_expiry == T0 + timedelta(seconds=100)

    eng.manual_unblock(ATTACKER)                           # clear the stage
    eng.handle(detection(), now=T0)                        # 2nd block: 100*2 = 200s
    second_expiry = eng.blocked_ips()[ATTACKER]["expires_at"]
    assert second_expiry == T0 + timedelta(seconds=200)


def test_block_duration_is_capped():
    eng = EscalationEngine(
        whitelist=Whitelist(), firewall=DryRunBackend(), blacklist=Blacklist(),
        base_block_seconds=100, block_multiplier=10.0, max_block_seconds=250,
    )
    eng.blacklist.record_block(ATTACKER)  # times_blocked = 1 -> would be 1000s
    eng.handle(detection(), now=T0)
    entry = eng.blocked_ips()[ATTACKER]
    assert entry["expires_at"] == T0 + timedelta(seconds=250)  # capped


# --- manual controls ---

def test_manual_block_and_unblock():
    eng = build_engine()
    eng.manual_block(ATTACKER, now=T0)
    assert ATTACKER in eng.firewall.list_blocked()
    eng.manual_unblock(ATTACKER)
    assert eng.firewall.list_blocked() == set()
    assert ATTACKER not in eng.blocked_ips()


# --- persistence ---

def test_block_state_survives_restart(tmp_path):
    path = str(tmp_path / "blocks.json")
    fw = DryRunBackend()
    eng = EscalationEngine(Whitelist(), fw, Blacklist(),
                           base_block_seconds=100, state_path=path)
    eng.handle(detection(), now=T0)

    # A fresh engine sharing the same firewall and state file.
    eng2 = EscalationEngine(Whitelist(), fw, Blacklist(),
                            base_block_seconds=100, state_path=path)
    assert ATTACKER in eng2.blocked_ips()
    eng2.tick(now=T0 + timedelta(seconds=150))  # expiry still enforced
    assert ATTACKER not in eng2.blocked_ips()
