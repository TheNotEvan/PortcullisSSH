from datetime import datetime, timedelta

from portcullis.alerts import Alerter, SlackNotifier
from portcullis.audit import Audit
from portcullis.detector import Detection, Level
from portcullis.escalation import EscalationEngine
from portcullis.firewall.dryrun import DryRunBackend
from portcullis.reputation import Blacklist, Whitelist

T0 = datetime(2026, 7, 5, 12, 0, 0)
ATTACKER = "45.33.32.156"


class FakeNotifier:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, message):
        if self.fail:
            raise RuntimeError("channel down")
        self.sent.append(message)


def make_detection(level=Level.BLOCK):
    return Detection(ip=ATTACKER, level=level, weighted_count=8.0,
                     usernames=frozenset({"root", "admin"}),
                     first_seen=T0, last_seen=T0 + timedelta(minutes=2))


# --- Alerter fan-out and throttling ---

def test_alert_fans_out_to_all_notifiers():
    a, b = FakeNotifier(), FakeNotifier()
    alerter = Alerter([a, b])
    alerter.notify("attack!", ip=ATTACKER)
    assert a.sent == ["attack!"]
    assert b.sent == ["attack!"]


def test_dead_notifier_does_not_stop_the_others():
    dead, alive = FakeNotifier(fail=True), FakeNotifier()
    alerter = Alerter([dead, alive])
    alerter.notify("attack!", ip=ATTACKER)  # must not raise
    assert alive.sent == ["attack!"]


def test_per_ip_throttle():
    clock_value = [T0]
    n = FakeNotifier()
    alerter = Alerter([n], throttle_seconds=900, clock=lambda: clock_value[0])

    alerter.notify("first", ip=ATTACKER)
    clock_value[0] = T0 + timedelta(minutes=5)
    alerter.notify("too soon", ip=ATTACKER)        # inside window: dropped
    clock_value[0] = T0 + timedelta(minutes=20)
    alerter.notify("late enough", ip=ATTACKER)     # window passed: sent
    assert n.sent == ["first", "late enough"]


def test_throttle_is_per_ip_not_global():
    n = FakeNotifier()
    alerter = Alerter([n], clock=lambda: T0)
    alerter.notify("a", ip="1.1.1.1")
    alerter.notify("b", ip="2.2.2.2")   # different IP: not throttled
    assert n.sent == ["a", "b"]


def test_ipless_messages_bypass_throttle():
    n = FakeNotifier()
    alerter = Alerter([n], clock=lambda: T0)
    alerter.notify("system notice")
    alerter.notify("another notice")
    assert len(n.sent) == 2


# --- Slack notifier (no real Slack: monkeypatch urlopen) ---

def test_slack_posts_json_payload(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append((req, timeout))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    notifier = SlackNotifier("https://hooks.slack.example/T000/B000/XXX")
    notifier.send("BLOCKED 45.33.32.156")

    assert len(calls) == 1
    req, timeout = calls[0]
    assert timeout == 5                                # the hang guard
    assert b"BLOCKED 45.33.32.156" in req.data
    assert req.get_header("Content-type") == "application/json"


# --- Audit ---

def test_detection_round_trip():
    audit = Audit(":memory:")
    audit.record_detection(make_detection())
    rows = audit.top_attackers()
    assert rows == [(ATTACKER, 1, (T0 + timedelta(minutes=2)).isoformat())]


def test_actions_recorded_and_filtered_by_time():
    audit = Audit(":memory:")
    audit.record_action(ATTACKER, "block", T0, expires_at=T0 + timedelta(days=1))
    audit.record_action(ATTACKER, "unblock", T0 + timedelta(days=1))

    all_rows = audit.recent_actions()
    assert [r[2] for r in all_rows] == ["block", "unblock"]

    late = audit.recent_actions(since=T0 + timedelta(hours=1))
    assert [r[2] for r in late] == ["unblock"]


def test_operator_is_recorded():
    audit = Audit(":memory:")
    audit.record_action(ATTACKER, "block", T0, operator="manual")
    assert audit.recent_actions()[0][4] == "manual"


def test_top_attackers_orders_by_count():
    audit = Audit(":memory:")
    for _ in range(3):
        audit.record_detection(make_detection())
    noisy = Detection(ip="198.51.100.99", level=Level.ALERT, weighted_count=3.0,
                      usernames=frozenset({"bob"}), first_seen=T0, last_seen=T0)
    audit.record_detection(noisy)
    rows = audit.top_attackers()
    assert rows[0][0] == ATTACKER
    assert rows[0][1] == 3


def test_sql_injection_username_is_inert():
    # An attacker whose username is a SQL payload must land as plain data.
    hostile = Detection(ip=ATTACKER, level=Level.BLOCK, weighted_count=8.0,
                        usernames=frozenset({"'; DROP TABLE detections;--"}),
                        first_seen=T0, last_seen=T0)
    audit = Audit(":memory:")
    audit.record_detection(hostile)
    assert audit.top_attackers()[0][1] == 1  # table intact, row stored


# --- engine + audit end to end ---

def test_engine_writes_audit_trail():
    audit = Audit(":memory:")
    eng = EscalationEngine(Whitelist(), DryRunBackend(), Blacklist(),
                           audit=audit, base_block_seconds=100)
    eng.handle(make_detection(), now=T0)
    eng.tick(now=T0 + timedelta(seconds=150))

    assert audit.top_attackers()[0][0] == ATTACKER
    actions = [r[2] for r in audit.recent_actions()]
    assert actions == ["block", "unblock"]
