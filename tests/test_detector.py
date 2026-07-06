from datetime import datetime, timedelta

from ssh_bfd.detector import BruteForceDetector, Level
from ssh_bfd.parser import AuthEvent, EventType

T0 = datetime(2026, 7, 5, 12, 0, 0)


def failure(ip="203.0.113.7", minute=0, user="root",
            event_type=EventType.FAILED_PASSWORD):
    """Fabricate a synthetic auth event at T0 + minute."""
    return AuthEvent(
        timestamp=T0 + timedelta(minutes=minute),
        event_type=event_type,
        username=user,
        source_ip=ip,
        port=22,
        raw_line="synthetic",
    )


def run_events(detector, events):
    """Feed events through, returning only the non-None detections."""
    results = []
    for e in events:
        d = detector.process_event(e)
        if d is not None:
            results.append(d)
    return results


# --- thresholds and escalation ---

def test_no_detection_below_threshold():
    d = BruteForceDetector()
    assert d.process_event(failure(minute=0)) is None
    assert d.process_event(failure(minute=1)) is None


def test_alert_at_threshold():
    d = BruteForceDetector()
    events = [failure(minute=i) for i in range(3)]
    results = run_events(d, events)
    assert len(results) == 1
    assert results[0].level == Level.ALERT
    assert results[0].weighted_count == 3.0


def test_escalation_ladder_emits_each_level_once():
    d = BruteForceDetector()
    # 10 failures, one every 30 seconds: crosses 3, 5 and 8.
    events = [failure(minute=i * 0.5) for i in range(10)]
    results = run_events(d, events)
    assert [r.level for r in results] == [Level.ALERT, Level.RATE_LIMIT, Level.BLOCK]


def test_no_repeat_emission_at_same_level():
    d = BruteForceDetector()
    run_events(d, [failure(minute=i) for i in range(3)])  # -> ALERT
    # 4th failure: count 4.0, still in ALERT territory -> silence.
    assert d.process_event(failure(minute=3)) is None


# --- the sliding window ---

def test_failures_outside_window_never_accumulate():
    d = BruteForceDetector(window_seconds=600)
    # One failure every 11 minutes: each expires before the next arrives.
    events = [failure(minute=i * 11) for i in range(10)]
    assert run_events(d, events) == []


def test_quiet_period_resets_episode():
    d = BruteForceDetector(window_seconds=600)
    # Ramp all the way to BLOCK...
    results = run_events(d, [failure(minute=i) for i in range(8)])
    assert results[-1].level == Level.BLOCK
    # ...then 20 minutes of silence, then a NEW attack. It must re-alert,
    # not be muffled by Monday's stale BLOCK memory.
    new_attack = [failure(minute=27 + i) for i in range(3)]
    results = run_events(d, new_attack)
    assert [r.level for r in results] == [Level.ALERT]


# --- weights ---

def test_invalid_user_counts_double():
    d = BruteForceDetector()
    # Two invalid-user attempts at weight 2.0 = 4.0, crossing ALERT(3) on the 2nd.
    events = [failure(minute=i, user=f"ghost{i}", event_type=EventType.INVALID_USER)
              for i in range(2)]
    results = run_events(d, events)
    assert len(results) == 1
    assert results[0].level == Level.ALERT
    assert results[0].weighted_count == 4.0


# --- username spray tripwire ---

def test_username_spray_forces_rate_limit():
    d = BruteForceDetector(distinct_users_threshold=4)
    # 4 failures as 4 DIFFERENT users: weight only 4.0 (ALERT range), but the
    # spray tripwire must raise it to RATE_LIMIT.
    users = ["root", "admin", "oracle", "postgres"]
    events = [failure(minute=i, user=users[i]) for i in range(4)]
    results = run_events(d, events)
    assert results[-1].level == Level.RATE_LIMIT
    assert results[-1].usernames == frozenset(users)


# --- isolation and hygiene ---

def test_ips_tracked_independently():
    d = BruteForceDetector()
    # Interleave two attackers; each must cross ALERT on its own 3rd failure.
    results = []
    for i in range(3):
        for ip in ("203.0.113.7", "198.51.100.99"):
            r = d.process_event(failure(ip=ip, minute=i))
            if r:
                results.append(r)
    assert len(results) == 2
    assert {r.ip for r in results} == {"203.0.113.7", "198.51.100.99"}


def test_accepted_events_are_ignored():
    d = BruteForceDetector()
    events = [failure(minute=i, event_type=EventType.ACCEPTED) for i in range(10)]
    assert run_events(d, events) == []


def test_event_without_ip_is_ignored():
    d = BruteForceDetector()
    e = AuthEvent(T0, EventType.FAILED_PASSWORD, "root", None, 22, "raw")
    assert d.process_event(e) is None


# --- detection contents ---

def test_detection_reports_window_facts():
    d = BruteForceDetector()
    events = [failure(minute=i, user=f"user{i}") for i in range(3)]
    results = run_events(d, events)
    r = results[0]
    assert r.ip == "203.0.113.7"
    assert r.first_seen == T0
    assert r.last_seen == T0 + timedelta(minutes=2)
    assert r.usernames == frozenset({"user0", "user1", "user2"})
