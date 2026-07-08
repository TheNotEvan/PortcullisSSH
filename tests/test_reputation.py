from datetime import datetime, timedelta

import pytest

from portcullis.reputation import Blacklist, Whitelist

T0 = datetime(2026, 7, 5, 12, 0, 0)


# --- Whitelist ---

def test_exact_ip_match():
    w = Whitelist(["203.0.113.7"])
    assert w.is_listed("203.0.113.7")
    assert not w.is_listed("203.0.113.8")


def test_cidr_range_match_both_sides_of_boundary():
    w = Whitelist(["192.168.1.0/24"])
    assert w.is_listed("192.168.1.1")
    assert w.is_listed("192.168.1.254")
    assert not w.is_listed("192.168.2.1")


def test_loopback_always_listed_even_with_no_entries():
    w = Whitelist()
    assert w.is_listed("127.0.0.1")
    assert w.is_listed("127.255.255.255")  # whole /8, not just .1
    assert w.is_listed("::1")


def test_garbage_ip_fails_closed():
    w = Whitelist(["192.168.1.0/24"])
    assert not w.is_listed("not-an-ip")
    assert not w.is_listed("")


def test_invalid_entry_raises_at_construction():
    with pytest.raises(ValueError, match="192.168.1.0/33"):
        Whitelist(["192.168.1.0/33"])


def test_sloppy_cidr_is_tolerated():
    # Host bits set: strict=False should round down to the network.
    w = Whitelist(["192.168.1.5/24"])
    assert w.is_listed("192.168.1.200")


def test_overlapping_entries_are_harmless():
    w = Whitelist(["10.0.0.0/8", "10.1.0.0/16"])
    assert w.is_listed("10.1.2.3")


# --- Blacklist ---

def test_stranger_has_zero_blocks():
    b = Blacklist()
    assert b.times_blocked("203.0.113.7") == 0


def test_failures_are_counted():
    b = Blacklist()
    b.record_failure("203.0.113.7", T0)
    b.record_failure("203.0.113.7", T0 + timedelta(minutes=1))
    b.record_failure("203.0.113.7", T0 + timedelta(minutes=2))
    record = b._records["203.0.113.7"]
    assert record["total_failures"] == 3
    assert record["first_seen"] == T0                          # frozen
    assert record["last_seen"] == T0 + timedelta(minutes=2)    # advances


def test_blocks_are_counted():
    b = Blacklist()
    b.record_failure("203.0.113.7", T0)
    b.record_block("203.0.113.7")
    b.record_block("203.0.113.7")
    assert b.times_blocked("203.0.113.7") == 2


def test_block_without_prior_failures_creates_record():
    # A manual block of an IP the detector never saw must not crash.
    b = Blacklist()
    b.record_block("203.0.113.7", timestamp=T0)
    assert b.times_blocked("203.0.113.7") == 1
    assert b._records["203.0.113.7"]["total_failures"] == 0


def test_ips_tracked_independently():
    b = Blacklist()
    b.record_failure("203.0.113.7", T0)
    b.record_failure("198.51.100.99", T0)
    b.record_block("203.0.113.7")
    assert b.times_blocked("203.0.113.7") == 1
    assert b.times_blocked("198.51.100.99") == 0


# --- persistence ---

def test_save_and_reload_round_trip(tmp_path):
    path = str(tmp_path / "blacklist.json")
    b = Blacklist(path)
    b.record_failure("203.0.113.7", T0)
    b.record_failure("203.0.113.7", T0 + timedelta(minutes=5))
    b.record_block("203.0.113.7")

    b2 = Blacklist(path)  # fresh object, same file
    assert b2.times_blocked("203.0.113.7") == 1
    record = b2._records["203.0.113.7"]
    assert record["total_failures"] == 2
    assert record["first_seen"] == T0                       # datetime restored,
    assert isinstance(record["first_seen"], datetime)       # not left a string


def test_corrupt_blacklist_file_is_ignored(tmp_path):
    path = tmp_path / "blacklist.json"
    path.write_text("{ not json")
    b = Blacklist(str(path))
    assert b.times_blocked("203.0.113.7") == 0  # empty memory, no crash


def test_memory_only_blacklist_writes_no_files(tmp_path):
    b = Blacklist()  # no path
    b.record_failure("203.0.113.7", T0)
    assert list(tmp_path.iterdir()) == []
