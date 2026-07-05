from datetime import datetime

from ssh_bfd.parser import EventType, parse_line


# --- plain positives: one per line shape ---

def test_failed_password_for_root():
    line = "Jun 30 14:22:01 myhost sshd[12345]: Failed password for root from 203.0.113.7 port 51236 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.FAILED_PASSWORD
    assert event.source_ip == "203.0.113.7"
    assert event.username == "root"
    assert event.port == 51236


def test_accepted_publickey():
    line = "Jun 30 14:23:10 myhost sshd[12350]: Accepted publickey for alice from 198.51.100.4 port 50022 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.ACCEPTED
    assert event.source_ip == "198.51.100.4"
    assert event.username == "alice"


def test_invalid_user_without_port():
    line = "Jun 30 14:22:05 myhost sshd[12345]: Invalid user oracle from 203.0.113.7"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.INVALID_USER
    assert event.source_ip == "203.0.113.7"
    assert event.username == "oracle"
    assert event.port is None


def test_max_auth_exceeded():
    line = "Jun 30 14:24:30 myhost sshd[12352]: error: maximum authentication attempts exceeded for root from 203.0.113.7 port 51310 ssh2 [preauth]"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.AUTH_MAX_EXCEEDED
    assert event.source_ip == "203.0.113.7"
    assert event.username == "root"


def test_disconnect_preauth():
    line = "Jun 30 14:24:00 myhost sshd[12351]: Connection closed by authenticating user root 203.0.113.7 port 51300 [preauth]"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.DISCONNECT_PREAUTH
    assert event.source_ip == "203.0.113.7"
    assert event.username == "root"


# --- bug-catchers ---

def test_invalid_user_beats_failed_password():
    # Ordering trap: this line also matches the general FAILED_PASSWORD pattern.
    # The more specific INVALID_USER pattern must win, and the username must be
    # just "admin", not "invalid user admin".
    line = "Jun 30 14:22:03 myhost sshd[12345]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == EventType.INVALID_USER
    assert event.username == "admin"


def test_non_sshd_line_returns_none():
    line = "Jun 30 14:25:01 myhost CRON[12360]: pam_unix(cron:session): session opened for user root"
    assert parse_line(line) is None


def test_irrelevant_sshd_line_returns_none():
    line = "Jun 30 14:26:00 myhost sshd[12353]: pam_unix(sshd:auth): authentication failure; logname= uid=0"
    assert parse_line(line) is None


def test_empty_string_returns_none():
    assert parse_line("") is None


def test_garbage_returns_none():
    assert parse_line("!!! not a log line at all !!!") is None


def test_log_injection_username():
    # The attacker's login username was literally "admin from 6.6.6.6 port 22".
    # sshd logs it verbatim, then appends the REAL source: 203.0.113.7.
    # The parser must report the real IP from the end of the line, never the
    # attacker-supplied decoy embedded in the username.
    line = (
        "Jun 30 14:22:01 myhost sshd[12345]: Failed password for invalid user "
        "admin from 6.6.6.6 port 22 from 203.0.113.7 port 51234 ssh2"
    )
    event = parse_line(line)
    assert event is not None
    assert event.source_ip == "203.0.113.7"
    assert event.source_ip != "6.6.6.6"


# --- timestamp year inference ---

def test_same_year_timestamp():
    line = "Jun 30 14:22:01 myhost sshd[12345]: Failed password for root from 203.0.113.7 port 51236 ssh2"
    event = parse_line(line, now=datetime(2026, 7, 4, 12, 0, 0))
    assert event is not None
    assert event.timestamp == datetime(2026, 6, 30, 14, 22, 1)


def test_january_year_rollover():
    # Reading a December log line on January 2: the event was LAST year.
    line = "Dec 31 23:58:11 myhost sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2"
    event = parse_line(line, now=datetime(2027, 1, 2, 0, 0, 0))
    assert event is not None
    assert event.timestamp.year == 2026
