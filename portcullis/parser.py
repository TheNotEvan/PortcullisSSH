from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
import ipaddress

ENVELOPE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

class EventType(Enum):
    FAILED_PASSWORD = "failed_password"
    INVALID_USER = "invalid_user"
    ACCEPTED = "accepted"
    AUTH_MAX_EXCEEDED = "auth_max_exceeded"
    DISCONNECT_PREAUTH = "disconnect_preauth"

@dataclass
class AuthEvent:
    timestamp: datetime
    event_type: EventType
    username: str | None
    source_ip: str | None
    port: int | None
    raw_line: str

MSG_PATTERNS = [
    (
        EventType.INVALID_USER,
        re.compile(
            r"^Failed password for invalid user (?P<user>.+) "
            r"from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        EventType.FAILED_PASSWORD,
        re.compile(
            r"^Failed password for (?P<user>.+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        EventType.INVALID_USER,
        re.compile(
            r"^Invalid user (?P<user>.+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
        ),
    ),
    (
        EventType.ACCEPTED,
        re.compile(
            r"^Accepted \S+ for (?P<user>.+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        EventType.AUTH_MAX_EXCEEDED,
        re.compile(
            r"^error: maximum authentication attempts exceeded for "
            r"(?:invalid user )?(?P<user>.+) from (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        EventType.DISCONNECT_PREAUTH,
        re.compile(
            r"^Connection (?:closed|reset) by (?:authenticating user (?P<user>.+) )?"
            r"(?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
]

def _valid_ip(value: str | None) -> str | None:

    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None

def parse_line(line: str, now:datetime | None = None) -> AuthEvent | None:
    line = line.rstrip("\r\n")

    env = ENVELOPE.match(line)
    if not env:
        return None

    now = now or datetime.now()
    
    try:
        # Syslog timestamps have no year; parse with the current year prepended
        # (strptime without a year is deprecated as of Python 3.14). If that
        # lands in the future (December log read in January), it was last year.
        ts = datetime.strptime(f"{now.year} {env.group('ts')}", "%Y %b %d %H:%M:%S")
        if ts > now:
            ts = ts.replace(year=now.year - 1)
    except ValueError:
        return None

    msg = env.group("msg")
    for event_type, pattern in MSG_PATTERNS:
        m = pattern.match(msg)
        if not m:
            continue
        groups = m.groupdict()
        port = groups.get("port")
        return AuthEvent(
            timestamp=ts,
            event_type=event_type,
            username=groups.get("user"),
            source_ip=_valid_ip(groups.get("ip")),
            port=int(port) if port else None,
            raw_line=line,
        )

    return None
