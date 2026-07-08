# SSH Brute Force Detector — Implementation Plan

A Python security tool that monitors SSH authentication logs, detects brute force
patterns, and responds automatically by blocking offending IPs at the firewall —
with escalating responses, whitelisting, auto-unblock, and full audit logging.

---

## 0. Development Strategy (read this first)

You are developing on **Windows 11**, but the tool targets **Linux** (auth logs,
iptables). Structure the project so ~90% of it is testable on Windows:

- **Abstract everything OS-specific behind interfaces.** The log source and the
  firewall backend are pluggable. On Windows you use a *file-based sample log*
  and a *dry-run firewall* that just prints/logs what it *would* do.
- **Ship sample log fixtures** (`tests/fixtures/auth.log`) containing real-format
  Debian/Ubuntu and RHEL log lines — both benign traffic and simulated attacks.
- **Final integration testing** happens on a Linux VM (WSL2, VirtualBox Ubuntu
  Server, or a cheap VPS). WSL2 + `openssh-server` is the easiest option: you can
  generate real failed logins against yourself with `ssh wronguser@localhost`.

**Suggested milestones (each one is a working, demoable state):**

| Milestone | Deliverable |
|---|---|
| M1 | Parser: turn log lines into structured events |
| M2 | Tail/monitor: follow a live log file, survive rotation, persist state |
| M3 | Detector: sliding-window threshold detection per IP |
| M4 | Whitelist/blacklist + config file |
| M5 | Firewall backends (dry-run, iptables) + safeguards |
| M6 | Escalation engine + auto-unblock scheduler |
| M7 | Alerting (Slack/syslog) + audit database |
| M8 | CLI, docs, deployment (systemd unit), Linux integration test |

---

## 1. Project Layout

```
portcullis/
├── portcullis/
│   ├── __init__.py
│   ├── __main__.py          # python -m portcullis → CLI entry
│   ├── cli.py               # argparse: run, status, block, unblock, test-config
│   ├── config.py            # load/validate YAML config (dataclasses)
│   ├── parser.py            # log line → AuthEvent
│   ├── monitor.py           # file tailing, rotation handling, state persistence
│   ├── detector.py          # sliding-window brute force detection
│   ├── reputation.py        # whitelist/blacklist management
│   ├── escalation.py        # multi-stage response state machine
│   ├── firewall/
│   │   ├── __init__.py      # get_backend(name) factory
│   │   ├── base.py          # FirewallBackend ABC: block/unblock/rate_limit/list
│   │   ├── dryrun.py        # logs actions only (Windows dev + safe testing)
│   │   └── iptables.py
│   ├── alerts.py            # Slack webhook / syslog notifiers
│   └── audit.py             # SQLite audit trail
├── tests/
│   ├── fixtures/
│   │   ├── auth_debian.log      # Ubuntu/Debian format samples
│   │   ├── auth_rhel.log        # RHEL /var/log/secure samples
│   │   └── attack_sample.log    # realistic brute force burst
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_reputation.py
│   ├── test_escalation.py
│   └── test_firewall_dryrun.py
├── config.example.yaml
├── deploy/portcullis.service   # systemd unit
├── README.md
├── SECURITY.md              # best practices & mitigation discussion
└── pyproject.toml
```

Dependencies: keep it stdlib-heavy. `PyYAML` for config, `pytest` for tests,
optionally `requests` for Slack webhooks (or just use stdlib `urllib.request`).
Everything else (re, sqlite3, subprocess, ipaddress, collections, datetime) is
stdlib.

---

## 2. M1 — Log Parser (`parser.py`)

### Log formats to support

Classic syslog format (Debian/Ubuntu `/var/log/auth.log`, RHEL `/var/log/secure`):

```
Jun 30 14:22:01 myhost sshd[12345]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2
Jun 30 14:22:03 myhost sshd[12345]: Failed password for root from 203.0.113.7 port 51236 ssh2
Jun 30 14:22:05 myhost sshd[12345]: Invalid user oracle from 203.0.113.7 port 51240
Jun 30 14:23:10 myhost sshd[12350]: Accepted publickey for alice from 198.51.100.4 port 50022 ssh2
Jun 30 14:24:00 myhost sshd[12351]: Connection closed by authenticating user root 203.0.113.7 port 51300 [preauth]
Jun 30 14:24:30 myhost sshd[12352]: error: maximum authentication attempts exceeded for root from 203.0.113.7 port 51310 ssh2 [preauth]
```

Also handle ISO-8601 timestamps (newer distros with rsyslog `RSYSLOG_FileFormat`
or `journalctl -o short-iso` output): `2026-06-30T14:22:01.123456+00:00 ...`.

### Design

```python
@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    event_type: EventType   # FAILED_PASSWORD | INVALID_USER | ACCEPTED |
                            # AUTH_MAX_EXCEEDED | DISCONNECT_PREAUTH | OTHER
    username: str | None
    source_ip: str | None   # validated via ipaddress module (v4 and v6!)
    port: int | None
    raw_line: str
```

- One compiled regex per pattern, tried in order; `parse_line(line) -> AuthEvent | None`
  (return `None` for non-sshd / irrelevant lines — never raise on garbage input).
- **Timestamp gotcha:** classic syslog has no year. Assume current year; if that
  puts the event in the future (January rollover), subtract one year.
- Track `ACCEPTED` too — a success after many failures from the same IP is a
  *compromise indicator* worth a high-severity alert.
- Unit tests: every fixture line parses to the expected event; malformed lines
  return None; IPv6 addresses parse.

---

## 3. M2 — Log Monitor (`monitor.py`)

Continuously tail the log file, robust to rotation, without re-reading lines.

### Approach

- Open file, seek to saved offset (or end on first run), read new lines, sleep
  `poll_interval` (1s default), repeat. A generator `follow() -> Iterator[str]`
  keeps this testable.
- **Rotation detection:** each poll, `os.stat()` the path and compare
  `(st_ino, st_size)` (inode on Linux; on Windows-dev just size) with what you
  have open:
  - inode changed → file was rotated (renamed + recreated): finish reading the
    old handle, then reopen the path from offset 0.
  - size < current offset → file was truncated (copytruncate rotation): reset
    offset to 0.
- **State persistence:** write `{path, inode, offset}` to a small JSON state file
  (`/var/lib/portcullis/state.json`) after each batch, so restarts don't re-process
  (which would re-block) or miss lines.
- Optional stretch: a `journalctl -f -u ssh -o short-iso` subprocess source for
  systemd-journal-only hosts. Keep it behind the same source interface.

---

## 4. M3 — Brute Force Detector (`detector.py`)

### Sliding-window counting

- `defaultdict(deque)` mapping `source_ip -> deque[datetime]` of recent failures.
- On each failure event: append timestamp, evict entries older than
  `window_seconds`, compare count to threshold.
- `INVALID_USER` and `AUTH_MAX_EXCEEDED` events can carry a higher weight
  (configurable, e.g. ×2) — nobody legitimately typos a nonexistent username
  ten times.
- Also track *distinct usernames per IP* in the window: many usernames from one
  IP is a strong brute-force/spray signal even below the failure-count threshold.
- Periodically prune IPs with empty deques (memory hygiene for long-running daemon).
- Detector is a pure function of events + clock → emits `Detection(ip, level_hint,
  count, usernames, first_seen, last_seen)`. No side effects; the escalation
  engine decides what to do. This makes it trivially unit-testable with synthetic
  event streams (inject a fake clock — don't call `datetime.now()` inside).

### Config knobs

```yaml
detection:
  window_seconds: 600        # 10-minute window
  alert_threshold: 3         # failures → notify admin
  rate_limit_threshold: 5    # failures → rate-limit stage
  block_threshold: 8         # failures → full block
  invalid_user_weight: 2
  distinct_users_threshold: 4  # ≥4 usernames in window → treat as attack
```

---

## 5. M4 — IP Reputation (`reputation.py`)

- **Whitelist:** list of IPs *and CIDR networks* (use `ipaddress.ip_network`;
  membership via `ip in network`). Always includes `127.0.0.0/8`, `::1`, and —
  critically — auto-detects and includes **the admin's current SSH client IP**
  (parse `$SSH_CLIENT`/`$SSH_CONNECTION` env or `who am i` at startup) so you can
  never lock yourself out. Whitelisted IPs generate *alerts only*, never blocks.
- **Blacklist:** persisted set of IPs with attack history: first_seen, last_seen,
  total_attempts, times_blocked. Repeat offenders can get longer block durations
  (e.g. double each time). Store in the SQLite DB (shared with audit) rather than
  a flat file — you already need SQLite for M7.
- Manual management via CLI: `portcullis whitelist add 198.51.100.0/24`,
  `portcullis blacklist show`, etc.

---

## 6. M5 — Firewall Backends (`firewall/`)

### Interface

```python
class FirewallBackend(ABC):
    def block(self, ip: str) -> None: ...
    def rate_limit(self, ip: str) -> None: ...   # may fall back to block()
    def unblock(self, ip: str) -> None: ...
    def list_blocked(self) -> set[str]: ...
```

### Implementations

- **dryrun** — logs every action; default backend. This is what runs on Windows
  and what you use to validate detection logic against real logs safely.
- **iptables** — use a **dedicated chain** so you never touch other rules:
  ```
  iptables -N PORTCULLIS                      (once, at startup; idempotent)
  iptables -I INPUT -p tcp --dport 22 -j PORTCULLIS   (once)
  iptables -A PORTCULLIS -s <ip> -j DROP      (block)
  iptables -D PORTCULLIS -s <ip> -j DROP      (unblock)
  ```
  Rate-limit stage: `-m hashlimit` or `-m recent` rule instead of DROP.
  Use `subprocess.run([...], check=True, capture_output=True)` — **always a list
  argv, never `shell=True`**, and validate the IP with `ipaddress.ip_address()`
  before it goes anywhere near a command (defense-in-depth against log-injection
  → command-injection: attackers control usernames in log lines!).
- (Stretch, if you want a second backend later: `ufw` or `nftables`. The
  `FirewallBackend` ABC means adding one is self-contained and doesn't touch the
  rest of the tool.)

### Safeguards (non-negotiable)

1. Refuse to block whitelisted IPs — checked in escalation *and* re-checked in
   the backend (belt and suspenders).
2. Refuse to block private/loopback ranges unless `allow_private_blocking: true`
   (for lab testing).
3. Refuse to block the IP of the current SSH session (self-lockout guard).
4. `max_blocked_ips` cap (e.g. 1000) so a spoofed-log or misparse event can't
   turn the tool into a self-inflicted DoS.
5. On startup, reconcile: read `list_blocked()` and the DB so state survives
   restarts; expired blocks get removed.
6. **Log injection hardening:** never trust the username field (attacker-chosen);
   only ever act on the regex-validated IP field.

---

## 7. M6 — Escalation Engine (`escalation.py`)

Per-IP state machine:

```
NORMAL → ALERTED → RATE_LIMITED → BLOCKED → (expiry) → UNBLOCKED/NORMAL
```

- Stage transitions driven by detector output crossing each threshold.
- **Auto-unblock:** every block gets `expires_at = now + block_duration`
  (default 24h; multiplied for repeat offenders, capped at e.g. 30 days).
  A scheduler tick (runs in the main poll loop, no threads needed) unblocks
  expired IPs and logs it.
- **Manual controls:** `portcullis unblock <ip>` (and optionally
  `--whitelist` to also whitelist it), `portcullis block <ip>` for manual blocks.
- All state persisted to SQLite so a daemon restart doesn't forget who's blocked
  or when they expire.

---

## 8. M7 — Alerting & Audit (`alerts.py`, `audit.py`)

### Alerts

- Notifier interface with implementations: **syslog** (via `logging.handlers.SysLogHandler`
  / stdlib logging — always on) and **Slack** (webhook POST, config-gated).
  Fan out to all configured notifiers. (The interface keeps adding another channel
  later — email, PagerDuty, etc. — a drop-in with no changes elsewhere.)
- Alert content: IP, event count, window, usernames targeted, stage
  (alert/rate-limit/block), action taken, unblock time.
- **Throttle alerts per IP** (e.g. max 1 per 15 min per IP) so an ongoing attack
  doesn't flood your inbox.
- Special high-severity alert: successful login from an IP with recent failures.

### Audit trail (SQLite)

Tables:
- `events(id, ts, ip, username, event_type, raw_line)` — optionally only
  attack-related events to bound size
- `detections(id, ts, ip, count, distinct_users, stage)`
- `actions(id, ts, ip, action, backend, expires_at, operator)` — operator =
  'auto' or CLI user; covers blocks, unblocks, manual overrides
- `ip_reputation(ip, first_seen, last_seen, total_failures, times_blocked, listed)`

`portcullis report [--since 24h]` prints a summary (top attackers, usernames
targeted, actions taken) for incident review / compliance.

---

## 9. M8 — CLI, Config, Deployment, Docs

### CLI (`cli.py`)

```
portcullis run [--config /etc/portcullis/config.yaml] [--dry-run] [--once]
portcullis status                 # blocked IPs, expiries, stats
portcullis block/unblock <ip>
portcullis whitelist add/remove/show <ip|cidr>
portcullis report [--since 24h]
portcullis test-config            # validate config, test alert channels
portcullis replay <logfile>       # run detector over a static file (training/demo)
```

`--once` (process available lines and exit) and `replay` make testing and demos
easy without a daemon.

### Config file (`config.example.yaml`)

Everything above: log path, poll interval, thresholds, window, backend choice,
block durations, whitelist, alert channels, DB path. Validate at startup with
clear error messages; `test-config` subcommand.

### Deployment

- `deploy/portcullis.service` systemd unit: `User=root` (needed for iptables),
  `Restart=on-failure`, hardening directives (`ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/portcullis`, `NoNewPrivileges` won't work with iptables —
  document why).
- Install: `pipx install .` or venv in `/opt/portcullis`.
- **First-run checklist in README:** run in `--dry-run` for 48h, review would-block
  log, add your own IPs/CIDRs to whitelist, then enable enforcement.

### Documentation (README.md + SECURITY.md)

- SSH hardening best practices: key-only auth (`PasswordAuthentication no`),
  disable root login, `MaxAuthTries`, non-standard port trade-offs, VPN/bastion
  restriction, 2FA.
- How brute force / credential-stuffing / password-spray attacks look in logs,
  with annotated real examples (your `attack_sample.log`).
- Comparison with fail2ban / CrowdSec / sshguard — what this tool teaches vs.
  what you'd run in production, and how to tune thresholds to avoid false
  positives (fat-fingered passwords vs. attacks).
- Threat model & limitations: distributed (botnet) attacks defeat per-IP
  thresholds; IPv6 rotation; log injection risks; why whitelisting matters.

---

## 10. Testing Plan

- **Unit (Windows-friendly):** parser fixtures, detector with fake clock,
  reputation CIDR matching, escalation transitions, dry-run backend.
- **Simulation:** a `tests/gen_attack.py` script that writes synthetic attack
  traffic into a log file in real time; run `portcullis run --dry-run` against it
  and watch detections fire. Also simulate rotation (rename the file mid-run)
  to prove M2 works.
- **Linux integration (WSL2/VM):**
  1. `sudo apt install openssh-server`, start sshd.
  2. Run the tool with iptables backend, `allow_private_blocking: true`,
     low thresholds.
  3. From another shell: `for i in $(seq 1 10); do ssh -o PreferredAuthentications=password wronguser@127.0.0.1; done`
     (or better, from a second VM so you're blocking a non-local IP).
  4. Verify: alert fired → rate limit → block appears in `iptables -L PORTCULLIS -n`
     → connection refused → auto-unblock after configured (short, for testing)
     duration → audit rows present.
  5. Verify self-lockout guard: try to make it block your own session IP.

**Only ever run enforcement against machines you own/control (your VMs).**

---

## 11. Order of Work — Summary Checklist

1. [ ] Scaffold repo, `pyproject.toml`, config loader, fixtures
2. [ ] `parser.py` + tests (M1)
3. [ ] `monitor.py` with rotation + state file + tests (M2)
4. [ ] `detector.py` sliding window + tests (M3)
5. [ ] `reputation.py` whitelist/blacklist + SQLite schema (M4)
6. [ ] `firewall/` dry-run → iptables + safeguards (M5)
7. [ ] `escalation.py` + auto-unblock scheduler (M6)
8. [ ] `alerts.py` (syslog + Slack) + `audit.py` + report command (M7)
9. [ ] CLI polish, systemd unit, README/SECURITY docs (M8)
10. [ ] WSL2/VM end-to-end test with real sshd
