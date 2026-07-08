# ssh-bfd — SSH Brute Force Detector

Monitors SSH authentication logs, detects brute-force patterns, and responds by
blocking offending IPs at the firewall — with escalating responses, whitelisting,
automatic unblocking, alerting, and a full audit trail.

> Educational project. Run enforcement only against machines you own or are
> authorized to defend.

## How it works

```
auth.log ──▶ LogMonitor ──▶ parse_line ──▶ BruteForceDetector ──▶ EscalationEngine
             (tail,          (structured     (sliding-window        (whitelist gate,
              rotation,       events)          weighted scoring)      firewall action,
              offset)                                                 auto-expiry)
                                                                         │
                                                        Alerter ◀────────┼────────▶ Audit (SQLite)
                                                 (syslog + Slack,                 (detections,
                                                  per-IP throttle)                 actions)
```

Each component is decoupled and independently tested (100+ tests). The firewall
is pluggable: a **dry-run** backend (logs only) for development and safe trials,
and an **iptables** backend for real Linux enforcement.

## Install

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e .           # installs the `ssh-bfd` command and PyYAML
```

## Quick start (safe, observe-only)

```bash
cp config.example.yaml config.yaml
# edit config.yaml: set log_path and add your own IP/office range to whitelist
ssh-bfd --config config.yaml test-config      # validate
ssh-bfd --config config.yaml run --dry-run    # watch, but never touch the firewall
```

Let it run in `--dry-run` for a day or two, review what it *would* have blocked
(`ssh-bfd --config config.yaml report`), tune thresholds, add any missing IPs to
the whitelist — **then** switch `firewall.backend` to `iptables` and run as root.

## Commands

| Command | What it does |
|---|---|
| `run [--dry-run] [--once]` | Watch the log and respond |
| `status` | Show currently blocked IPs and expiry times |
| `block <ip>` / `unblock <ip>` | Manual controls |
| `report` | Top attackers and recent actions (from the audit DB) |
| `replay <logfile>` | Run the detector over a static log — great for training/tuning |
| `test-config` | Validate the config file |

Try `replay` right now, no setup needed:

```bash
ssh-bfd --config config.yaml replay tests/fixtures/attack_sample.log
```

## Deploying on Linux

1. Put the project in `/opt/ssh-bfd`, create the venv, `pip install -e .`.
2. `mkdir -p /var/lib/ssh-bfd /etc/ssh-bfd`, copy your config to
   `/etc/ssh-bfd/config.yaml`.
3. `cp deploy/ssh-bfd.service /etc/systemd/system/`, then
   `systemctl enable --now ssh-bfd`.
4. `journalctl -u ssh-bfd -f` to watch it work.

The iptables backend puts all rules in a dedicated `SSH_BFD` chain, so it never
touches rules it did not create; `iptables -F SSH_BFD` clears only its own.

See [SECURITY.md](SECURITY.md) for SSH hardening, threat model, false-positive
tuning, and how this compares to fail2ban.
