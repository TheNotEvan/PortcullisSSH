# PortcullisSSH

Monitors SSH authentication logs, detects brute-force patterns, and drops the gate
on offending IPs at the firewall — with escalating responses, whitelisting,
automatic unblocking, alerting, and a full audit trail. Invoked as `portcullis`.

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
pip install -e .           # installs the `portcullis` command and PyYAML
```

## Quick start (safe, observe-only)

```bash
cp config.example.yaml config.yaml
# edit config.yaml: set log_path and add your own IP/office range to whitelist
portcullis --config config.yaml test-config      # validate
portcullis --config config.yaml run --dry-run    # watch, but never touch the firewall
```

Let it run in `--dry-run` for a day or two, review what it *would* have blocked
(`portcullis --config config.yaml report`), tune thresholds, add any missing IPs to
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
portcullis --config config.yaml replay tests/fixtures/attack_sample.log
```

## Deploying on Linux

1. Put the project in `/opt/portcullis`, create the venv, `pip install -e .`.
2. `mkdir -p /var/lib/portcullis /etc/portcullis`, copy your config to
   `/etc/portcullis/config.yaml`.
3. `cp deploy/portcullis.service /etc/systemd/system/`, then
   `systemctl enable --now portcullis`.
4. `journalctl -u portcullis -f` to watch it work.

The iptables backend puts all rules in a dedicated `PORTCULLIS` chain, so it never
touches rules it did not create; `iptables -F PORTCULLIS` clears only its own.

See [SECURITY.md](SECURITY.md) for SSH hardening, threat model, false-positive
tuning, and how this compares to fail2ban.
