# Security Guide

## SSH hardening comes first

Blocking brute-force IPs is a *second* line of defense. The first is making
password guessing pointless. On the server you are protecting:

- **Use key-based authentication and disable passwords.** In `/etc/ssh/sshd_config`:
  `PasswordAuthentication no`, `ChallengeResponseAuthentication no`. A brute-force
  attack against a key-only server cannot succeed regardless of attempts.
- **Disable root login:** `PermitRootLogin no`.
- **Limit retries per connection:** `MaxAuthTries 3`.
- **Restrict who can log in:** `AllowUsers` / `AllowGroups`.
- **Prefer a bastion host or VPN** so SSH is not exposed to the whole internet.
- **Consider 2FA** (e.g. `pam_google_authenticator`).

If you do all of the above, `portcullis` mostly serves to cut log noise and shed the
load of automated scanners — which is still worth doing.

## What brute-force attacks look like in the logs

From `tests/fixtures/attack_sample.log` — a real-shaped burst from one IP:

```
Failed password for root from 45.33.32.156 ...
Failed password for root from 45.33.32.156 ...
Failed password for invalid user admin from 45.33.32.156 ...
Invalid user oracle from 45.33.32.156 ...
Failed password for invalid user postgres from 45.33.32.156 ...
Failed password for invalid user test from 45.33.32.156 ...
error: maximum authentication attempts exceeded for root from 45.33.32.156 ...
```

Two independent tells: many failures fast, and many *different* usernames
(`admin`, `oracle`, `postgres`, `test`) — nobody legitimate walks a username list.
`portcullis` scores both (weighted failure count and distinct-user count).

## Tuning to avoid false positives

The risk is blocking a legitimate user who fat-fingers a password. Defenses built in:

- **Whitelist** your own IP, office ranges, and monitoring hosts (CIDR supported).
  Your current SSH session's IP is auto-whitelisted, and loopback always is.
- **Weighted scoring** — a plain failed password counts 1, an invalid-username
  attempt counts 2, because the latter has no innocent explanation.
- **Escalation** — the first response is an *alert*, then a rate-limit, then a
  block, so a borderline case surfaces before anyone is cut off.
- **Start in `--dry-run`** and read the `report` before enabling enforcement.

If real users get caught, raise `block_threshold` or `window_seconds`; if attacks
slip through, lower them. Tune against your own `report` output, not guesses.

## Threat model and limitations

- **Distributed (botnet) attacks** defeat any per-IP threshold: 1000 IPs trying
  one password each never trip a per-IP counter. Per-IP blocking is not a defense
  against a spread-out credential-stuffing campaign — key-only auth is.
- **IPv6 rotation** — an attacker with a /64 has effectively unlimited addresses.
- **Log injection** — usernames in logs are attacker-controlled. This tool only
  ever acts on the independently validated source IP, never on the username, and
  never passes either to a shell (list-argv subprocess) or to SQL (parameterized
  queries). Keep it that way in any extension.
- **Self-lockout** — mitigated by the whitelist, loopback protection, private-range
  refusal, and session-IP auto-whitelisting — but when testing enforcement, always
  keep a console session open that does not depend on SSH.
- **Restart reconciliation** — block expiries persist across restarts, but the tool
  does not currently reconcile its state against pre-existing kernel rules it did
  not create. Clear stale rules with `iptables -F PORTCULLIS` if needed.

## Alternatives and prior art

- **fail2ban** — the mature, widely deployed tool for this job; regex "jails" over
  many services. Use it in production. `portcullis` is a from-scratch teaching
  implementation of the same core ideas.
- **sshguard**, **CrowdSec** — other production options, the latter with
  crowd-sourced IP reputation.
