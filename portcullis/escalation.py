import json
import logging
import os
from datetime import datetime, timedelta

from portcullis.detector import Level

logger = logging.getLogger("portcullis.escalation")


class EscalationEngine:
    """Turns detector verdicts into firewall actions, with per-offender block
    durations and automatic expiry.

    Collaborators are injected (whitelist, firewall, blacklist, alerter) so the
    engine names interfaces, not concrete classes -- tests pass in a dry-run
    firewall and a fake alerter.
    """

    def __init__(self, whitelist, firewall, blacklist, alerter=None, audit=None,
                 base_block_seconds=86400, block_multiplier=2.0,
                 max_block_seconds=2592000, state_path=None, clock=None):
        self.whitelist = whitelist
        self.firewall = firewall
        self.blacklist = blacklist
        self.alerter = alerter
        self.audit = audit
        self.base_block_seconds = base_block_seconds
        self.block_multiplier = block_multiplier
        self.max_block_seconds = max_block_seconds
        self.state_path = state_path
        self._clock = clock or datetime.now
        # ip -> {"stage": Level, "expires_at": datetime | None}
        self._blocks = {}
        self._load()

    # --- reacting to a detection ---

    def handle(self, detection, now=None):
        now = now or self._clock()
        ip = detection.ip

        # Every detection is audit-worthy, acted on or not.
        if self.audit is not None:
            self.audit.record_detection(detection)

        # Gate 1: the whitelist wins every argument. Never act on a listed IP.
        if self.whitelist.is_listed(ip):
            self._notify(f"whitelisted {ip} hit {detection.level.name}; not acting", ip)
            return

        # Gate 2: escalation-only. Don't re-act at a stage we've already reached
        # (survives detector resets and restarts via the persisted stage map).
        entry = self._blocks.get(ip)
        current_stage = entry["stage"] if entry else None
        if current_stage is not None and detection.level <= current_stage:
            return

        if detection.level == Level.ALERT:
            self._blocks[ip] = {"stage": Level.ALERT, "expires_at": None}
            self._notify(f"ALERT {ip} weighted={detection.weighted_count} "
                         f"users={sorted(detection.usernames)}", ip)

        elif detection.level == Level.RATE_LIMIT:
            self.firewall.rate_limit(ip)
            expires = now + timedelta(seconds=self.base_block_seconds)
            self._blocks[ip] = {"stage": Level.RATE_LIMIT, "expires_at": expires}
            self._audit_action(ip, "rate_limit", now, expires)
            self._notify(f"RATE-LIMITED {ip} until {expires.isoformat()}", ip)

        elif detection.level == Level.BLOCK:
            expires = now + timedelta(seconds=self._block_duration(ip))
            self.firewall.block(ip)
            self.blacklist.record_block(ip, now)  # AFTER reading duration
            self._blocks[ip] = {"stage": Level.BLOCK, "expires_at": expires}
            self._audit_action(ip, "block", now, expires)
            self._notify(f"BLOCKED {ip} until {expires.isoformat()}", ip)

        self._save()

    def _block_duration(self, ip):
        # Repeat offenders serve longer: base * multiplier**(prior blocks).
        # Read times_blocked BEFORE record_block, so a first offense uses **0 = 1.
        times = self.blacklist.times_blocked(ip)
        duration = self.base_block_seconds * (self.block_multiplier ** times)
        return min(duration, self.max_block_seconds)

    # --- the heartbeat: expire old blocks ---

    def tick(self, now=None):
        now = now or self._clock()
        changed = False
        # Snapshot items: we mutate the dict while iterating it.
        for ip, entry in list(self._blocks.items()):
            expires = entry["expires_at"]
            if expires is not None and now >= expires:
                self.firewall.unblock(ip)
                del self._blocks[ip]
                self._audit_action(ip, "unblock", now)
                self._notify(f"auto-unblocked {ip} (block expired)", ip)
                changed = True
        if changed:
            self._save()

    # --- manual controls (the CLI calls these) ---

    def manual_block(self, ip, now=None, duration_seconds=None):
        now = now or self._clock()
        duration = duration_seconds or self.base_block_seconds
        expires = now + timedelta(seconds=duration)
        self.firewall.block(ip)
        self.blacklist.record_block(ip, now)
        self._blocks[ip] = {"stage": Level.BLOCK, "expires_at": expires}
        self._audit_action(ip, "block", now, expires, operator="manual")
        self._notify(f"manually blocked {ip}", ip)
        self._save()

    def manual_unblock(self, ip, now=None):
        now = now or self._clock()
        self.firewall.unblock(ip)
        self._blocks.pop(ip, None)  # also drop from state, or tick still tracks it
        self._audit_action(ip, "unblock", now, operator="manual")
        self._notify(f"manually unblocked {ip}", ip)
        self._save()

    def blocked_ips(self):
        return dict(self._blocks)

    # --- helpers ---

    def _notify(self, message, ip=None):
        logger.info(message)
        if self.alerter is not None:
            self.alerter.notify(message, ip=ip)

    def _audit_action(self, ip, action, now, expires_at=None, operator="auto"):
        if self.audit is not None:
            self.audit.record_action(ip, action, now, expires_at, operator)

    def _save(self):
        if self.state_path is None:
            return
        data = {}
        for ip, entry in self._blocks.items():
            expires = entry["expires_at"]
            data[ip] = {
                "stage": int(entry["stage"]),
                "expires_at": expires.isoformat() if expires else None,
            }
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.state_path)

    def _load(self):
        if self.state_path is None:
            return
        try:
            with open(self.state_path, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
        blocks = {}
        for ip, entry in data.items():
            expires = entry["expires_at"]
            blocks[ip] = {
                "stage": Level(entry["stage"]),
                "expires_at": datetime.fromisoformat(expires) if expires else None,
            }
        self._blocks = blocks
