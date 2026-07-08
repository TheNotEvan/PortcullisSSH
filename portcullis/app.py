"""Application assembly and the main poll loop.

This is where every component finally meets: monitor -> parser -> detector ->
escalation engine, plus the tick() heartbeat that expires old blocks.
"""

import os
import time

from portcullis.alerts import Alerter, LogNotifier, SlackNotifier
from portcullis.audit import Audit
from portcullis.detector import BruteForceDetector
from portcullis.escalation import EscalationEngine
from portcullis.firewall import get_backend
from portcullis.monitor import LogMonitor
from portcullis.parser import parse_line
from portcullis.reputation import Blacklist, Whitelist


def _admin_ssh_ip():
    """The IP of the current SSH session, if any, so we never self-block it."""
    conn = os.environ.get("SSH_CONNECTION", "")
    parts = conn.split()
    return parts[0] if parts else None


def build_whitelist(config):
    entries = list(config.whitelist)
    admin_ip = _admin_ssh_ip()
    if admin_ip and admin_ip not in entries:
        entries.append(admin_ip)  # never lock out the hand at the keyboard
    return Whitelist(entries)


def build_alerter(config):
    notifiers = []
    if config.alerts.syslog_enabled:
        notifiers.append(LogNotifier())
    if config.alerts.slack.enabled:
        notifiers.append(SlackNotifier(config.alerts.slack.webhook_url))
    return Alerter(notifiers, throttle_seconds=config.alerts.throttle_seconds)


class Application:
    """Holds the wired-together components and runs the loop."""

    def __init__(self, config, dry_run=False):
        self.config = config
        os.makedirs(config.state_dir, exist_ok=True)  # ensure state dir exists
        d = config.detection

        backend_name = "dryrun" if dry_run else config.firewall.backend
        firewall = get_backend(
            backend_name,
            chain=config.firewall.chain,
            ssh_port=config.firewall.ssh_port,
            allow_private_blocking=config.firewall.allow_private_blocking,
            max_blocked_ips=config.firewall.max_blocked_ips,
        )

        self.blacklist = Blacklist(config.blacklist_path)
        self.audit = Audit(config.db_path)
        self.detector = BruteForceDetector(
            alert_threshold=d.alert_threshold,
            rate_limit_threshold=d.rate_limit_threshold,
            block_threshold=d.block_threshold,
            window_seconds=d.window_seconds,
            invalid_user_weight=d.invalid_user_weight,
            distinct_users_threshold=d.distinct_users_threshold,
        )
        self.engine = EscalationEngine(
            whitelist=build_whitelist(config),
            firewall=firewall,
            blacklist=self.blacklist,
            alerter=build_alerter(config),
            audit=self.audit,
            base_block_seconds=config.escalation.base_block_seconds,
            block_multiplier=config.escalation.block_multiplier,
            max_block_seconds=config.escalation.max_block_seconds,
            state_path=config.block_state_path,
        )
        self.monitor = LogMonitor(
            config.log_path,
            state_path=config.monitor_state_path,
            poll_interval=config.poll_interval,
        )

    def _process_line(self, line, now=None):
        event = parse_line(line)
        if event is None:
            return
        if event.source_ip:
            self.blacklist.record_failure(event.source_ip, event.timestamp)
        detection = self.detector.process_event(event)
        if detection is not None:
            self.engine.handle(detection, now=now)

    def run(self, once=False):
        """The daemon loop: drain new lines, expire old blocks, sleep, repeat."""
        while True:
            for line in self.monitor.read_new_lines():
                self._process_line(line)
            self.engine.tick()
            if once:
                return
            time.sleep(self.config.poll_interval)


def replay(config, logfile):
    """Run the detector/engine over a static log file for training or demos.

    Uses each event's own timestamp as the clock, so windows and expiries behave
    exactly as they would have live.
    """
    app = Application(config, dry_run=True)
    last_ts = None
    with open(logfile, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            event = parse_line(line)
            if event is None:
                continue
            last_ts = event.timestamp
            if event.source_ip:
                app.blacklist.record_failure(event.source_ip, event.timestamp)
            detection = app.detector.process_event(event)
            if detection is not None:
                app.engine.handle(detection, now=event.timestamp)
    if last_ts is not None:
        app.engine.tick(now=last_ts)
    return app
