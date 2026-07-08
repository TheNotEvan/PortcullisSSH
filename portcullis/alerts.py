import json
import logging
import urllib.request
from datetime import datetime, timedelta

logger = logging.getLogger("portcullis.alerts")


class LogNotifier:
    """Emits alerts through the logging system at WARNING severity.

    On Linux, route the root logger to syslog (SysLogHandler, wired in the M8
    startup) and these messages reach the system journal; on Windows dev they
    reach the console. The notifier itself stays platform-neutral.
    """

    def send(self, message):
        logger.warning("%s", message)


class SlackNotifier:
    """POSTs alerts to a Slack incoming-webhook URL. Stdlib only."""

    def __init__(self, webhook_url, timeout=5):
        self.webhook_url = webhook_url
        # The timeout is non-negotiable: without it, Slack having a bad day
        # would hang the poll loop -- and stop us reading the attack log.
        self.timeout = timeout

    def send(self, message):
        payload = json.dumps({"text": message}).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=self.timeout)


class Alerter:
    """Fans one alert out to every configured notifier, with per-IP throttling
    so an ongoing attack doesn't flood the channel.
    """

    def __init__(self, notifiers=None, throttle_seconds=900, clock=None):
        self.notifiers = notifiers if notifiers is not None else []
        self.throttle_seconds = throttle_seconds
        self._clock = clock or datetime.now
        self._last_sent = {}  # ip -> datetime of last alert sent

    def notify(self, message, ip=None):
        now = self._clock()
        if ip is not None:
            last = self._last_sent.get(ip)
            if last is not None and (now - last) < timedelta(seconds=self.throttle_seconds):
                # Throttled, but never silently: the log keeps the full record.
                logger.info("throttled alert for %s: %s", ip, message)
                return
            self._last_sent[ip] = now
        for notifier in self.notifiers:
            try:
                notifier.send(message)
            except Exception:
                # One dead channel must never take down the others -- or the loop.
                logger.exception("notifier %s failed", type(notifier).__name__)
