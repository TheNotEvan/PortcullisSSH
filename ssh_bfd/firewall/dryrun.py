import ipaddress
import logging

from ssh_bfd.firewall.base import FirewallBackend

logger = logging.getLogger("ssh_bfd.firewall")


class DryRunBackend(FirewallBackend):
    """A firewall that only pretends: it logs what it would do and remembers
    it in memory. Used for Windows development and for safe observe-only trials
    before enabling real enforcement.
    """

    def __init__(self):
        self._blocked = set()
        self._rate_limited = set()

    def block(self, ip):
        # A non-IP reaching a backend is an upstream bug: fail loudly, do not hide it.
        ipaddress.ip_address(ip)
        self._blocked.add(ip)
        logger.info("DRY-RUN: would block %s", ip)

    def unblock(self, ip):
        # discard() (not remove()) so unblocking an unblocked IP is a no-op:
        # auto-expiry and manual unblock can race.
        self._blocked.discard(ip)
        self._rate_limited.discard(ip)
        logger.info("DRY-RUN: would unblock %s", ip)

    def rate_limit(self, ip):
        ipaddress.ip_address(ip)
        self._rate_limited.add(ip)
        logger.info("DRY-RUN: would rate-limit %s", ip)

    def list_blocked(self):
        # Return a copy: never hand callers a live reference to our internals.
        return set(self._blocked)
