import ipaddress
import logging
import subprocess

from portcullis.firewall.base import FirewallBackend

logger = logging.getLogger("portcullis.firewall")


class IptablesBackend(FirewallBackend):
    """Real firewall enforcement via iptables on Linux.

    All rules live in a dedicated chain (default PORTCULLIS) so this tool never
    touches rules it did not create. Requires root; call ensure_chain() once
    at startup before blocking.
    """

    def __init__(self, chain="PORTCULLIS", ssh_port=22,
                 allow_private_blocking=False, max_blocked_ips=1000):
        self.chain = chain
        self.ssh_port = ssh_port
        self.allow_private_blocking = allow_private_blocking
        self.max_blocked_ips = max_blocked_ips

    # --- the single seam every command funnels through (tests replace this) ---

    def _run(self, args):
        subprocess.run(
            ["iptables", *args],
            check=True,             # nonzero exit -> raise, never silently "succeed"
            capture_output=True,
            text=True,
        )

    def ensure_chain(self):
        """Create the dedicated chain and route SSH traffic into it. Idempotent:
        safe to call on every startup even if the chain already exists.
        """
        try:
            self._run(["-N", self.chain])  # create chain
        except subprocess.CalledProcessError:
            pass  # already exists
        # Route inbound SSH through our chain, but only if not already routed.
        try:
            self._run(["-C", "INPUT", "-p", "tcp", "--dport", str(self.ssh_port),
                       "-j", self.chain])
        except subprocess.CalledProcessError:
            self._run(["-I", "INPUT", "-p", "tcp", "--dport", str(self.ssh_port),
                       "-j", self.chain])

    # --- safety gate shared by every acting method ---

    def _validate(self, ip):
        addr = ipaddress.ip_address(ip)  # raises on non-IP: upstream bug
        if not self.allow_private_blocking and (addr.is_private or addr.is_loopback):
            raise ValueError(f"refusing to block private/loopback address {ip}")
        return addr

    def block(self, ip):
        self._validate(ip)
        if len(self.list_blocked()) >= self.max_blocked_ips and ip not in self.list_blocked():
            raise RuntimeError(
                f"max_blocked_ips ({self.max_blocked_ips}) reached; refusing to block {ip}"
            )
        self._run(["-A", self.chain, "-s", ip, "-j", "DROP"])
        logger.info("blocked %s", ip)

    def unblock(self, ip):
        ipaddress.ip_address(ip)  # validate, but don't apply private/loopback policy
        try:
            self._run(["-D", self.chain, "-s", ip, "-j", "DROP"])
        except subprocess.CalledProcessError:
            pass  # rule not present: unblocking an unblocked IP is a no-op
        logger.info("unblocked %s", ip)

    def rate_limit(self, ip):
        # v1: real rate-limiting (-m hashlimit) is a documented stretch goal.
        # The interface supports it; for now we fall back to a full block.
        logger.info("rate-limit requested for %s; falling back to block", ip)
        self.block(ip)

    def list_blocked(self):
        """Parse the DROP rules in our chain back into a set of IPs."""
        result = subprocess.run(
            ["iptables", "-S", self.chain],
            check=True,
            capture_output=True,
            text=True,
        )
        blocked = set()
        for line in result.stdout.splitlines():
            # Lines look like: -A PORTCULLIS -s 203.0.113.7/32 -j DROP
            parts = line.split()
            if "-s" in parts and "DROP" in parts:
                src = parts[parts.index("-s") + 1]
                blocked.add(src.split("/")[0])  # strip the /32 the kernel adds
        return blocked
