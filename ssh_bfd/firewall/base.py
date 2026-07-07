from abc import ABC, abstractmethod


class FirewallBackend(ABC):
    """Contract for anything that can act as this tool's firewall.

    Implementations MUST validate the ip argument before acting on it:
    it is ultimately derived from attacker-influenced log lines.
    """

    @abstractmethod
    def block(self, ip: str) -> None:
        """Drop all traffic from this IP."""

    @abstractmethod
    def unblock(self, ip: str) -> None:
        """Remove the block for this IP. A no-op if it wasn't blocked."""

    @abstractmethod
    def rate_limit(self, ip: str) -> None:
        """Throttle this IP's connections (may fall back to block)."""

    @abstractmethod
    def list_blocked(self) -> set[str]:
        """Return the set of currently blocked IPs."""
