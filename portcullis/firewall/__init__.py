"""Firewall backend package and factory."""

from portcullis.firewall.base import FirewallBackend
from portcullis.firewall.dryrun import DryRunBackend
from portcullis.firewall.iptables import IptablesBackend

_BACKENDS = {
    "dryrun": DryRunBackend,
    "iptables": IptablesBackend,
}


def get_backend(name, **options):
    """Build a firewall backend by config name, e.g. get_backend("dryrun").

    Extra keyword options are passed to the backend's constructor (the iptables
    backend accepts chain, ssh_port, allow_private_blocking, max_blocked_ips).
    """
    try:
        backend_cls = _BACKENDS[name]
    except KeyError:
        raise ValueError(
            f"unknown firewall backend {name!r}; choose one of {sorted(_BACKENDS)}"
        ) from None
    if name == "dryrun":
        return backend_cls()  # dry-run takes no options
    return backend_cls(**options)
