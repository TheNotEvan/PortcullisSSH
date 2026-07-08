import pytest

from portcullis.firewall import get_backend
from portcullis.firewall.base import FirewallBackend
from portcullis.firewall.dryrun import DryRunBackend
from portcullis.firewall.iptables import IptablesBackend


# --- the ABC contract ---

def test_cannot_instantiate_abstract_base():
    with pytest.raises(TypeError):
        FirewallBackend()


def test_incomplete_subclass_cannot_instantiate():
    class Half(FirewallBackend):
        def block(self, ip):
            pass

    with pytest.raises(TypeError):
        Half()


# --- dry-run backend ---

def test_block_records_ip():
    fw = DryRunBackend()
    fw.block("203.0.113.7")
    assert fw.list_blocked() == {"203.0.113.7"}


def test_unblock_removes_ip():
    fw = DryRunBackend()
    fw.block("203.0.113.7")
    fw.unblock("203.0.113.7")
    assert fw.list_blocked() == set()


def test_unblock_unknown_ip_is_noop():
    fw = DryRunBackend()
    fw.unblock("203.0.113.7")  # must not raise
    assert fw.list_blocked() == set()


def test_block_rejects_non_ip():
    fw = DryRunBackend()
    with pytest.raises(ValueError):
        fw.block("not-an-ip")


def test_list_blocked_returns_a_copy():
    fw = DryRunBackend()
    fw.block("203.0.113.7")
    snapshot = fw.list_blocked()
    snapshot.add("198.51.100.1")  # mutating the copy...
    assert fw.list_blocked() == {"203.0.113.7"}  # ...must not affect internals


# --- factory ---

def test_get_backend_dryrun():
    assert isinstance(get_backend("dryrun"), DryRunBackend)


def test_get_backend_iptables_with_options():
    fw = get_backend("iptables", chain="TEST_CHAIN", ssh_port=2222)
    assert isinstance(fw, IptablesBackend)
    assert fw.chain == "TEST_CHAIN"
    assert fw.ssh_port == 2222


def test_get_backend_unknown_raises():
    with pytest.raises(ValueError, match="unknown firewall backend"):
        get_backend("nftables")


# --- iptables command construction (no real iptables involved) ---

def record_commands(backend, monkeypatch):
    commands = []
    monkeypatch.setattr(backend, "_run", lambda args: commands.append(args))
    return commands


def test_iptables_block_builds_correct_command(monkeypatch):
    fw = IptablesBackend()
    commands = record_commands(fw, monkeypatch)
    # list_blocked is called inside block() for the cap check; stub it out.
    monkeypatch.setattr(fw, "list_blocked", lambda: set())
    # NB: 203.0.113.x is a reserved TEST-NET range that ipaddress treats as
    # non-global, so use a genuinely public address here.
    fw.block("45.33.32.156")
    assert ["-A", "PORTCULLIS", "-s", "45.33.32.156", "-j", "DROP"] in commands


def test_iptables_unblock_builds_correct_command(monkeypatch):
    fw = IptablesBackend()
    commands = record_commands(fw, monkeypatch)
    fw.unblock("203.0.113.7")
    assert ["-D", "PORTCULLIS", "-s", "203.0.113.7", "-j", "DROP"] in commands


def test_iptables_refuses_private_ip_by_default(monkeypatch):
    fw = IptablesBackend()
    commands = record_commands(fw, monkeypatch)
    monkeypatch.setattr(fw, "list_blocked", lambda: set())
    with pytest.raises(ValueError, match="private/loopback"):
        fw.block("192.168.1.50")
    assert commands == []  # nothing was run


def test_iptables_allows_private_ip_when_configured(monkeypatch):
    fw = IptablesBackend(allow_private_blocking=True)
    commands = record_commands(fw, monkeypatch)
    monkeypatch.setattr(fw, "list_blocked", lambda: set())
    fw.block("192.168.1.50")
    assert ["-A", "PORTCULLIS", "-s", "192.168.1.50", "-j", "DROP"] in commands


def test_iptables_rejects_non_ip(monkeypatch):
    fw = IptablesBackend()
    record_commands(fw, monkeypatch)
    with pytest.raises(ValueError):
        fw.block("1.2.3.4; rm -rf /")  # injection attempt: dies at validation


def test_iptables_max_blocked_cap(monkeypatch):
    fw = IptablesBackend(max_blocked_ips=2)
    commands = record_commands(fw, monkeypatch)
    monkeypatch.setattr(fw, "list_blocked", lambda: {"1.1.1.1", "2.2.2.2"})
    with pytest.raises(RuntimeError, match="max_blocked_ips"):
        fw.block("45.33.32.156")
    assert commands == []
