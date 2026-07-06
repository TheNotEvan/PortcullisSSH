import ipaddress
import json
import os
from datetime import datetime


class Whitelist:
    def __init__(self, entries=None):
        if entries is None:
            entries = []
        self._networks = []
        for entry in entries:
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid whitelist entry: {entry}") from exc

        # Non-negotiable defaults: a tool that can firewall its own loopback
        # has a self-destruct button.
        self._networks.append(ipaddress.ip_network("127.0.0.0/8"))
        self._networks.append(ipaddress.ip_network("::1/128"))

    def is_listed(self, ip) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False  # garbage fails closed: not whitelisted, never crash
        for net in self._networks:
            if addr in net:
                return True
        return False


class Blacklist:

    def __init__(self, path=None):
        self.path = path       # where to persist, None = memory-only
        self._records = {}     # ip -> {first_seen, last_seen, total_failures, times_blocked}
        self.load()

    def record_failure(self, ip, timestamp):
        record = self._records.get(ip)
        if record is None:
            self._records[ip] = {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "total_failures": 1,
                "times_blocked": 0,
            }
        else:
            record["last_seen"] = timestamp
            record["total_failures"] += 1
        self.save()

    def record_block(self, ip, timestamp=None):
        record = self._records.get(ip)
        if record is None:
            # Blocked without prior recorded failures (e.g. a manual block).
            now = timestamp or datetime.now()
            self._records[ip] = {
                "first_seen": now,
                "last_seen": now,
                "total_failures": 0,
                "times_blocked": 1,
            }
        else:
            record["times_blocked"] += 1
        self.save()

    def times_blocked(self, ip):
        record = self._records.get(ip)
        if record is None:
            return 0
        return record["times_blocked"]

    def save(self):
        if self.path is None:
            return
        # JSON can't hold datetimes: convert to ISO strings on the way out.
        serializable = {}
        for ip, record in self._records.items():
            serializable[ip] = {
                **record,
                "first_seen": record["first_seen"].isoformat(),
                "last_seen": record["last_seen"].isoformat(),
            }
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(serializable, f)
        os.replace(tmp, self.path)

    def load(self):
        if self.path is None:
            return
        try:
            with open(self.path, "r") as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return  # first run, or corrupt file: start with empty memory
        records = {}
        for ip, record in raw.items():
            records[ip] = {
                **record,
                "first_seen": datetime.fromisoformat(record["first_seen"]),
                "last_seen": datetime.fromisoformat(record["last_seen"]),
            }
        self._records = records
