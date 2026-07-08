"""Configuration loading and validation.

The whole tool is driven by one YAML file, parsed here into validated dataclasses
so the rest of the code works with typed objects and a bad config fails loudly at
startup rather than mid-attack.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field, fields


class ConfigError(ValueError):
    """Raised when the config file is malformed or fails validation."""


@dataclass
class DetectionConfig:
    window_seconds: int = 600
    alert_threshold: float = 3
    rate_limit_threshold: float = 5
    block_threshold: float = 8
    invalid_user_weight: float = 2
    distinct_users_threshold: int = 4


@dataclass
class EscalationConfig:
    base_block_seconds: int = 86400        # 24h
    block_multiplier: float = 2.0
    max_block_seconds: int = 2592000       # 30d cap


@dataclass
class FirewallConfig:
    backend: str = "dryrun"                # dryrun | iptables
    allow_private_blocking: bool = False
    max_blocked_ips: int = 1000
    chain: str = "PORTCULLIS"
    ssh_port: int = 22


@dataclass
class SlackConfig:
    enabled: bool = False
    webhook_url: str = ""


@dataclass
class AlertConfig:
    syslog_enabled: bool = True
    throttle_seconds: int = 900
    slack: SlackConfig = field(default_factory=SlackConfig)


@dataclass
class Config:
    log_path: str = "/var/log/auth.log"
    poll_interval: float = 1.0
    state_dir: str = "/var/lib/portcullis"
    whitelist: list = field(default_factory=list)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    escalation: EscalationConfig = field(default_factory=EscalationConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)

    # Derived file paths under state_dir.
    @property
    def monitor_state_path(self):
        return os.path.join(self.state_dir, "monitor_state.json")

    @property
    def blacklist_path(self):
        return os.path.join(self.state_dir, "blacklist.json")

    @property
    def block_state_path(self):
        return os.path.join(self.state_dir, "blocks.json")

    @property
    def db_path(self):
        return os.path.join(self.state_dir, "audit.db")


def _build(cls, data):
    """Build a flat dataclass from a dict, rejecting unknown keys."""
    if not isinstance(data, dict):
        raise ConfigError(f"expected a mapping for {cls.__name__}")
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown key(s) in {cls.__name__}: {', '.join(sorted(unknown))}")
    return cls(**data)


def load_config(path):
    """Load and validate a YAML config file into a Config object."""
    import yaml  # imported here so default Config() works without PyYAML

    if not os.path.exists(path):
        raise ConfigError(f"config file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    nested = ("detection", "escalation", "firewall", "alerts")
    cfg = Config(**{k: v for k, v in raw.items() if k not in nested})
    if "detection" in raw:
        cfg.detection = _build(DetectionConfig, raw["detection"])
    if "escalation" in raw:
        cfg.escalation = _build(EscalationConfig, raw["escalation"])
    if "firewall" in raw:
        cfg.firewall = _build(FirewallConfig, raw["firewall"])
    if "alerts" in raw:
        alerts_raw = dict(raw["alerts"])
        slack_raw = alerts_raw.pop("slack", None)
        cfg.alerts = _build(AlertConfig, alerts_raw)
        if slack_raw is not None:
            cfg.alerts.slack = _build(SlackConfig, slack_raw)

    validate(cfg)
    return cfg


def validate(cfg):
    """Sanity-check a Config; raise ConfigError on the first problem found."""
    d = cfg.detection
    if not (d.alert_threshold <= d.rate_limit_threshold <= d.block_threshold):
        raise ConfigError(
            "thresholds must satisfy alert <= rate_limit <= block"
        )
    if d.window_seconds <= 0:
        raise ConfigError("detection.window_seconds must be positive")
    if cfg.poll_interval <= 0:
        raise ConfigError("poll_interval must be positive")
    if cfg.firewall.backend not in ("dryrun", "iptables"):
        raise ConfigError(f"unknown firewall backend: {cfg.firewall.backend!r}")
    for entry in cfg.whitelist:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ConfigError(f"invalid whitelist entry {entry!r}: {exc}") from exc
    if cfg.alerts.slack.enabled and not cfg.alerts.slack.webhook_url:
        raise ConfigError("alerts.slack.enabled is true but webhook_url is empty")
