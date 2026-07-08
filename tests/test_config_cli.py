import os

import pytest

from ssh_bfd.cli import main
from ssh_bfd.config import Config, ConfigError, load_config

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
ATTACK_LOG = os.path.join(FIXTURES, "attack_sample.log")


def write_config(tmp_path, body):
    path = tmp_path / "config.yaml"
    path.write_text(body)
    return str(path)


# --- config loading ---

def test_defaults_need_no_yaml():
    cfg = Config()
    assert cfg.firewall.backend == "dryrun"
    assert cfg.detection.block_threshold == 8


def test_load_minimal_config(tmp_path):
    path = write_config(tmp_path, "log_path: /tmp/auth.log\npoll_interval: 2.0\n")
    cfg = load_config(path)
    assert cfg.log_path == "/tmp/auth.log"
    assert cfg.poll_interval == 2.0
    # unspecified sections fall back to defaults
    assert cfg.detection.block_threshold == 8


def test_nested_override(tmp_path):
    path = write_config(tmp_path, "detection:\n  block_threshold: 20\n")
    cfg = load_config(path)
    assert cfg.detection.block_threshold == 20


def test_derived_paths_use_state_dir(tmp_path):
    path = write_config(tmp_path, "state_dir: /var/lib/xyz\n")
    cfg = load_config(path)
    assert cfg.db_path == os.path.join("/var/lib/xyz", "audit.db")


def test_unknown_key_rejected(tmp_path):
    path = write_config(tmp_path, "detection:\n  blck_threshold: 20\n")  # typo
    with pytest.raises(ConfigError, match="unknown key"):
        load_config(path)


def test_threshold_ordering_validated(tmp_path):
    path = write_config(tmp_path, "detection:\n  alert_threshold: 9\n  block_threshold: 3\n")
    with pytest.raises(ConfigError, match="alert <= rate_limit <= block"):
        load_config(path)


def test_bad_whitelist_rejected(tmp_path):
    path = write_config(tmp_path, "whitelist:\n  - 999.999.0.0/8\n")
    with pytest.raises(ConfigError, match="whitelist"):
        load_config(path)


def test_slack_enabled_without_url_rejected(tmp_path):
    path = write_config(tmp_path, "alerts:\n  slack:\n    enabled: true\n")
    with pytest.raises(ConfigError, match="webhook_url"):
        load_config(path)


# --- CLI end to end ---

def base_config(tmp_path):
    return write_config(
        tmp_path,
        f"log_path: {ATTACK_LOG}\n"
        f"state_dir: {tmp_path.as_posix()}/state\n"
        "detection:\n  window_seconds: 600\n",
    )


def test_test_config_command(tmp_path, capsys):
    (tmp_path / "state").mkdir()
    main(["--config", base_config(tmp_path), "test-config"])
    assert "config OK" in capsys.readouterr().out


def test_replay_command_detects_attacker(tmp_path, capsys):
    (tmp_path / "state").mkdir()
    main(["--config", base_config(tmp_path), "replay", ATTACK_LOG])
    out = capsys.readouterr().out
    assert "45.33.32.156" in out          # the attacker surfaces
    assert "198.51.100.7" not in out      # the one-failure legit user does not


def test_run_once_processes_newly_appended_lines(tmp_path, capsys):
    # run defaults to start_at_end: a fresh watcher ignores existing history and
    # only reacts to lines that arrive AFTER it starts. Prove that behavior.
    (tmp_path / "state").mkdir()
    log = tmp_path / "auth.log"
    log.write_text("")  # empty to begin with
    cfg = write_config(
        tmp_path,
        f"log_path: {log.as_posix()}\n"
        f"state_dir: {tmp_path.as_posix()}/state\n",
    )

    main(["--config", cfg, "run", "--dry-run", "--once"])  # establishes + persists offset
    with open(ATTACK_LOG) as f:
        log.write_text(f.read())  # attack traffic arrives after the first watcher stopped
    main(["--config", cfg, "run", "--dry-run", "--once"])  # a restart resumes and sees it

    capsys.readouterr()  # clear
    main(["--config", cfg, "report"])
    assert "45.33.32.156" in capsys.readouterr().out


def test_invalid_config_exits_nonzero(tmp_path):
    bad = write_config(tmp_path, "poll_interval: -1\n")
    with pytest.raises(SystemExit) as exc:
        main(["--config", bad, "test-config"])
    assert exc.value.code == 2
