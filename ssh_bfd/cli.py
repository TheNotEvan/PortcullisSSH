"""Command-line interface: ssh-bfd <subcommand>."""

import argparse
import logging
import sys

from ssh_bfd.app import Application, replay
from ssh_bfd.config import ConfigError, load_config

DEFAULT_CONFIG = "/etc/ssh-bfd/config.yaml"


def _load(args):
    try:
        return load_config(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        raise SystemExit(2)


def cmd_run(args):
    config = _load(args)
    app = Application(config, dry_run=args.dry_run)
    mode = "DRY-RUN" if args.dry_run else config.firewall.backend
    print(f"ssh-bfd watching {config.log_path} (firewall: {mode}); Ctrl-C to stop")
    try:
        app.run(once=args.once)
    except KeyboardInterrupt:
        print("\nstopping")


def cmd_status(args):
    config = _load(args)
    app = Application(config, dry_run=True)  # read-only view; don't touch firewall
    blocks = app.engine.blocked_ips()
    if not blocks:
        print("no active blocks")
        return
    print(f"{'IP':<20} {'STAGE':<12} EXPIRES")
    for ip, entry in blocks.items():
        expires = entry["expires_at"]
        print(f"{ip:<20} {entry['stage'].name:<12} {expires.isoformat() if expires else '-'}")


def cmd_block(args):
    config = _load(args)
    app = Application(config, dry_run=args.dry_run)
    app.engine.manual_block(args.ip)
    print(f"blocked {args.ip}")


def cmd_unblock(args):
    config = _load(args)
    app = Application(config, dry_run=args.dry_run)
    app.engine.manual_unblock(args.ip)
    print(f"unblocked {args.ip}")


def cmd_report(args):
    config = _load(args)
    app = Application(config, dry_run=True)
    print("Top attackers:")
    for ip, count, last in app.audit.top_attackers():
        print(f"  {ip:<20} {count:>5} detections  (last {last})")
    print("\nRecent actions:")
    for ts, ip, action, expires, operator in app.audit.recent_actions():
        print(f"  {ts}  {action:<11} {ip:<20} by {operator}")


def cmd_replay(args):
    config = _load(args)
    app = replay(config, args.logfile)
    print("Replay complete. Would-block summary:")
    for ip, count, last in app.audit.top_attackers():
        print(f"  {ip:<20} {count:>5} detections")


def cmd_test_config(args):
    config = _load(args)  # exits nonzero on error
    print(f"config OK: watching {config.log_path}, backend {config.firewall.backend}")


def build_parser():
    parser = argparse.ArgumentParser(prog="ssh-bfd", description="SSH brute force detector")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="path to config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="watch the log and respond")
    p_run.add_argument("--dry-run", action="store_true", help="never touch the real firewall")
    p_run.add_argument("--once", action="store_true", help="process available lines and exit")
    p_run.set_defaults(func=cmd_run)

    sub.add_parser("status", help="show active blocks").set_defaults(func=cmd_status)

    p_block = sub.add_parser("block", help="manually block an IP")
    p_block.add_argument("ip")
    p_block.add_argument("--dry-run", action="store_true")
    p_block.set_defaults(func=cmd_block)

    p_unblock = sub.add_parser("unblock", help="manually unblock an IP")
    p_unblock.add_argument("ip")
    p_unblock.add_argument("--dry-run", action="store_true")
    p_unblock.set_defaults(func=cmd_unblock)

    sub.add_parser("report", help="attack/action summary").set_defaults(func=cmd_report)

    p_replay = sub.add_parser("replay", help="run the detector over a static log file")
    p_replay.add_argument("logfile")
    p_replay.set_defaults(func=cmd_replay)

    sub.add_parser("test-config", help="validate the config file").set_defaults(func=cmd_test_config)
    return parser


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
