"""CLI. Snapshot directories only. A URL is refused."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ready_gate.scan import build_scan, dumps, load_scan, same_verdict


def _snapshot(value: str) -> Path:
    path = Path(value)
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"snapshot is not a directory: {value}")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ready-gate")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_common(command: argparse.ArgumentParser, claim: str) -> None:
        command.add_argument("--snapshot", type=_snapshot)
        command.add_argument("--url", default="")
        command.add_argument("--origin-id", required=True)
        command.add_argument("--out", type=Path)
        command.add_argument("--world-claim", default=claim)

    scan = sub.add_parser("scan")
    add_common(scan, "scan")
    keep = sub.add_parser("keep")
    add_common(keep, "keep")
    keep.add_argument("--previous", type=Path, required=True)
    replay = sub.add_parser("replay")
    replay.add_argument("--snapshot", type=_snapshot)
    replay.add_argument("--url", default="")
    replay.add_argument("--expect", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.url or not args.snapshot:
        print("v0 reads snapshot bytes only", file=sys.stderr)
        return 2

    if args.cmd == "replay":
        expect = load_scan(args.expect)
        fresh = build_scan(
            args.snapshot,
            origin_id=str(expect.get("origin_id") or ""),
            world_claim=str(expect.get("world_claim") or "scan"),
        )
        if not same_verdict(fresh, expect):
            print("result=fail", file=sys.stderr)
            return 1
        print("result=pass")
        return 0

    previous = load_scan(args.previous) if args.cmd == "keep" else None
    scan_doc = build_scan(
        args.snapshot,
        origin_id=args.origin_id,
        world_claim=args.world_claim,
        previous=previous,
    )
    text = dumps(scan_doc)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    print(f"result={scan_doc['result']}", file=sys.stderr)
    return 0 if scan_doc["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
