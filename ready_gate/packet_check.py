"""Replay the snapshot named by one packet. No network."""

from __future__ import annotations

import sys
from pathlib import Path

from ready_gate.scan import build_scan, load_scan, same_verdict


def _front_matter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        raise ValueError("packet has no front matter")
    end = text.find("\n---", 4)
    if end < 0:
        raise ValueError("packet front matter does not close")
    data: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if not line.strip() or line.startswith(" ") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def check_packet(root: Path, packet_id: str) -> str:
    path = root / "packets" / f"{packet_id}.md"
    if not path.is_file():
        raise ValueError(f"missing {path}")
    meta = _front_matter(path.read_text(encoding="utf-8"))
    if meta.get("world_judge") != "ready-gate":
        raise ValueError("world_judge must be ready-gate")
    snapshot = root / meta.get("snapshot", "")
    expect = root / meta.get("scan", "")
    if not snapshot.is_dir():
        raise ValueError("snapshot is not a directory")
    if not expect.is_file():
        raise ValueError("scan file is missing")
    fresh = build_scan(
        snapshot,
        origin_id=str(meta.get("id") or packet_id),
        world_claim=str(meta.get("world_claim") or "scan"),
    )
    pinned = load_scan(expect)
    if not same_verdict(fresh, pinned):
        raise ValueError("replay does not match SCAN.json")
    if fresh["result"] != "pass":
        raise ValueError(f"replay result is {fresh['result']}")
    return fresh["result"]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or not args[0].startswith("packet/P-"):
        print("usage: python -m ready_gate.packet_check packet/P-YYYYMMDD-xxxx", file=sys.stderr)
        return 2
    packet_id = args[0].split("/", 1)[1]
    try:
        result = check_packet(Path.cwd(), packet_id)
    except (OSError, ValueError) as exc:
        print(f"packet-replay fail {exc}", file=sys.stderr)
        return 1
    print(f"packet-replay {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
