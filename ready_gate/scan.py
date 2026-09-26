"""HTTP checklist L1+L2 over a snapshot directory."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

CHECK_IDS = ("h1", "summary", "md_link", "md_200", "robots")
_H1 = re.compile(r"^# [^#\s].*")
_HEADING = re.compile(r"^#{1,6} ")
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def snapshot_hash(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and p.name != "SCAN.json" and ".git" not in p.parts
    )
    for path in files:
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")


def _links(text: str) -> list[str]:
    return [m.group(1).strip() for m in _LINK.finditer(text)]


def _resolve(root: Path, target: str) -> Path | None:
    path = target.split("#", 1)[0]
    if not path or path.startswith(("http://", "https://", "//")):
        return None
    if "\\" in path or path.startswith("/"):
        return None
    candidate = (root / path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _summary_ok(lines: list[str], start: int) -> bool:
    body: list[str] = []
    for line in lines[start + 1 :]:
        if _HEADING.match(line):
            break
        body.append(line)
    quote = [ln[1:].strip() for ln in body if ln.startswith(">")]
    if any(quote):
        return True
    paragraph: list[str] = []
    for line in body:
        if not line.strip():
            if paragraph:
                break
            continue
        paragraph.append(line.strip())
    return len(" ".join(paragraph)) >= 40


def _robots_ok(text: str, linked: list[str]) -> bool:
    if not text.strip():
        return False
    forbidden = {"/", "/llms.txt"}
    for rel in linked:
        forbidden.add("/" + rel.lstrip("/"))
    groups: list[tuple[list[str], list[tuple[str, str]]]] = []
    agents: list[str] = []
    rules: list[tuple[str, str]] = []

    def flush() -> None:
        nonlocal agents, rules
        if agents or rules:
            groups.append((agents, rules))
        agents, rules = [], []

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            flush()
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip().lower(), val.strip()
        if key == "user-agent":
            if rules:
                flush()
            agents.append(val.lower())
        else:
            rules.append((key, val))
    flush()
    for group_agents, group_rules in groups:
        if group_agents and "*" not in group_agents:
            continue
        for key, val in group_rules:
            if key == "disallow" and val in forbidden:
                return False
    return True


def evaluate(root: Path) -> dict[str, bool]:
    llms_path = root / "llms.txt"
    checks = {name: False for name in CHECK_IDS}
    if not llms_path.is_file():
        return checks
    text = _read(llms_path)
    lines = text.splitlines()
    idx = next((i for i, line in enumerate(lines) if line.strip()), None)
    if idx is None:
        return checks
    first = lines[idx].strip()
    checks["h1"] = bool(_H1.match(first))
    checks["summary"] = checks["h1"] and _summary_ok(lines, idx)
    targets = _links(text)
    http = any(t.startswith(("http://", "https://", "//")) for t in targets)
    relative = []
    for target in targets:
        resolved = _resolve(root, target)
        if resolved is not None and target.split("#", 1)[0].endswith(".md"):
            relative.append(target.split("#", 1)[0])
    checks["md_link"] = bool(relative) and not http
    if relative:
        dest = _resolve(root, relative[0])
        checks["md_200"] = bool(
            dest and dest.is_file() and dest.stat().st_size > 0
        )
    robots = root / "robots.txt"
    linked = relative[:1]
    checks["robots"] = robots.is_file() and _robots_ok(_read(robots), linked)
    return checks


def build_scan(
    root: Path,
    *,
    origin_id: str,
    world_claim: str,
    previous: dict | None = None,
) -> dict:
    checks = evaluate(root)
    passed = all(checks[name] for name in CHECK_IDS)
    if passed:
        result = "pass"
    elif previous and previous.get("result") == "pass":
        result = "drift"
    else:
        result = "fail"
    return {
        "origin_id": origin_id,
        "world_claim": world_claim,
        "checklist": "L1+L2",
        "coverage": "pinned-corpus-only",
        "snapshot_hash": snapshot_hash(root),
        "result": result,
        "checks": [{"id": name, "pass": checks[name]} for name in CHECK_IDS],
    }


def dumps(scan: dict) -> str:
    return json.dumps(scan, indent=2) + "\n"


def load_scan(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def same_verdict(left: dict, right: dict) -> bool:
    keys = ("result", "snapshot_hash", "checklist", "coverage", "checks")
    return all(left.get(key) == right.get(key) for key in keys)
