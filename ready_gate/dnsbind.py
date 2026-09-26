"""DNS identity over cached RRsets. No resolver and no live query."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

BINDING_KEYS = ("NS", "CNAME", "TXT:_agentweb", "DS")


class DnsError(ValueError):
    pass


def load_cache(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip().lower()
    if stripped.startswith("<!doctype html") or stripped.startswith("<html"):
        raise DnsError("html is not dns evidence")
    data = json.loads(text)
    if not isinstance(data, dict) or "rrsets" not in data:
        raise DnsError("dns cache must be a json object with rrsets")
    return data


def binding_hash(data: dict) -> str:
    rrsets = data.get("rrsets") or {}
    body = {
        key: sorted(str(item) for item in (rrsets.get(key) or []))
        for key in BINDING_KEYS
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def judge(previous: dict | None, current: dict, *, move: bool) -> dict:
    digest = binding_hash(current)
    serial = int(current.get("soa_serial") or 0)
    prev_serial = int((previous or {}).get("soa_serial") or 0)
    prev_hash = binding_hash(previous) if previous else None
    dnssec = str(current.get("dnssec") or "unsigned")
    hash_changed = prev_hash is not None and digest != prev_hash
    serial_up = previous is not None and serial > prev_serial
    errors: list[str] = []
    if hash_changed and not serial_up:
        errors.append("hash changed without soa serial advance")
    is_move = bool(hash_changed and serial_up)
    if move and dnssec != "valid":
        errors.append("dns move requires dnssec valid")
    if move and not is_move and not errors:
        errors.append("move packet has no dns binding change")
    return {
        "dns-binding-hash": digest,
        "soa_serial": serial,
        "dnssec": dnssec,
        "move": is_move,
        "result": "fail" if errors else "pass",
        "errors": errors,
    }
