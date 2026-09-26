"""F0 pass, F1 fail, F2 drift, replay, and cached DNS binding."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ready_gate.dnsbind import DnsError, binding_hash, judge, load_cache
from ready_gate.__main__ import main
from ready_gate.scan import build_scan, evaluate, same_verdict

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"


class ChecklistTests(unittest.TestCase):
    def test_f0_pass(self) -> None:
        scan = build_scan(FIX / "f0", origin_id="P-f0", world_claim="scan")
        self.assertEqual(scan["result"], "pass")
        self.assertEqual(scan["coverage"], "pinned-corpus-only")
        self.assertTrue(all(item["pass"] for item in scan["checks"]))
        self.assertEqual(main(["scan", "--snapshot", str(FIX / "f0"), "--origin-id", "P-f0"]), 0)

    def test_f1_false_llms_is_fail(self) -> None:
        scan = build_scan(FIX / "f1", origin_id="P-f1", world_claim="scan")
        self.assertEqual(scan["result"], "fail")
        flags = {item["id"]: item["pass"] for item in scan["checks"]}
        self.assertFalse(flags["h1"])
        self.assertFalse(flags["md_200"])
        self.assertNotEqual(
            main(["scan", "--snapshot", str(FIX / "f1"), "--origin-id", "P-f1"]), 0
        )

    def test_missing_h1_alone_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "llms.txt").write_text(
                "A paragraph without a heading that is certainly longer than forty characters.\n\n"
                "- [Page](page.md)\n",
                encoding="utf-8",
            )
            (root / "page.md").write_text("# Page\n\nHere.\n", encoding="utf-8")
            (root / "robots.txt").write_text("User-agent: *\nAllow: /\n", encoding="utf-8")
            flags = evaluate(root)
            self.assertFalse(flags["h1"])
            self.assertFalse(flags["summary"])

    def test_http_link_fails_v0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "llms.txt").write_text(
                "# Origin\n\nThis summary is long enough to satisfy the paragraph rule.\n\n"
                "- [Page](https://example.com/page.md)\n",
                encoding="utf-8",
            )
            (root / "robots.txt").write_text("User-agent: *\nAllow: /\n", encoding="utf-8")
            self.assertFalse(evaluate(root)["md_link"])

    def test_f2_keep_drift(self) -> None:
        previous = build_scan(FIX / "f2" / "snap1", origin_id="P-f2", world_claim="scan")
        self.assertEqual(previous["result"], "pass")
        with tempfile.TemporaryDirectory() as tmp:
            prev = Path(tmp) / "previous.json"
            prev.write_text(json.dumps(previous), encoding="utf-8")
            code = main(
                [
                    "keep",
                    "--snapshot",
                    str(FIX / "f2" / "snap2"),
                    "--previous",
                    str(prev),
                    "--origin-id",
                    "P-f2",
                ]
            )
        self.assertEqual(code, 1)
        drifted = build_scan(
            FIX / "f2" / "snap2",
            origin_id="P-f2",
            world_claim="keep",
            previous=previous,
        )
        self.assertEqual(drifted["result"], "drift")

    def test_replay_matches_without_network(self) -> None:
        scan = build_scan(FIX / "f0", origin_id="P-f0", world_claim="scan")
        with tempfile.TemporaryDirectory() as tmp:
            expect = Path(tmp) / "SCAN.json"
            expect.write_text(json.dumps(scan), encoding="utf-8")
            again = build_scan(FIX / "f0", origin_id="P-f0", world_claim="scan")
            self.assertTrue(same_verdict(scan, again))
            self.assertEqual(
                main(["replay", "--snapshot", str(FIX / "f0"), "--expect", str(expect)]),
                0,
            )

    def test_url_is_refused(self) -> None:
        self.assertEqual(main(["scan", "--url", "https://example.com", "--origin-id", "P"]), 2)

    def test_other_agent_disallow_does_not_fail_star(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "llms.txt").write_text((FIX / "f0" / "llms.txt").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "page.md").write_text((FIX / "f0" / "page.md").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "robots.txt").write_text(
                "User-agent: googlebot\nDisallow: /\n\nUser-agent: *\nAllow: /\n",
                encoding="utf-8",
            )
            self.assertTrue(evaluate(root)["robots"])

    def test_disallow_root_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "llms.txt").write_text((FIX / "f0" / "llms.txt").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "page.md").write_text((FIX / "f0" / "page.md").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "robots.txt").write_text("User-agent: *\nDisallow: /\n", encoding="utf-8")
            self.assertFalse(evaluate(root)["robots"])


class DnsTests(unittest.TestCase):
    def test_address_is_not_identity(self) -> None:
        data = load_cache(FIX / "dns" / "unsigned.json")
        first = binding_hash(data)
        changed = json.loads(json.dumps(data))
        changed["A"] = ["203.0.113.9"]
        self.assertEqual(first, binding_hash(changed))

    def test_ns_change_without_serial_fails(self) -> None:
        current = load_cache(FIX / "dns" / "unsigned.json")
        previous = json.loads(json.dumps(current))
        current["rrsets"]["NS"] = ["ns9.example.net."]
        verdict = judge(previous, current, move=False)
        self.assertEqual(verdict["result"], "fail")

    def test_serial_advance_same_hash_is_not_a_move(self) -> None:
        current = load_cache(FIX / "dns" / "unsigned.json")
        previous = json.loads(json.dumps(current))
        current["soa_serial"] = previous["soa_serial"] + 1
        verdict = judge(previous, current, move=False)
        self.assertEqual(verdict["result"], "pass")
        self.assertFalse(verdict["move"])

    def test_unsigned_scan_passes_and_move_requires_dnssec(self) -> None:
        current = load_cache(FIX / "dns" / "unsigned.json")
        scan = judge(None, current, move=False)
        self.assertEqual(scan["result"], "pass")
        moved = json.loads(json.dumps(current))
        moved["soa_serial"] = current["soa_serial"] + 1
        moved["rrsets"]["TXT:_agentweb"] = ["origin=other"]
        self.assertEqual(judge(current, moved, move=True)["result"], "fail")
        moved["dnssec"] = "valid"
        self.assertEqual(judge(current, moved, move=True)["result"], "pass")
        self.assertTrue(judge(current, moved, move=True)["move"])

    def test_html_is_not_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zone.html"
            path.write_text("<html><body>ns1</body></html>", encoding="utf-8")
            with self.assertRaises(DnsError):
                load_cache(path)


if __name__ == "__main__":
    unittest.main()
