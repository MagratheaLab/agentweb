# CANON (frozen identifiers)

Packets pin a sha256 of this file. Do not redefine.

- `checklist` — v0 is `L1+L2` only. L3 and L4 are later packets.
- `llms.txt` — one H1, a summary, one relative `.md` link. An `http` or `https` link fails v0.
- `robots.txt` — present. `User-agent: *` must not `Disallow: /`, `Disallow: /llms.txt`, or the linked path.
- `origin-id` — packet id of the first merged scan. A and AAAA are not an origin.
- `dns-binding-hash` — hash of NS, CNAME, TXT `_agentweb`, and DS. SOA serial is a witness.
- `coverage` — the only allowed scope sentence is `pinned-corpus-only`.
- `world_claim` — `scan`, `keep`, `advise`, `apply`, `move`, `adversary`, `blocked`, `dead-end`. Not `lemma`.

English only in this file.
