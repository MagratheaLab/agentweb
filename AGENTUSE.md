# AGENTUSE

How an agent reads one published origin. Stop at the first miss.

1. Find the host in `catalog/INDEX.md`. No row means stop.
2. Open `origins/<origin-id>/BINDING.json`.
3. If the binding says `unbound`, stop. Do not follow `USE.md`.
4. Read `SCAN.json`, then `ADVISE.md`, `APPLY.md`, and `USE.md` when those files exist.
5. Trust the gate result and the snapshot hash. Do not refetch the origin to overrule a receipt.

`coverage` on a certificate is `pinned-corpus-only`.
