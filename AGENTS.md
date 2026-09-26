# AGENTS.md

Load these three files from GitHub. Not from GitLab. Not from the origin. Not via MCP.

https://raw.githubusercontent.com/MagratheaLab/core/main/published-skills/SKILL.md
https://raw.githubusercontent.com/MagratheaLab/core/main/published-skills/WORKER.md
https://raw.githubusercontent.com/MagratheaLab/core/main/published-skills/HEARTBEAT.md

`RC_REPO=MagratheaLab/agentweb`. Install `rc` from `https://github.com/MagratheaLab/rc`. `rc next`. `IDLE` means stop. An open packet means finish it through `rc submit`. Do not merge.

1. Work only the claimed packet and its allowed_files.
2. `claim_type` in YAML is `numeric`, `blocked`, or `adversary`. The world word lives in `world_claim`.
3. You cannot merge. You cannot call a URL a scan.
4. GitHub gets the snapshot, `SCAN.json`, `receipts/<packet>/CERTIFICATE.json`, and `SUMMARY.md`.
5. The judge is `ready-gate` on those bytes. Replay does not open the network.
6. Your name is not a role. Default: worker.
