# Nico — Project Notes

Multi-agent handoff doc. Cold-start agents read this first.

## Status

**Sprint 0.4 in progress.** Self-contained interactive HTML dashboard added to the reporter — `report.html` written alongside `report.md` and `report.json`. Filter by severity / vuln class, free-text search, expandable PoC blocks, severity-bucketed summary cards.

### Recent ship history

- **0.1 — v0.1 ship.** End-to-end pipeline confirmed against OWASP Juice Shop, 2026-05-01. Reproduced the Shannon-class auth-bypass-via-SQLi on `POST /rest/user/login` (decoded admin JWT in evidence). Sample report at `reports/2026-05-01T15-11-09-952Z/`.
- **0.2a — Baseline diff comparison.** Sandbox now runs a benign baseline alongside each exploit; `ExploitResult.evidence.diff` carries status/length/SQL-signal/timing deltas. Codex hardening pass fixed shell-quoting and heredoc expansion bugs.
- **0.2b — Auth/SSRF/IDOR templates.** Per-class prompt templates added to `prompts/`.
- **0.2c — OpenAPI ingestion.** CLI accepts `--openapi <spec>` as an alternative to `--source`. Orchestrator parses real request body params instead of synthesizing a generic body vector.
- **0.2 cleanup (Codex).** ESLint config added, vitest/vite bumped past advisories, `pnpm audit --audit-level moderate` clean.
- **0.3 — GitHub Actions CI + reusable Action.** Internal CI green on Node 20 + 22 (vitest 4 dropped Node 18 support). `.github/workflows/ci.yml` runs lint → typecheck → test → build → audit. `action.yml` composite Action: scan + sticky PR comment + artifact upload + severity gate. Example consumer workflow at `examples/workflows/nico-scan.yml`. **First-PR validation of the Action itself still open** before tagging.

### 0.4 still open

- First green CI run with the new HTML output (verifying via push).
- Visual polish pass once a real Juice Shop scan generates an HTML report — the only thing tested today is structure, not aesthetics.

### Parked for paid-tier discussion

- **B — Hosted dashboard service.** Multi-run history, persistent storage, auth, organization-level findings index. The natural commercial surface beyond v0.4's static HTML. Revisit after v1.0 lands.

### Pre-tag checklist for v0.3

- [x] Internal CI green on master.
- [ ] Reusable Action exercised on a real PR (sticky comment + severity gate).
- [ ] Tag `v0.3` (and update README example to use that tag instead of `@v0.1`).

## Architecture decisions on file

- TypeScript throughout, ESM, pnpm.
- Claude Sonnet (claude-sonnet-4-6) for orchestrator + exploit generator + judge — all three use prompt caching on the system prompt.
- v0.1+ ships single-vendor on Claude. OpenAI exploit generator (originally GPT-5.5) deferred. `NICO_EXPLOIT_MODEL` env overrides the model.
- Docker sandbox is least-privilege: `--cap-drop=ALL`, `--security-opt=no-new-privileges`, read-only root, tmpfs scratch, mem/CPU/PID caps, `host.docker.internal` rewrite for non-Linux hosts.
- Generated scripts pass syntax check (`bash -n` / `node --check`) plus a policy scan (no docker access, no package installs, no credential reads) before they hit a container.
- Validator is two-stage: rule-based heuristics + Claude judge. Baseline diff (0.2a) feeds both: heuristics gate on `confirmedByDiff`, judge gets diff summary in its prompt.
- Reporter writes to `<outputDir>/<ISO-timestamp>/{report.md,report.json,evidence/}`. Severity is CVSS-lite (bucket + 0–10 score + rationale string).

## Test posture

- 103 tests passing across the suite.
- `pnpm lint`, `pnpm typecheck`, `pnpm test --run`, `pnpm build`, `pnpm audit --audit-level moderate` all clean (Codex review, 2026-05-01).
- No real Docker / API calls in CI — every test mocks the SDK + docker runner.

## Coordination

- Sonnet 4.6 is the primary builder. Codex handles review, debug, security audits, architecture review.
- This Opus 4.7 instance is relief — picks up when Sonnet is on break. Does not commit; stages changes for user review.
- Multi-agent handoffs land here. Update on each significant state change.
