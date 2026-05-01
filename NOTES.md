# Nico — Project Notes

Multi-agent handoff doc. Cold-start agents read this first.

## Status

**Sprint 0.5a shipped on master.** CORS misconfiguration detection is in place. Current Codex branch `codex/verify-action-dashboard-polish` is validating the reusable Action on a real draft PR and polishing the static HTML dashboard from a live Juice Shop scan.

### Recent ship history

- **0.1 — v0.1 ship.** End-to-end pipeline confirmed against OWASP Juice Shop, 2026-05-01. Reproduced the Shannon-class auth-bypass-via-SQLi on `POST /rest/user/login` (decoded admin JWT in evidence). Sample report at `reports/2026-05-01T15-11-09-952Z/`.
- **0.2a — Baseline diff comparison.** Sandbox now runs a benign baseline alongside each exploit; `ExploitResult.evidence.diff` carries status/length/SQL-signal/timing deltas. Codex hardening pass fixed shell-quoting and heredoc expansion bugs.
- **0.2b — Auth/SSRF/IDOR templates.** Per-class prompt templates added to `prompts/`.
- **0.2c — OpenAPI ingestion.** CLI accepts `--openapi <spec>` as an alternative to `--source`. Orchestrator parses real request body params instead of synthesizing a generic body vector.
- **0.2 cleanup (Codex).** ESLint config added, vitest/vite bumped past advisories, `pnpm audit --audit-level moderate` clean.
- **0.3 — GitHub Actions CI + reusable Action.** Internal CI green on Node 20 + 22 (vitest 4 dropped Node 18 support). `.github/workflows/ci.yml` runs lint → typecheck → test → build → audit. `action.yml` composite Action: scan + sticky PR comment + artifact upload + severity gate. Example consumer workflow at `examples/workflows/nico-scan.yml`. **First-PR validation of the Action itself still open** before tagging.
- **0.4 — Static HTML dashboard.** Self-contained interactive `report.html` written alongside `report.md` and `report.json`. Filter by severity / vuln class, free-text search, expandable PoC blocks, severity-bucketed summary cards. CI green on Node 20 + 22.
- **0.5a — CORS detection.** Adds `cors` vuln class, prompt template, OpenAPI synthetic `Origin` header vectors, source analyzer prompt support, CORS comparator signal, heuristics, severity scoring, and tests.
- **Action smoke PR (Codex).** Draft PR branch `codex/verify-action-dashboard-polish` adds `.github/workflows/nico-action-smoke.yml`, which starts OWASP Juice Shop, writes a focused OpenAPI spec for `/rest/user/login`, runs the reusable Action from the PR checkout, posts the sticky PR comment, uploads the report artifact, and sets `fail-on-severity: high` so the severity gate is exercised against a real confirmed SQLi finding. Earlier runs caught Action packaging bugs: GitHub rejects `${{ ... }}` expressions inside input descriptions, and `setup-node` rejects the composite Action cache path when invoked via `uses: ./`.
- **Dashboard polish (Codex).** Live scan artifact at `reports/visual-check/2026-05-01T19-10-16-528Z/` confirmed 3 findings (1 critical auth, 2 high SQLi) and 3 inconclusive generation failures. `src/reporter/html.ts` now uses a lighter, more legible dashboard palette, responsive summary cards, better wrapping for long routes/error text, and a wider reasoning column for inconclusive records.
- **Exploit generation repair (Codex).** GitHub smoke run `25229336174` completed Action plumbing but produced 0 confirmed / 8 inconclusive because every generated auth script failed shell syntax validation. `generateExploit` now performs one self-repair retry with the Nico validation error fed back to the model before marking a vector as generation failure.
- **Linux sandbox loopback fix (Codex).** GitHub smoke run `25230004438` generated/reran SQLi exploits but confirmed 0 because `localhost:3000` inside the exploit container resolved to the sandbox container on Linux. `adaptForDocker` now rewrites `localhost` and `127.0.0.1` to `host.docker.internal` on all platforms; the Docker runner already maps that host alias with `--add-host=host.docker.internal:host-gateway`.
- **Configurable sandbox network (Codex).** GitHub runner networking did not expose the host alias to the sandbox reliably, so `NICO_DOCKER_NETWORK` can now override the sandbox network and `NICO_DOCKER_HOST_ALIAS` can override loopback rewriting. The Action smoke workflow creates a `nico-smoke` Docker network, runs Juice Shop as `nico-juice-shop`, publishes `localhost:3000` for preflight, and rewrites sandbox loopback to `nico-juice-shop:3000`. Default remains `bridge` + `host.docker.internal`.
- **Pinned Juice Shop smoke image (Codex).** The Action smoke workflow pins `bkimminich/juice-shop@sha256:a8139c141311c7f31fcf2e611125246928f703ee42827de33983fd9425d1b2f6`, matching the local image that confirmed the OpenAPI SQLi smoke scan.
- **Deterministic SQLi smoke mode (Codex).** `NICO_DETERMINISTIC_SQLI=1` makes SQLi exploit generation use a built-in curl proof instead of a fresh model script. The Action smoke workflow enables it so severity-gate validation depends on a live exploit result, not model-output variance.

### 0.5 still open

- Business logic detection.
- Multi-vector correlation / chained findings.
- Watch the Action smoke PR and confirm sticky PR comment + artifact upload + expected severity-gate behavior.

### Parked for paid-tier discussion

- **B — Hosted dashboard service.** Multi-run history, persistent storage, auth, organization-level findings index. The natural commercial surface beyond v0.4's static HTML. Revisit after v1.0 lands.

### Pre-tag checklist for v0.3

- [x] Internal CI green on master.
- [ ] Reusable Action exercised on a real PR (sticky comment + severity gate). Draft smoke PR branch: `codex/verify-action-dashboard-polish`.
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

- 115 tests passing across the suite.
- `pnpm lint`, `pnpm typecheck`, `pnpm test --run`, `pnpm build`, `pnpm audit --audit-level moderate` all clean (Codex review, 2026-05-01).
- No real Docker / API calls in CI — every test mocks the SDK + docker runner.

## Coordination

- Sonnet 4.6 is the primary builder. Codex handles review, debug, security audits, architecture review.
- Codex/Opus relief picks up when Sonnet is on break. Commit/push only when the user explicitly asks or the active handoff requests it.
- Multi-agent handoffs land here. Update on each significant state change.
