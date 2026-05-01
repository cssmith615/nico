# Nico — Project Notes

Multi-agent handoff doc. Cold-start agents read this first.

## Status

**Sprint 6 — live pipeline confirmed end-to-end against OWASP Juice Shop, 2026-05-01.**

```
CLI → preflight → orchestrator (Claude) → exploits (Claude) → sandbox (Docker)
   → validation (heuristics + Claude judge) → reporter (md + json)
```

Reproduced the Shannon-class auth-bypass-via-SQLi on `POST /rest/user/login` (email field). Sandbox returned a valid admin JWT (decoded: `admin@juice-sh.op` / role: admin). Judge confirmed via response inspection. Report at `reports/2026-05-01T15-11-09-952Z/`.

**v0.1 ship is unblocked.** User owns final commit + git tag.

## Sprint 6 — what's done

- `src/cli/preflight.ts` — env keys, Docker daemon, source path, target reachability checks. Wired into CLI before any spend.
- `sample-targets/juice-shop.json` — config for reproducing Shannon's findings.
- `README.md` — full usage, Juice Shop quickstart, sample report excerpt, sandbox containment notes.
- `tests/e2e.test.ts` — mocked-API smoke test exercising orchestrator → exploits → sandbox → validation → reporter; catches wiring regressions without spend.

## Sprint 6 — open

1. **Live scan against Juice Shop** — needs user to spin up Juice Shop (`docker run -p 3000:3000 bkimminich/juice-shop`), have `.env` populated, then run the CLI. Expected confirmed findings: SQLi on `POST /rest/user/login` via `email`, plus the auth bypass downstream of it.
2. **Prompt tuning** — only meaningful after a live run; tune based on actual false positives / misses, not speculation.
3. **v0.1 tag** — owned by user. Stage everything for review first.

## Architecture decisions on file

- TypeScript throughout, ESM, pnpm.
- Claude Sonnet (claude-sonnet-4-6) for orchestrator + exploit generator + judge — all three use prompt caching on the system prompt.
- v0.1 ships single-vendor on Claude. OpenAI exploit generator (originally GPT-5.5) is deferred — code in `src/exploit/generator.ts` was pivoted to Anthropic to ship now without a second key. Exploit model override via `NICO_EXPLOIT_MODEL` env. Per-class prompt templates live in `prompts/`.
- Docker sandbox is least-privilege: `--cap-drop=ALL`, `--security-opt=no-new-privileges`, read-only root, tmpfs scratch, mem/CPU/PID caps, `host.docker.internal` rewrite for non-Linux hosts.
- Generated scripts pass syntax check (`bash -n` / `node --check`) plus a policy scan (no docker access, no package installs, no credential reads) before they hit a container.
- Validator is two-stage: rule-based heuristics catch obvious confirmations and false positives without an API call; only ambiguous cases hit the Claude judge.
- Reporter writes to `<outputDir>/<ISO-timestamp>/{report.md,report.json,evidence/}`. Severity is CVSS-lite (bucket + 0–10 score + rationale string).

## Test posture

- 60 tests passing across 6 files (5 from prior sprints + e2e + reporter).
- `pnpm test --run`, `pnpm typecheck`, `pnpm build` all clean.
- No real Docker / API calls in CI — `tests/execution.integration.ts` is the integration target if needed (does not exist yet).

## Coordination

- Sonnet 4.6 is the primary builder. Codex handles review, debug, security audits, architecture review.
- This Opus 4.7 instance is relief — picks up when Sonnet is on break. Does not commit; stages changes for user review.
- Multi-agent handoffs land here. Update on each significant state change.
