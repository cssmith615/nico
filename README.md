# Nico

Autonomous AI pentester for web applications and APIs.

Claude maps the attack surface, generates the exploits, and judges the results. A Docker sandbox confirms them. A two-stage validator (rule-based pre-filter + Claude judge) suppresses false positives. Only proven vulnerabilities make the report.

> **v0.1 stack note:** v0.1 ships single-vendor on Claude (orchestrator + exploit generator + judge). A second-vendor exploit generator (OpenAI / GPT-5.5) is planned but deferred.

## Status

**Sprint 0.5a in progress** — CORS misconfiguration detection added on top of the shipped 0.1–0.4 pipeline.

Previous:
- 0.4 — self-contained interactive HTML dashboard generated alongside `report.md` and `report.json`
- 0.3 — GitHub Actions CI + reusable Action for PR pipelines
- 0.2 — baseline response diffing, XSS/auth/SSRF/IDOR templates, OpenAPI/Swagger JSON ingestion

## Architecture

```
CLI
 │
 ▼
Orchestrator (Claude Sonnet)
 │  reads source, maps attack surface, builds task queue
 ▼
Exploit Generator (Claude Sonnet)
 │  per-vector Playwright/curl scripts; syntax + policy validated
 ▼
Sandbox (Docker)
 │  least-privilege container, captures evidence (status, body, screenshot)
 ▼
Validator (heuristics → Claude judge)
 │  false-positive gate; only confirmed findings forwarded
 ▼
Reporter
    markdown + JSON, CVSS-lite severity, copy-paste PoC
```

## Install

```bash
pnpm install
cp .env.example .env  # add ANTHROPIC_API_KEY
```

Requires Node 20+, pnpm, Docker, and an Anthropic API key.

## Usage

```bash
pnpm dev scan \
  --target http://localhost:3000 \
  --source ./path/to/app/source \
  --scope sqli,xss \
  --output ./reports

# Or scan from an OpenAPI/Swagger JSON spec
pnpm dev scan \
  --target http://localhost:3000 \
  --openapi ./openapi.json \
  --scope sqli,xss,auth,ssrf,idor,cors
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-t, --target <url>` | required | URL of the running target application |
| `-s, --source <path>` | optional | Local path to the application source code |
| `--openapi <path>` | optional | OpenAPI/Swagger JSON spec; alternative to `--source` |
| `--scope <vulns>` | `sqli` | Comma-separated vuln classes: `sqli,xss,auth,ssrf,idor,cors` |
| `-o, --output <dir>` | `./reports` | Output directory for reports |
| `--timeout <ms>` | `30000` | Sandbox timeout per exploit |
| `--retries <n>` | `2` | Max retries on ambiguous results |

### Output

Reports land in `<output>/<ISO-timestamp>/`:

- `report.md` — human-readable, severity-sorted, with PoC and evidence
- `report.json` — structured findings (matches `Finding` zod schema)
- `report.html` — self-contained interactive dashboard (filter by severity/class, search, expandable PoC)
- `evidence/` — screenshots from confirmed exploits

The HTML dashboard is fully self-contained — no external scripts or stylesheets, no network — open it directly from disk in any modern browser. The GitHub Action uploads the entire directory as the `nico-report` artifact.

## OWASP Juice Shop quickstart

A reference run against the OWASP Juice Shop. Config lives in `sample-targets/juice-shop.json`.

```bash
# 1. Run Juice Shop locally
docker run --rm -p 3000:3000 bkimminich/juice-shop

# 2. Clone the source so the orchestrator can map it
git clone https://github.com/juice-shop/juice-shop.git ./juice-shop-src

# 3. Scan
pnpm dev scan \
  --target http://localhost:3000 \
  --source ./juice-shop-src \
  --scope sqli,auth
```

Expected confirmed findings:

- SQLi in `POST /rest/user/login` via `email` (payload `' OR 1=1--`)
- Auth bypass on `POST /rest/user/login` (downstream of the SQLi)

## Vuln coverage

| Version | Coverage |
|---|---|
| v0.1 | SQL injection |
| v0.2 | XSS, auth bypass, SSRF, IDOR, OpenAPI ingestion |
| v0.3 | GitHub Actions CI + reusable Action |
| v0.4 | Self-contained HTML report dashboard |
| v0.5a | CORS |
| v0.5 | Business logic, correlation |

## GitHub Action

Nico ships as a reusable composite action you can drop into any pipeline. A copy-paste workflow lives at [`examples/workflows/nico-scan.yml`](examples/workflows/nico-scan.yml).

```yaml
- name: Run Nico
  uses: cssmith615/nico@v0.1
  with:
    target-url: http://localhost:3000
    source-path: ./
    scope: sqli,xss,auth,cors
    fail-on-severity: high
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Action inputs

| Input | Default | Required | Description |
|---|---|---|---|
| `target-url` | — | yes | URL of the running target. Must be reachable from the runner. |
| `source-path` | — | one of | Path to source. Either this or `openapi-path` must be set. |
| `openapi-path` | — | one of | Path to OpenAPI/Swagger JSON. Alternative to `source-path`. |
| `scope` | `sqli,xss,auth` | no | Comma-separated vuln classes: `sqli,xss,auth,ssrf,idor,cors`. |
| `output-dir` | `./nico-report` | no | Where Nico writes the timestamped report directory. |
| `fail-on-severity` | `high` | no | Fail the job at this severity or above. `none` to disable gating. |
| `comment-pr` | `true` | no | Post a sticky summary comment on PR events. |
| `anthropic-api-key` | — | yes | Pass as a secret. |

### What the Action does

- Builds Nico in `${{ github.action_path }}` and runs `nico scan` with your inputs.
- Uploads `report.md` + `report.json` (and any screenshots) as the `nico-report` artifact.
- On PRs, posts or updates a sticky comment with severity counts and a findings table.
- Exits non-zero when any finding meets `fail-on-severity` so the PR can be gated.

### Permissions

The calling job needs `pull-requests: write` for sticky-comment updates. Push events skip the comment step automatically.

### Secrets

Add `ANTHROPIC_API_KEY` to your repo's Actions secrets. The Action does not need the key to be in `.env`.

### Starting the target

The Action assumes the target is already running and reachable at `target-url`. Bring it up in an earlier step (docker, docker compose, `pnpm dev`, etc.) and tear it down with an `if: always()` step. The example workflow demonstrates the pattern with OWASP Juice Shop.

## Pre-flight checks

The CLI runs pre-flight before any API call:

- `ANTHROPIC_API_KEY` present
- Docker daemon reachable
- Source path exists and is a directory, or OpenAPI spec exists as a file
- Target URL responds to a GET

Failure exits with a clear error before burning tokens.

## Sandbox containment

Each exploit runs in a fresh Docker container with:

- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- `--read-only` root, tmpfs for `/tmp` and `/home/pwuser`
- Memory, CPU, and PID limits
- Timeout enforced at host level — orphaned containers are force-removed
- Generated scripts are syntax-checked and policy-scanned (no docker access, no package installs, no credential reads) before execution
- Baseline request comparison suppresses script-only false positives when exploit responses do not differ meaningfully from benign requests

## Development

```bash
pnpm test        # vitest (run --run for single pass)
pnpm typecheck   # tsc --noEmit
pnpm build       # emit dist/
```

## License

MIT
