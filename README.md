# Nico

Autonomous AI pentester for web applications and APIs.

Claude maps the attack surface, generates the exploits, and judges the results. A Docker sandbox confirms them. A two-stage validator (rule-based pre-filter + Claude judge) suppresses false positives. Only proven vulnerabilities make the report.

> **v0.1 stack note:** v0.1 ships single-vendor on Claude (orchestrator + exploit generator + judge). A second-vendor exploit generator (OpenAI / GPT-5.5) is planned but deferred.

## Status

**Sprint 5 complete** — full pipeline wired: orchestrator → exploits → sandbox → validation → reporter.

Sprint 6 in progress: end-to-end validation against OWASP Juice Shop, prompt tuning, v0.1 ship.

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

Requires Node 18+, pnpm, Docker, and an Anthropic API key.

## Usage

```bash
pnpm dev scan \
  --target http://localhost:3000 \
  --source ./path/to/app/source \
  --scope sqli,xss \
  --output ./reports
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-t, --target <url>` | required | URL of the running target application |
| `-s, --source <path>` | required | Local path to the application source code |
| `--scope <vulns>` | `sqli` | Comma-separated vuln classes: `sqli,xss,auth,ssrf,idor` |
| `-o, --output <dir>` | `./reports` | Output directory for reports |
| `--timeout <ms>` | `30000` | Sandbox timeout per exploit |
| `--retries <n>` | `2` | Max retries on ambiguous results |

### Output

Reports land in `<output>/<ISO-timestamp>/`:

- `report.md` — human-readable, severity-sorted, with PoC and evidence
- `report.json` — structured findings (matches `Finding` zod schema)
- `evidence/` — screenshots from confirmed exploits

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
| v0.2 | XSS |
| v0.3 | Auth bypass |
| v0.4 | SSRF |
| v0.5 | IDOR, CORS, business logic |

## Pre-flight checks

The CLI runs pre-flight before any API call:

- `ANTHROPIC_API_KEY` present
- Docker daemon reachable
- Source path exists and is a directory
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

## Development

```bash
pnpm test        # vitest (run --run for single pass)
pnpm typecheck   # tsc --noEmit
pnpm build       # emit dist/
```

## License

MIT
