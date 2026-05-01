# Nico

Autonomous AI pentester for web applications and APIs.

Claude maps the attack surface. GPT-5.5 generates the exploits. A Docker sandbox confirms them. Only proven vulnerabilities make the report.

## Status

**Sprint 0 complete** — scaffold, types, CLI shell, Docker base.
Sprint 1 next: Orchestrator (Claude source analysis + attack surface mapping).

## Architecture

```
CLI → Orchestrator (Claude) → Exploit Generator (GPT-5.5) → Sandbox (Docker) → Reporter
```

- **Orchestrator**: reads your source code, identifies attack vectors, builds an exploit task queue
- **Exploit Generator**: writes executable Playwright/curl scripts per vector
- **Sandbox**: runs scripts in isolation, captures evidence
- **Reporter**: confirmed-only findings with copy-paste PoCs

## Usage

```bash
pnpm install
cp .env.example .env  # add ANTHROPIC_API_KEY + OPENAI_API_KEY

# Run a scan
pnpm dev scan --target http://localhost:3000 --source ./my-app --scope sqli
```

## Requirements

- Node.js 18+
- pnpm
- Docker (for sandbox execution)
- Anthropic API key
- OpenAI API key (GPT-5.5)

## Vuln Coverage

| Version | Coverage |
|---|---|
| v0.1 | SQL Injection |
| v0.2 | XSS |
| v0.3 | Auth bypass |
| v0.4 | SSRF |
| v0.5 | IDOR, CORS, business logic |

## License

MIT
