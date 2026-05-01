import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(__dirname, "fixtures/simple-express");

// --- Mocks for all external services ---

// Anthropic — used by orchestrator analyzer, exploit generator, and validation judge.
// Routes by prompt content.
vi.mock("@anthropic-ai/sdk", () => ({
  default: class {
    messages = {
      create: async (req: { messages: Array<{ content: unknown }> }) => {
        const last = req.messages[req.messages.length - 1];
        const content = typeof last.content === "string" ? last.content : JSON.stringify(last.content);

        if (content.includes("Identify attack vectors") || content.includes("attack vectors")) {
          const vectors = [
            {
              id: "sqli-001",
              vulnClass: "sqli",
              route: "/api/users",
              method: "GET",
              inputName: "id",
              inputType: "query",
              sourceFile: "routes/users.js",
              sourceLine: 12,
              riskScore: 9,
              notes: "raw concat into query",
            },
          ];
          return { content: [{ type: "text", text: JSON.stringify(vectors) }] };
        }

        if (content.includes("PAYLOADS TO TRY") || content.includes("/workspace/evidence.json")) {
          // Exploit generator — must be valid bash so `bash -n` passes on Linux runners.
          // Heredoc avoids the quote-balancing problem of inlining the SQLi payload in echo.
          const script = [
            "#!/bin/bash",
            'PAYLOADS=("\' OR 1=1--")',
            'curl -s "http://t/api/users?id=1" > /tmp/r',
            "cat > /workspace/evidence.json <<'EVIDENCE'",
            '{"confirmed":true,"payload":"\' OR 1=1--","response":"syntax error","statusCode":500}',
            "EVIDENCE",
            "",
          ].join("\n");
          return {
            content: [{ type: "text", text: script }],
          };
        }

        // Judge — return confirmed
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ verdict: "confirmed", reasoning: "mock judge: confirmed" }),
            },
          ],
        };
      },
    };
  },
}));

// Docker runner — pretend the script ran and returned a confirmed evidence file.
vi.mock("../src/execution/docker.js", () => ({
  imageExists: async () => true,
  buildImage: async () => undefined,
  runInContainer: async () => ({
    evidenceJson: JSON.stringify({
      confirmed: true,
      payload: "' OR 1=1--",
      response: "you have an error in your sql syntax near 'OR 1=1'",
      statusCode: 500,
    }),
    screenshotPath: undefined,
    timedOut: false,
  }),
  SANDBOX_IMAGE: "nico-sandbox",
}));

// Imports after mocks are registered
const { runOrchestrator } = await import("../src/orchestrator/index.js");
const { generateExploits } = await import("../src/exploit/index.js");
const { ensureSandbox, runExploits } = await import("../src/execution/index.js");
const { validateResults } = await import("../src/validation/index.js");
const { generateReport } = await import("../src/reporter/index.js");

describe("E2E pipeline (mocked APIs)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "nico-e2e-"));
    process.env.ANTHROPIC_API_KEY = "test";
    process.env.OPENAI_API_KEY = "test";
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it("runs the full pipeline and writes a confirmed finding to disk", async () => {
    const config = {
      targetUrl: "http://localhost:3000",
      sourcePath: FIXTURE,
      scope: ["sqli"] as const,
      outputDir: tmp,
      maxRetries: 1,
      timeoutMs: 5000,
    };

    // 1. Orchestrator
    const vectors = await runOrchestrator({ ...config, scope: [...config.scope] });
    expect(vectors).toHaveLength(1);
    expect(vectors[0].vulnClass).toBe("sqli");

    // 2. Exploit generation
    const scripts = await generateExploits(vectors, config.targetUrl);
    expect(scripts).toHaveLength(1);
    expect(scripts[0].script).toContain("curl");

    // 3. Sandbox (mocked)
    await ensureSandbox();
    const results = await runExploits(scripts, vectors, config.targetUrl, config.timeoutMs, config.maxRetries);
    expect(results).toHaveLength(1);
    expect(results[0].confirmed).toBe(true);

    // 4. Validation — heuristic should catch SQL error keyword
    const findings = await validateResults(results, vectors, scripts);
    expect(findings).toHaveLength(1);
    expect(findings[0].verdict).toBe("confirmed");

    // 5. Reporter
    const report = await generateReport(findings, { ...config, scope: [...config.scope] });
    expect(report.confirmedCount).toBe(1);
    expect(report.inconclusiveCount).toBe(0);

    const md = await readFile(report.markdownPath, "utf-8");
    expect(md).toContain("NICO-SQLI-001");
    expect(md).toContain("GET /api/users");
    expect(md).toContain("' OR 1=1--");

    const json = JSON.parse(await readFile(report.jsonPath, "utf-8"));
    expect(json.findings).toHaveLength(1);
    expect(json.findings[0].vulnClass).toBe("sqli");
    expect(json.findings[0].severity).toBe("high");
  });
});
