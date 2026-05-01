import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, readdir, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scoreFinding } from "../src/reporter/severity.js";
import { renderMarkdown } from "../src/reporter/markdown.js";
import { buildReportJson } from "../src/reporter/json.js";
import { generateReport } from "../src/reporter/index.js";
import type { ValidatedFinding } from "../src/validation/index.js";
import type { AttackVector, ExploitResult, ExploitScript, ScanConfig } from "../src/types/index.js";

function makeVector(overrides: Partial<AttackVector> = {}): AttackVector {
  return {
    id: "sqli-001",
    vulnClass: "sqli",
    route: "/api/users",
    method: "GET",
    inputName: "id",
    inputType: "query",
    riskScore: 9,
    notes: "raw concat",
    ...overrides,
  };
}

function makeResult(overrides: Partial<ExploitResult> = {}): ExploitResult {
  return {
    vectorId: "sqli-001",
    confirmed: true,
    evidence: { responseBody: "syntax error in query", statusCode: 500 },
    retryCount: 0,
    ...overrides,
  };
}

function makeScript(overrides: Partial<ExploitScript> = {}): ExploitScript {
  return {
    vectorId: "sqli-001",
    type: "curl",
    script: "#!/bin/bash\ncurl 'http://t/api/users?id=1%27'",
    payload: "' OR 1=1--",
    ...overrides,
  };
}

function makeFinding(overrides: Partial<ValidatedFinding> = {}): ValidatedFinding {
  return {
    verdict: "confirmed",
    reasoning: "SQL error keywords in body",
    vector: makeVector(),
    script: makeScript(),
    result: makeResult(),
    ...overrides,
  };
}

function makeConfig(outputDir: string): ScanConfig {
  return {
    targetUrl: "http://localhost:3000",
    sourcePath: "./fixture",
    scope: ["sqli"],
    outputDir,
    maxRetries: 2,
    timeoutMs: 30000,
  };
}

describe("scoreFinding", () => {
  it("scores SQLi base above 7 (high)", () => {
    const s = scoreFinding(makeFinding());
    expect(s.severity).toBe("high");
    expect(s.score).toBeGreaterThanOrEqual(7);
  });

  it("bumps SQLi on admin route to critical", () => {
    const f = makeFinding({ vector: makeVector({ route: "/admin/users", riskScore: 9 }) });
    const s = scoreFinding(f);
    expect(s.severity).toBe("critical");
  });

  it("scores XSS as medium without screenshot", () => {
    const f = makeFinding({
      vector: makeVector({ vulnClass: "xss", riskScore: 4 }),
      result: makeResult({ evidence: { responseBody: "<script>", statusCode: 200 } }),
    });
    const s = scoreFinding(f);
    expect(s.severity).toBe("medium");
  });

  it("bumps XSS with screenshot evidence", () => {
    const f = makeFinding({
      vector: makeVector({ vulnClass: "xss", riskScore: 4 }),
      result: makeResult({
        evidence: { responseBody: "<script>", statusCode: 200, screenshotPath: "/tmp/x.png" },
      }),
    });
    const s = scoreFinding(f);
    expect(s.score).toBeGreaterThan(6);
  });

  it("auth scores critical at base", () => {
    const f = makeFinding({ vector: makeVector({ vulnClass: "auth", riskScore: 9 }) });
    const s = scoreFinding(f);
    expect(s.severity).toBe("critical");
  });

  it("caps score at 10.0", () => {
    const f = makeFinding({ vector: makeVector({ vulnClass: "auth", route: "/admin/root", riskScore: 10 }) });
    const s = scoreFinding(f);
    expect(s.score).toBeLessThanOrEqual(10.0);
  });

  it("includes rationale strings", () => {
    const s = scoreFinding(makeFinding());
    expect(s.rationale).toContain("base sqli");
  });
});

describe("renderMarkdown", () => {
  const config = makeConfig("/ignored");
  const now = new Date("2026-05-01T14:22:09Z");

  it("renders empty report when no confirmed findings", () => {
    const md = renderMarkdown([], [], config, now);
    expect(md).toContain("# Nico Scan Report");
    expect(md).toContain("No confirmed vulnerabilities");
  });

  it("includes summary table for confirmed findings", () => {
    const f = makeFinding();
    const md = renderMarkdown([{ finding: f, severity: scoreFinding(f) }], [], config, now);
    expect(md).toContain("| ID | Severity |");
    expect(md).toContain("NICO-SQLI-001");
    expect(md).toContain("GET /api/users");
  });

  it("includes PoC fenced block", () => {
    const f = makeFinding();
    const md = renderMarkdown([{ finding: f, severity: scoreFinding(f) }], [], config, now);
    expect(md).toContain("### Proof of concept");
    expect(md).toContain("```bash");
    expect(md).toContain("' OR 1=1--");
  });

  it("renders findings in the provided order", () => {
    const a = makeFinding({ vector: makeVector({ id: "a", vulnClass: "xss", riskScore: 4 }) });
    const b = makeFinding({ vector: makeVector({ id: "b", vulnClass: "auth", route: "/admin/x", riskScore: 9 }) });
    const md = renderMarkdown(
      [
        { finding: a, severity: scoreFinding(a) },
        { finding: b, severity: scoreFinding(b) },
      ],
      [],
      config,
      now
    );
    // Auth (critical) should appear in first finding block
    const authIdx = md.indexOf("AUTH in");
    const xssIdx = md.indexOf("XSS in");
    expect(authIdx).toBeGreaterThan(-1);
    expect(xssIdx).toBeGreaterThan(-1);
    expect(xssIdx).toBeLessThan(authIdx);
  });

  it("includes inconclusive section when present", () => {
    const incon = makeFinding({ verdict: "inconclusive", reasoning: "judge could not decide" });
    const md = renderMarkdown([], [incon], config, now);
    expect(md).toContain("## Inconclusive");
    expect(md).toContain("judge could not decide");
  });

  it("links screenshot when provided", () => {
    const f = makeFinding({
      vector: makeVector({ vulnClass: "xss", riskScore: 4 }),
      result: makeResult({
        evidence: { responseBody: "<script>", statusCode: 200, screenshotPath: "/tmp/x.png" },
      }),
    });
    const md = renderMarkdown(
      [{ finding: f, severity: scoreFinding(f), screenshotRelPath: "evidence/x.png" }],
      [],
      config,
      now
    );
    expect(md).toContain("evidence/x.png");
  });
});

describe("buildReportJson", () => {
  const config = makeConfig("/ignored");
  const now = new Date("2026-05-01T14:22:09Z");

  it("produces a Finding-schema-valid record per confirmed entry", () => {
    const f = makeFinding();
    const json = buildReportJson([{ finding: f, severity: scoreFinding(f) }], [], config, now);
    expect(json.findings).toHaveLength(1);
    expect(json.findings[0].id).toBe("NICO-SQLI-001");
    expect(json.findings[0].vulnClass).toBe("sqli");
    expect(json.findings[0].severity).toBe("high");
    expect(json.findings[0].score).toBeGreaterThan(7);
  });

  it("captures inconclusive findings", () => {
    const incon = makeFinding({ verdict: "inconclusive", reasoning: "ambiguous" });
    const json = buildReportJson([], [incon], config, now);
    expect(json.summary.inconclusive).toBe(1);
    expect(json.inconclusive[0].reasoning).toBe("ambiguous");
  });

  it("includes scan metadata", () => {
    const json = buildReportJson([], [], config, now);
    expect(json.target).toBe("http://localhost:3000");
    expect(json.scope).toEqual(["sqli"]);
    expect(json.generatedAt).toBe(now.toISOString());
  });
});

describe("generateReport", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "nico-report-"));
  });

  afterEach(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  it("writes report.md and report.json into a timestamped subdir", async () => {
    const config = makeConfig(tmp);
    const out = await generateReport([makeFinding()], config);
    expect(out.confirmedCount).toBe(1);
    const dirs = await readdir(tmp);
    expect(dirs).toHaveLength(1);
    const md = await readFile(out.markdownPath, "utf-8");
    expect(md).toContain("NICO-SQLI-001");
    const json = JSON.parse(await readFile(out.jsonPath, "utf-8"));
    expect(json.findings).toHaveLength(1);
  });

  it("filters non-confirmed verdicts out of findings array", async () => {
    const config = makeConfig(tmp);
    const fps = [
      makeFinding(),
      makeFinding({ verdict: "false_positive" }),
      makeFinding({ verdict: "not_exploitable" }),
      makeFinding({ verdict: "inconclusive", reasoning: "ambiguous" }),
    ];
    const out = await generateReport(fps, config);
    expect(out.confirmedCount).toBe(1);
    expect(out.inconclusiveCount).toBe(1);
    const json = JSON.parse(await readFile(out.jsonPath, "utf-8"));
    expect(json.findings).toHaveLength(1);
    expect(json.inconclusive).toHaveLength(1);
  });

  it("copies screenshot evidence into report dir", async () => {
    const config = makeConfig(tmp);
    const screenshotSrc = join(tmp, "screenshot.png");
    await writeFile(screenshotSrc, "fake png bytes");
    const f = makeFinding({
      result: makeResult({
        evidence: { responseBody: "x", statusCode: 200, screenshotPath: screenshotSrc },
      }),
    });
    const out = await generateReport([f], config);
    const copied = join(out.reportDir, "evidence", "screenshot.png");
    const s = await stat(copied);
    expect(s.isFile()).toBe(true);
  });

  it("writes empty-state report when no findings", async () => {
    const config = makeConfig(tmp);
    const out = await generateReport([], config);
    expect(out.confirmedCount).toBe(0);
    const md = await readFile(out.markdownPath, "utf-8");
    expect(md).toContain("No confirmed vulnerabilities");
  });

  it("uses the same severity-sorted IDs in markdown and JSON", async () => {
    const config = makeConfig(tmp);
    const xss = makeFinding({ vector: makeVector({ id: "xss-001", vulnClass: "xss", route: "/search", riskScore: 4 }) });
    const auth = makeFinding({ vector: makeVector({ id: "auth-001", vulnClass: "auth", route: "/admin", riskScore: 9 }) });

    const out = await generateReport([xss, auth], config);
    const md = await readFile(out.markdownPath, "utf-8");
    const json = JSON.parse(await readFile(out.jsonPath, "utf-8"));

    expect(md.indexOf("NICO-AUTH-001")).toBeLessThan(md.indexOf("NICO-XSS-002"));
    expect(json.findings[0].id).toBe("NICO-AUTH-001");
    expect(json.findings[0].route).toBe("/admin");
    expect(json.findings[1].id).toBe("NICO-XSS-002");
    expect(json.findings[1].route).toBe("/search");
  });
});
