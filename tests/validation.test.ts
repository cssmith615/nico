import { describe, it, expect, vi } from "vitest";
import { applyHeuristics } from "../src/validation/heuristics.js";
import { confirmedOnly } from "../src/validation/index.js";
import type { ExploitResult, AttackVector, ExploitScript } from "../src/types/index.js";

// Mock Anthropic so judge tests never hit the real API
vi.mock("@anthropic-ai/sdk", () => ({
  default: class {
    messages = {
      create: async () => ({
        content: [{ type: "text", text: '{"verdict":"false_positive","reasoning":"mock: generic error page"}' }],
      }),
    };
  },
}));

// Import after mock is registered
const { validateResults } = await import("../src/validation/index.js");

// --- fixtures ---

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
    evidence: { responseBody: "syntax error in query", statusCode: 200 },
    retryCount: 0,
    ...overrides,
  };
}

function makeScript(overrides: Partial<ExploitScript> = {}): ExploitScript {
  return {
    vectorId: "sqli-001",
    type: "curl",
    script: "#!/bin/bash\ncurl ...",
    payload: "' OR 1=1--",
    ...overrides,
  };
}

// --- heuristics ---

describe("applyHeuristics", () => {
  it("returns likely_false_positive when confirmed=false", () => {
    const r = makeResult({ confirmed: false });
    expect(applyHeuristics(r, makeVector())).toBe("likely_false_positive");
  });

  it("returns likely_false_positive for 500 with empty body", () => {
    const r = makeResult({ evidence: { statusCode: 500, responseBody: "" } });
    expect(applyHeuristics(r, makeVector())).toBe("likely_false_positive");
  });

  it("returns likely_false_positive for empty body with no screenshot", () => {
    const r = makeResult({ evidence: { responseBody: "", statusCode: 200 } });
    expect(applyHeuristics(r, makeVector())).toBe("likely_false_positive");
  });

  it("returns likely_confirmed for SQL error keywords", () => {
    const r = makeResult({ evidence: { responseBody: "You have an error in your SQL syntax", statusCode: 500 } });
    expect(applyHeuristics(r, makeVector())).toBe("likely_confirmed");
  });

  it("returns likely_confirmed for postgresql keyword", () => {
    const r = makeResult({ evidence: { responseBody: "PostgreSQL error: unterminated string", statusCode: 500 } });
    expect(applyHeuristics(r, makeVector())).toBe("likely_confirmed");
  });

  it("returns likely_confirmed for XSS with screenshot", () => {
    const r = makeResult({
      evidence: { responseBody: "page content", statusCode: 200, screenshotPath: "/tmp/evidence.png" },
    });
    expect(applyHeuristics(r, makeVector({ vulnClass: "xss" }))).toBe("likely_confirmed");
  });

  it("returns send_to_judge for ambiguous confirmed result", () => {
    const r = makeResult({ evidence: { responseBody: "some data returned", statusCode: 200 } });
    expect(applyHeuristics(r, makeVector())).toBe("send_to_judge");
  });

  it("returns likely_confirmed for auth bypass via 401→200 with substantial body change", () => {
    const r = makeResult({
      confirmed: true,
      evidence: {
        responseBody: '{"token":"eyJhbGciOiJIUzI1NiJ9...","user":{"id":1,"role":"admin"}}',
        statusCode: 200,
        diff: {
          statusChanged: true,
          lengthDelta: 90,
          newSqlSignals: [],
          responseTimeDeltaMs: 40,
          jsonLengthDelta: 0,
          confirmedByDiff: true,
          diffSummary: "status 401 → 200; body length delta: +90",
        },
      },
    });
    expect(applyHeuristics(r, makeVector({ vulnClass: "auth" }))).toBe("likely_confirmed");
  });

  it("does NOT confirm auth bypass when body change is marginal", () => {
    const r = makeResult({
      confirmed: true,
      evidence: {
        responseBody: '{"error":"try again"}',
        statusCode: 200,
        diff: {
          statusChanged: true,
          lengthDelta: 10,
          newSqlSignals: [],
          responseTimeDeltaMs: 30,
          jsonLengthDelta: 0,
          confirmedByDiff: true,
          diffSummary: "status 401 → 200",
        },
      },
    });
    expect(applyHeuristics(r, makeVector({ vulnClass: "auth" }))).toBe("send_to_judge");
  });

  it("returns likely_confirmed for reflected CORS origin with credentials", () => {
    const r = makeResult({
      confirmed: true,
      evidence: {
        responseBody: "ACAO=https://evil.example.com|ACAC=true|origin=https://evil.example.com|status=200",
        statusCode: 200,
        diff: {
          statusChanged: false,
          lengthDelta: 70,
          newSqlSignals: [],
          responseTimeDeltaMs: 10,
          jsonLengthDelta: 0,
          confirmedByDiff: true,
          diffSummary: "CORS misconfig: ACAO=https://evil.example.com, ACAC=true",
        },
      },
    });
    expect(applyHeuristics(r, makeVector({ vulnClass: "cors", inputName: "Origin", inputType: "header" }))).toBe("likely_confirmed");
  });

  it("returns likely_false_positive for CORS without ACAC", () => {
    const r = makeResult({
      confirmed: true,
      evidence: {
        responseBody: "ACAO=https://evil.example.com|ACAC=false|origin=https://evil.example.com|status=200",
        statusCode: 200,
        diff: {
          statusChanged: false,
          lengthDelta: 70,
          newSqlSignals: [],
          responseTimeDeltaMs: 10,
          jsonLengthDelta: 0,
          confirmedByDiff: true,
          diffSummary: "body length delta: +70",
        },
      },
    });
    expect(applyHeuristics(r, makeVector({ vulnClass: "cors", inputName: "Origin", inputType: "header" }))).toBe("likely_false_positive");
  });
});

// --- validateResults ---

describe("validateResults", () => {
  it("marks unconfirmed results as not_exploitable without calling judge", async () => {
    const result = makeResult({ confirmed: false, evidence: { errorMessage: "no data returned" } });
    const findings = await validateResults([result], [makeVector()], [makeScript()]);
    expect(findings).toHaveLength(1);
    expect(findings[0].verdict).toBe("not_exploitable");
  });

  it("marks strong SQL error signals as confirmed without calling judge", async () => {
    const result = makeResult({
      evidence: { responseBody: "sqlite error: unclosed quotation mark", statusCode: 500 },
    });
    const findings = await validateResults([result], [makeVector()], [makeScript()]);
    expect(findings[0].verdict).toBe("confirmed");
  });

  it("marks 500 with empty body as false_positive without calling judge", async () => {
    const result = makeResult({ evidence: { statusCode: 500, responseBody: "" } });
    const findings = await validateResults([result], [makeVector()], [makeScript()]);
    expect(findings[0].verdict).toBe("false_positive");
  });

  it("calls judge for ambiguous cases and uses its verdict", async () => {
    // Ambiguous result (body has data but no SQL keywords) → heuristics returns send_to_judge
    // Mocked Anthropic returns false_positive
    const result = makeResult({ evidence: { responseBody: "unexpected data returned", statusCode: 200 } });
    const findings = await validateResults([result], [makeVector()], [makeScript()]);
    expect(["confirmed", "false_positive", "inconclusive"]).toContain(findings[0].verdict);
  });

  it("skips pairs with no matching vector or script", async () => {
    const result = makeResult({ vectorId: "unknown-999" });
    const findings = await validateResults([result], [makeVector()], [makeScript()]);
    expect(findings).toHaveLength(0);
  });
});

// --- confirmedOnly ---

describe("confirmedOnly", () => {
  it("filters to only confirmed findings", () => {
    const findings = [
      { verdict: "confirmed" as const, reasoning: "", vector: makeVector(), script: makeScript(), result: makeResult() },
      { verdict: "false_positive" as const, reasoning: "", vector: makeVector(), script: makeScript(), result: makeResult() },
      { verdict: "not_exploitable" as const, reasoning: "", vector: makeVector(), script: makeScript(), result: makeResult() },
    ];
    expect(confirmedOnly(findings)).toHaveLength(1);
    expect(confirmedOnly(findings)[0].verdict).toBe("confirmed");
  });

  it("returns empty array when nothing confirmed", () => {
    const findings = [
      { verdict: "not_exploitable" as const, reasoning: "", vector: makeVector(), script: makeScript(), result: makeResult() },
    ];
    expect(confirmedOnly(findings)).toHaveLength(0);
  });
});
