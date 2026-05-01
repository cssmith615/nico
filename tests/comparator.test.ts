import { describe, it, expect } from "vitest";
import { compareResponses } from "../src/execution/comparator.js";
import { generateBaselineScript } from "../src/execution/baseline.js";
import type { BaselineEvidence } from "../src/types/index.js";

const makeBaseline = (overrides: Partial<BaselineEvidence> = {}): BaselineEvidence => ({
  statusCode: 200,
  responseBody: '{"message":"ok"}',
  responseTimeMs: 120,
  ...overrides,
});

// --- compareResponses ---

describe("compareResponses", () => {
  it("returns confirmedByDiff=false when responses are identical", () => {
    const baseline = makeBaseline();
    const result = compareResponses(baseline, {
      statusCode: 200,
      responseBody: '{"message":"ok"}',
      responseTimeMs: 130,
    });
    expect(result.confirmedByDiff).toBe(false);
    expect(result.lengthDelta).toBe(0);
    expect(result.statusChanged).toBe(false);
  });

  it("detects new SQL error keywords absent in baseline", () => {
    const baseline = makeBaseline({ responseBody: '{"message":"not found"}' });
    const result = compareResponses(baseline, {
      statusCode: 500,
      responseBody: 'SQLITE_ERROR: syntax error near OR',
      responseTimeMs: 140,
    });
    expect(result.newSqlSignals).toContain("syntax error");
    expect(result.newSqlSignals).toContain("sqlite");
    expect(result.confirmedByDiff).toBe(true);
  });

  it("does NOT flag SQL keywords present in both baseline and exploit", () => {
    const body = 'postgresql connection ok';
    const baseline = makeBaseline({ responseBody: body });
    const result = compareResponses(baseline, {
      statusCode: 200,
      responseBody: body + " — extra data",
      responseTimeMs: 130,
    });
    expect(result.newSqlSignals).toHaveLength(0);
  });

  it("detects time-based blind SQLi via response time delta", () => {
    const baseline = makeBaseline({ responseTimeMs: 100 });
    const result = compareResponses(baseline, {
      statusCode: 200,
      responseBody: '{"message":"ok"}',
      responseTimeMs: 3200,
    });
    expect(result.responseTimeDeltaMs).toBe(3100);
    expect(result.confirmedByDiff).toBe(true);
  });

  it("detects JSON array growth (data exfil)", () => {
    const baseline = makeBaseline({ responseBody: '[{"id":1}]' });
    const result = compareResponses(baseline, {
      statusCode: 200,
      responseBody: '[{"id":1},{"id":2},{"id":3,"email":"admin@site.com"}]',
      responseTimeMs: 130,
    });
    expect(result.jsonLengthDelta).toBe(2);
    expect(result.confirmedByDiff).toBe(true);
  });

  it("detects status code change to 200 from blocked", () => {
    const baseline = makeBaseline({ statusCode: 401, responseBody: '{"error":"unauthorized"}' });
    const result = compareResponses(baseline, {
      statusCode: 200,
      responseBody: '{"token":"eyJhbGciOiJSUzI1NiJ9...","user":{"role":"admin"}}',
      responseTimeMs: 140,
    });
    expect(result.statusChanged).toBe(true);
    expect(result.confirmedByDiff).toBe(true);
  });

  it("returns no confirmation for marginally longer response", () => {
    const baseline = makeBaseline({ responseBody: '{"count":5}' });
    const result = compareResponses(baseline, {
      statusCode: 200,
      responseBody: '{"count":5,"extra":true}',
      responseTimeMs: 125,
    });
    // Small delta, no SQL signals, no status change, no JSON array growth
    expect(result.confirmedByDiff).toBe(false);
  });

  it("populates diffSummary with human-readable signals", () => {
    const baseline = makeBaseline({ responseBody: "ok" });
    const result = compareResponses(baseline, {
      statusCode: 500,
      responseBody: "mysql error: syntax error",
      responseTimeMs: 140,
    });
    expect(result.diffSummary).toContain("SQL");
    expect(result.diffSummary).not.toBe("no meaningful diff vs baseline");
  });

  it("returns 'no meaningful diff' summary when responses are the same", () => {
    const baseline = makeBaseline();
    const result = compareResponses(baseline, {
      statusCode: 200,
      responseBody: '{"message":"ok"}',
      responseTimeMs: 125,
    });
    expect(result.diffSummary).toBe("no meaningful diff vs baseline");
  });
});

// --- generateBaselineScript ---

describe("generateBaselineScript", () => {
  const baseVector = {
    id: "sqli-001",
    vulnClass: "sqli" as const,
    route: "/api/users",
    method: "GET",
    inputName: "id",
    inputType: "query" as const,
    riskScore: 9,
  };

  it("generates a bash script", () => {
    const script = generateBaselineScript(baseVector, "http://localhost:3000");
    expect(script).toContain("#!/bin/bash");
    expect(script).toContain("curl");
    expect(script).toContain("baseline.json");
  });

  it("includes route and input name", () => {
    const script = generateBaselineScript(baseVector, "http://localhost:3000");
    expect(script).toContain("/api/users");
    expect(script).toContain("id=nico_baseline_safe");
  });

  it("uses POST with JSON body for body inputs", () => {
    const script = generateBaselineScript(
      { ...baseVector, method: "POST", inputType: "body" },
      "http://localhost:3000"
    );
    expect(script).toContain("-X POST");
    expect(script).toContain("Content-Type: application/json");
    expect(script).toContain('"id"');
  });

  it("sets header for header inputs", () => {
    const script = generateBaselineScript(
      { ...baseVector, inputType: "header" },
      "http://localhost:3000"
    );
    expect(script).toContain('-H "id:');
  });

  it("writes baseline.json to /workspace", () => {
    const script = generateBaselineScript(baseVector, "http://localhost:3000");
    expect(script).toContain("/workspace/baseline.json");
  });

  it("substitutes path param directly in URL for path inputType", () => {
    const script = generateBaselineScript(
      { ...baseVector, inputType: "path", route: "/api/users/{id}" },
      "http://localhost:3000"
    );
    expect(script).toContain("/api/users/");
    expect(script).not.toContain("?id=");
  });
});
