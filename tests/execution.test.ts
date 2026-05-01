import { describe, it, expect } from "vitest";
import { parseEvidence } from "../src/execution/runner.js";
import { adaptForDocker } from "../src/execution/docker.js";

// All tests here are pure unit tests — no Docker required.
// Integration tests live in tests/execution.integration.ts

const BASELINE_JSON = JSON.stringify({
  statusCode: 200,
  responseBody: '{"message":"ok"}',
  responseTimeMs: 100,
});

const BASELINE_WITH_SQL = JSON.stringify({
  statusCode: 200,
  responseBody: "postgresql connection ok",
  responseTimeMs: 100,
});

describe("parseEvidence — no baseline", () => {
  it("returns confirmed=true when script confirms and no baseline", () => {
    const json = JSON.stringify({
      confirmed: true,
      payload: "' OR 1=1--",
      response: '[{"id":1,"name":"admin"}]',
      statusCode: 200,
    });
    const result = parseEvidence(json, "sqli-001", 0);
    expect(result.confirmed).toBe(true);
    expect(result.scriptConfirmed).toBe(true);
    expect(result.evidence.diff).toBeUndefined();
  });

  it("returns confirmed=false when script says not confirmed", () => {
    const json = JSON.stringify({ confirmed: false, payload: "", response: "Not found", statusCode: 404 });
    const result = parseEvidence(json, "sqli-002", 1);
    expect(result.confirmed).toBe(false);
    expect(result.retryCount).toBe(1);
  });

  it("handles malformed JSON gracefully", () => {
    const result = parseEvidence("not json {{{", "sqli-003", 0);
    expect(result.confirmed).toBe(false);
    expect(result.evidence.errorMessage).toContain("not valid JSON");
  });

  it("truncates long response bodies to 1000 chars", () => {
    const json = JSON.stringify({ confirmed: true, payload: "x", response: "A".repeat(2000), statusCode: 200 });
    const result = parseEvidence(json, "sqli-004", 0);
    expect(result.evidence.responseBody!.length).toBeLessThanOrEqual(1000);
  });

  it("attaches screenshot path", () => {
    const json = JSON.stringify({ confirmed: true, payload: "<script>", response: "", statusCode: 200 });
    const result = parseEvidence(json, "xss-001", 0, "/tmp/nico-abc/evidence.png");
    expect(result.evidence.screenshotPath).toBe("/tmp/nico-abc/evidence.png");
  });

  it("rejects non-boolean confirmed values", () => {
    const json = JSON.stringify({ confirmed: 1, payload: "x", response: "ok", statusCode: 200 });
    const result = parseEvidence(json, "sqli-005", 0);
    expect(result.confirmed).toBe(false);
    expect(result.evidence.errorMessage).toContain("expected schema");
  });
});

describe("adaptForDocker", () => {
  it("rewrites loopback targets so sandbox containers can reach the Docker host", () => {
    delete process.env.NICO_DOCKER_NETWORK;
    const script = "curl http://localhost:3000 && curl http://127.0.0.1:4000";
    expect(adaptForDocker(script)).toBe(
      "curl http://host.docker.internal:3000 && curl http://host.docker.internal:4000"
    );
  });

  it("keeps loopback targets when host networking is explicitly enabled", () => {
    process.env.NICO_DOCKER_NETWORK = "host";
    try {
      const script = "curl http://localhost:3000";
      expect(adaptForDocker(script)).toBe(script);
    } finally {
      delete process.env.NICO_DOCKER_NETWORK;
    }
  });
});

describe("parseEvidence — with baseline (diff mode)", () => {
  it("confirmed when script confirms AND diff agrees", () => {
    const json = JSON.stringify({
      confirmed: true,
      response: "sqlite error: syntax error in query",
      statusCode: 500,
    });
    const result = parseEvidence(json, "sqli-001", 0, undefined, BASELINE_JSON);
    expect(result.confirmed).toBe(true);
    expect(result.scriptConfirmed).toBe(true);
    expect(result.evidence.diff?.confirmedByDiff).toBe(true);
    expect(result.evidence.baseline).toBeDefined();
  });

  it("NOT confirmed when script claims confirmed but diff sees no change", () => {
    const json = JSON.stringify({
      confirmed: true,
      response: '{"message":"ok"}',
      statusCode: 200,
    });
    const result = parseEvidence(json, "sqli-002", 0, undefined, BASELINE_JSON);
    expect(result.confirmed).toBe(false);
    expect(result.scriptConfirmed).toBe(true);
    expect(result.evidence.diff?.confirmedByDiff).toBe(false);
  });

  it("confirmed when diff detects change even if script says false", () => {
    // Baseline: 200 ok. Exploit: 500 + new SQL error signal
    const json = JSON.stringify({
      confirmed: false,
      response: "sqlite error: syntax error near OR",
      statusCode: 500,
    });
    const result = parseEvidence(json, "sqli-003", 0, undefined, BASELINE_JSON);
    expect(result.confirmed).toBe(true);
    expect(result.scriptConfirmed).toBe(false);
    expect(result.evidence.diff?.confirmedByDiff).toBe(true);
  });

  it("does not double-count SQL keywords present in baseline", () => {
    const json = JSON.stringify({
      confirmed: true,
      response: "postgresql connection ok — same as usual",
      statusCode: 200,
    });
    const result = parseEvidence(json, "sqli-004", 0, undefined, BASELINE_WITH_SQL);
    // postgresql was in baseline too, so not a new signal
    expect(result.evidence.diff?.newSqlSignals).toHaveLength(0);
    expect(result.confirmed).toBe(false);
  });

  it("attaches baseline and diff to evidence", () => {
    const json = JSON.stringify({ confirmed: true, response: "sqlite error", statusCode: 500 });
    const result = parseEvidence(json, "sqli-005", 0, undefined, BASELINE_JSON);
    expect(result.evidence.baseline?.statusCode).toBe(200);
    expect(result.evidence.diff).toBeDefined();
    expect(typeof result.evidence.diff?.diffSummary).toBe("string");
  });
});
