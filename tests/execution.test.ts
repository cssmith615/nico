import { describe, it, expect } from "vitest";
import { parseEvidence } from "../src/execution/runner.js";

// All tests here are pure unit tests — no Docker required.
// Integration tests (actual container runs) live in tests/execution.integration.ts
// and require Docker to be running.

describe("parseEvidence", () => {
  it("returns confirmed=true for a successful exploit", () => {
    const json = JSON.stringify({
      confirmed: true,
      payload: "' OR 1=1--",
      response: '[{"id":1,"name":"admin"},{"id":2,"name":"user"}]',
      statusCode: 200,
    });
    const result = parseEvidence(json, "sqli-001", 0);
    expect(result.confirmed).toBe(true);
    expect(result.vectorId).toBe("sqli-001");
    expect(result.retryCount).toBe(0);
    expect(result.evidence.statusCode).toBe(200);
    expect(result.evidence.responseBody).toContain("admin");
  });

  it("returns confirmed=false for a failed exploit", () => {
    const json = JSON.stringify({
      confirmed: false,
      payload: "",
      response: "Not found",
      statusCode: 404,
    });
    const result = parseEvidence(json, "sqli-002", 1);
    expect(result.confirmed).toBe(false);
    expect(result.retryCount).toBe(1);
    expect(result.evidence.statusCode).toBe(404);
  });

  it("handles malformed JSON gracefully", () => {
    const result = parseEvidence("not json {{{", "sqli-003", 0);
    expect(result.confirmed).toBe(false);
    expect(result.evidence.errorMessage).toContain("not valid JSON");
  });

  it("truncates long response bodies to 1000 chars", () => {
    const json = JSON.stringify({
      confirmed: true,
      payload: "x",
      response: "A".repeat(2000),
      statusCode: 200,
    });
    const result = parseEvidence(json, "sqli-004", 0);
    expect(result.evidence.responseBody!.length).toBeLessThanOrEqual(1000);
  });

  it("attaches screenshot path when provided", () => {
    const json = JSON.stringify({ confirmed: true, payload: "<script>", response: "", statusCode: 200 });
    const result = parseEvidence(json, "xss-001", 0, "/tmp/nico-abc/evidence.png");
    expect(result.evidence.screenshotPath).toBe("/tmp/nico-abc/evidence.png");
  });

  it("coerces truthy non-boolean confirmed values", () => {
    // Some models return 1 instead of true
    const json = JSON.stringify({ confirmed: 1, payload: "x", response: "ok", statusCode: 200 });
    const result = parseEvidence(json, "sqli-005", 0);
    expect(result.confirmed).toBe(true);
  });
});
