import type { VulnClass } from "../types/index.js";
import type { ValidatedFinding } from "../validation/index.js";

export type Severity = "critical" | "high" | "medium" | "low";

export interface SeverityScore {
  severity: Severity;
  score: number;
  rationale: string;
}

const BASE_SCORE: Record<VulnClass, number> = {
  auth: 9.0,
  sqli: 8.0,
  ssrf: 7.5,
  idor: 6.0,
  xss: 5.5,
};

const SQL_DATA_LEAK_SIGNALS = [
  "select",
  "from",
  "where",
  "user",
  "password",
  "email",
  "id=",
];

function bucket(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

export function scoreFinding(finding: ValidatedFinding): SeverityScore {
  const { vector, result } = finding;
  let score = BASE_SCORE[vector.vulnClass];
  const reasons: string[] = [`base ${vector.vulnClass} (${score.toFixed(1)})`];

  const body = (result.evidence.responseBody ?? "").toLowerCase();
  const status = result.evidence.statusCode ?? 0;

  // Authenticated/admin route exposure bumps score
  if (/admin|root|superuser/i.test(vector.route)) {
    score += 1.0;
    reasons.push("admin route (+1.0)");
  }

  // Data exfil signal in body — multiple SQL keywords suggest dumped rows
  if (vector.vulnClass === "sqli") {
    const matches = SQL_DATA_LEAK_SIGNALS.filter((kw) => body.includes(kw)).length;
    if (matches >= 3) {
      score += 0.8;
      reasons.push("data exfil signal (+0.8)");
    }
  }

  // Screenshot evidence on XSS shows confirmed JS execution
  if (vector.vulnClass === "xss" && result.evidence.screenshotPath) {
    score += 0.7;
    reasons.push("JS execution captured (+0.7)");
  }

  // 200 OK on injection means no input filtering at all
  if (status === 200 && vector.vulnClass === "sqli") {
    score += 0.3;
    reasons.push("200 OK on injection (+0.3)");
  }

  // High-risk vector flagged by orchestrator
  if (vector.riskScore >= 8) {
    score += 0.4;
    reasons.push(`high orchestrator risk ${vector.riskScore} (+0.4)`);
  }

  // Cap at 10.0
  if (score > 10.0) score = 10.0;

  return {
    severity: bucket(score),
    score: Math.round(score * 10) / 10,
    rationale: reasons.join(", "),
  };
}
