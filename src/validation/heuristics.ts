import type { ExploitResult, AttackVector } from "../types/index.js";

export type HeuristicVerdict =
  | "likely_confirmed"
  | "likely_false_positive"
  | "send_to_judge";

const SQL_ERROR_SIGNALS = [
  "syntax error",
  "mysql",
  "postgresql",
  "sqlite",
  "ora-",
  "unclosed quotation",
  "unterminated string",
  "you have an error in your sql",
  "pg_query",
  "division by zero",
];

export function applyHeuristics(
  result: ExploitResult,
  vector: AttackVector
): HeuristicVerdict {
  if (!result.confirmed) return "likely_false_positive";

  const body = (result.evidence.responseBody ?? "").toLowerCase();
  const status = result.evidence.statusCode ?? 0;
  const diff = result.evidence.diff;

  // Script claimed confirmed but diff found no meaningful change — false positive
  if (result.scriptConfirmed === true && diff && !diff.confirmedByDiff) {
    return "likely_false_positive";
  }

  // Diff detected new SQL errors not present in baseline — strong signal
  if (diff && diff.newSqlSignals.length > 0) return "likely_confirmed";

  // Diff detected JSON length growth (more rows returned) — data exfil
  if (diff && diff.jsonLengthDelta > 0) return "likely_confirmed";

  // Time-based blind SQLi
  if (diff && diff.responseTimeDeltaMs > 2000) return "likely_confirmed";

  // Auth bypass: previously blocked route now returns meaningful data
  if (diff && diff.statusChanged && diff.confirmedByDiff && diff.lengthDelta > 50) {
    return "likely_confirmed";
  }

  // No diff available — fall back to body-based heuristics
  if (!diff) {
    if (status >= 500 && body.length < 10) return "likely_false_positive";
    if (body.length < 5 && !result.evidence.screenshotPath) return "likely_false_positive";
    if (SQL_ERROR_SIGNALS.some((kw) => body.includes(kw))) return "likely_confirmed";
  }

  // XSS with a screenshot is strong regardless of diff
  if (vector.vulnClass === "xss" && result.evidence.screenshotPath) return "likely_confirmed";

  return "send_to_judge";
}
