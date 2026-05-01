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

  // Server crash with no meaningful body — could just be a broken endpoint
  if (status >= 500 && body.length < 10) return "likely_false_positive";

  // Empty response with no screenshot — nothing to confirm
  if (body.length < 5 && !result.evidence.screenshotPath) return "likely_false_positive";

  // Strong SQL error keywords — high confidence, skip judge
  if (SQL_ERROR_SIGNALS.some((kw) => body.includes(kw))) return "likely_confirmed";

  // XSS with a screenshot is strong confirmation
  if (vector.vulnClass === "xss" && result.evidence.screenshotPath) return "likely_confirmed";

  // Ambiguous — send to Claude judge
  return "send_to_judge";
}
