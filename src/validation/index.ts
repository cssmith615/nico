import type { ExploitResult, AttackVector, ExploitScript } from "../types/index.js";
import { applyHeuristics } from "./heuristics.js";
import { judgeResult } from "./judge.js";

export type Verdict = "confirmed" | "false_positive" | "inconclusive" | "not_exploitable";

export interface ValidatedFinding {
  verdict: Verdict;
  reasoning: string;
  vector: AttackVector;
  script: ExploitScript;
  result: ExploitResult;
}

function pairResults(
  results: ExploitResult[],
  vectors: AttackVector[],
  scripts: ExploitScript[]
): Array<{ result: ExploitResult; vector: AttackVector; script: ExploitScript }> {
  const paired = [];
  for (const result of results) {
    const vector = vectors.find((v) => v.id === result.vectorId);
    const script = scripts.find((s) => s.vectorId === result.vectorId);
    if (vector && script) paired.push({ result, vector, script });
  }
  return paired;
}

export async function validateResults(
  results: ExploitResult[],
  vectors: AttackVector[],
  scripts: ExploitScript[]
): Promise<ValidatedFinding[]> {
  const pairs = pairResults(results, vectors, scripts);
  const findings: ValidatedFinding[] = [];

  for (const { result, vector, script } of pairs) {
    // Not confirmed by sandbox — no need to judge
    if (!result.confirmed) {
      findings.push({
        verdict: "not_exploitable",
        reasoning: result.evidence.errorMessage ?? "Sandbox did not confirm exploitation",
        vector,
        script,
        result,
      });
      continue;
    }

    const heuristic = applyHeuristics(result, vector);

    if (heuristic === "likely_false_positive") {
      findings.push({
        verdict: "false_positive",
        reasoning: "Pre-filter: evidence does not support confirmed exploitation",
        vector,
        script,
        result,
      });
      continue;
    }

    if (heuristic === "likely_confirmed") {
      findings.push({
        verdict: "confirmed",
        reasoning: "Strong evidence signal (SQL error keywords or XSS screenshot)",
        vector,
        script,
        result,
      });
      continue;
    }

    // Ambiguous — send to Claude judge
    const judgment = await judgeResult(result, vector, script);
    findings.push({ ...judgment, vector, script, result });
  }

  return findings;
}

export function confirmedOnly(findings: ValidatedFinding[]): ValidatedFinding[] {
  return findings.filter((f) => f.verdict === "confirmed");
}
