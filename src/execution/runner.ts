import type { ExploitScript, ExploitResult, AttackVector, BaselineEvidence, DiffResult } from "../types/index.js";
import { runInContainer } from "./docker.js";
import { generateBaselineScript } from "./baseline.js";
import { compareResponses } from "./comparator.js";
import { z } from "zod";

const EvidenceFile = z.object({
  confirmed: z.boolean(),
  payload: z.string().optional(),
  response: z.unknown().optional(),
  statusCode: z.number().optional(),
  responseTimeMs: z.number().optional(),
});
type EvidenceFile = z.infer<typeof EvidenceFile>;

const BaselineFile = z.object({
  statusCode: z.number().optional(),
  responseBody: z.string().optional(),
  responseTimeMs: z.number().optional(),
});

function parseBaselineJson(json: string): BaselineEvidence | undefined {
  try {
    return BaselineFile.parse(JSON.parse(json));
  } catch {
    return undefined;
  }
}

function parseEvidence(
  json: string,
  vectorId: string,
  retryCount: number,
  screenshotPath?: string,
  baselineJson?: string
): ExploitResult {
  let ev: EvidenceFile;
  try {
    ev = EvidenceFile.parse(JSON.parse(json));
  } catch {
    return {
      vectorId,
      confirmed: false,
      evidence: { errorMessage: "Evidence file was not valid JSON or did not match expected schema" },
      retryCount,
    };
  }

  const scriptConfirmed = ev.confirmed === true;
  const baseline = baselineJson ? parseBaselineJson(baselineJson) : undefined;

  let diff: DiffResult | undefined;
  let confirmed: boolean;

  if (baseline) {
    diff = compareResponses(baseline, {
      statusCode: ev.statusCode,
      responseBody: ev.response ? String(ev.response).slice(0, 1000) : undefined,
      responseTimeMs: ev.responseTimeMs,
    });

    // Confirmed only when script AND diff agree — or diff alone is very strong
    if (scriptConfirmed && diff.confirmedByDiff) {
      confirmed = true;
    } else if (scriptConfirmed && !diff.confirmedByDiff) {
      // Script claimed confirmed but diff sees no change — suspicious, not confirmed
      confirmed = false;
    } else if (!scriptConfirmed && diff.confirmedByDiff) {
      // Diff detected a change the script missed — treat as confirmed, judge will evaluate
      confirmed = true;
    } else {
      confirmed = false;
    }
  } else {
    // No baseline available — fall back to script assertion only
    confirmed = scriptConfirmed;
  }

  return {
    vectorId,
    confirmed,
    scriptConfirmed,
    evidence: {
      responseBody: ev.response ? String(ev.response).slice(0, 1000) : undefined,
      statusCode: ev.statusCode,
      screenshotPath,
      baseline,
      diff,
    },
    retryCount,
  };
}

export async function runExploit(
  script: ExploitScript,
  vector: AttackVector,
  targetUrl: string,
  timeoutMs: number,
  maxRetries: number
): Promise<ExploitResult> {
  const baselineScript = generateBaselineScript(vector, targetUrl);

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const { evidenceJson, baselineJson, screenshotPath, timedOut } =
      await runInContainer(script.script, script.type, timeoutMs, baselineScript);

    if (timedOut) {
      return {
        vectorId: script.vectorId,
        confirmed: false,
        evidence: { errorMessage: `Sandbox timed out after ${timeoutMs}ms` },
        retryCount: attempt,
      };
    }

    const result = parseEvidence(
      evidenceJson,
      script.vectorId,
      attempt,
      screenshotPath,
      baselineJson
    );

    if (result.confirmed || attempt >= maxRetries) {
      return result;
    }
  }

  return {
    vectorId: script.vectorId,
    confirmed: false,
    evidence: { errorMessage: "Max retries exceeded" },
    retryCount: maxRetries,
  };
}

export { parseEvidence };
