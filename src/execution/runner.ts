import type { ExploitScript, ExploitResult } from "../types/index.js";
import { runInContainer } from "./docker.js";
import { z } from "zod";

const EvidenceFile = z.object({
  confirmed: z.boolean(),
  payload: z.string().optional(),
  response: z.unknown().optional(),
  statusCode: z.number().optional(),
});
type EvidenceFile = z.infer<typeof EvidenceFile>;

function parseEvidence(
  json: string,
  vectorId: string,
  retryCount: number,
  screenshotPath?: string
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

  return {
    vectorId,
    confirmed: ev.confirmed === true,
    evidence: {
      responseBody: ev.response ? String(ev.response).slice(0, 1000) : undefined,
      statusCode: ev.statusCode,
      screenshotPath,
    },
    retryCount,
  };
}

export async function runExploit(
  script: ExploitScript,
  timeoutMs: number,
  maxRetries: number
): Promise<ExploitResult> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const { evidenceJson, screenshotPath, timedOut } = await runInContainer(
      script.script,
      script.type,
      timeoutMs
    );

    if (timedOut) {
      return {
        vectorId: script.vectorId,
        confirmed: false,
        evidence: { errorMessage: `Sandbox timed out after ${timeoutMs}ms` },
        retryCount: attempt,
      };
    }

    const result = parseEvidence(evidenceJson, script.vectorId, attempt, screenshotPath);

    // Confirmed or exhausted retries — done
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
