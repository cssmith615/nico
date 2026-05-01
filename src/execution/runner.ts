import type { ExploitScript, ExploitResult } from "../types/index.js";
import { runInContainer } from "./docker.js";

interface EvidenceFile {
  confirmed: boolean;
  payload: string;
  response: string;
  statusCode: number;
}

function parseEvidence(
  json: string,
  vectorId: string,
  retryCount: number,
  screenshotPath?: string
): ExploitResult {
  let ev: EvidenceFile;
  try {
    ev = JSON.parse(json) as EvidenceFile;
  } catch {
    return {
      vectorId,
      confirmed: false,
      evidence: { errorMessage: "Evidence file was not valid JSON" },
      retryCount,
    };
  }

  return {
    vectorId,
    confirmed: Boolean(ev.confirmed),
    evidence: {
      responseBody: ev.response ? String(ev.response).slice(0, 1000) : undefined,
      statusCode: typeof ev.statusCode === "number" ? ev.statusCode : undefined,
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
