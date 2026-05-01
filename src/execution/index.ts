import type { ExploitScript, ExploitResult } from "../types/index.js";
import { runExploit } from "./runner.js";
import { imageExists, buildImage } from "./docker.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const DOCKERFILE = join(dirname(fileURLToPath(import.meta.url)), "../../docker/Dockerfile.sandbox");

const CONCURRENCY = 2; // limit concurrent containers

export async function ensureSandbox(): Promise<void> {
  if (!(await imageExists())) {
    await buildImage(DOCKERFILE);
  }
}

export async function runExploits(
  scripts: ExploitScript[],
  timeoutMs: number,
  maxRetries: number
): Promise<ExploitResult[]> {
  const results: ExploitResult[] = [];

  for (let i = 0; i < scripts.length; i += CONCURRENCY) {
    const batch = scripts.slice(i, i + CONCURRENCY);
    const settled = await Promise.allSettled(
      batch.map((s) => runExploit(s, timeoutMs, maxRetries))
    );
    for (const outcome of settled) {
      if (outcome.status === "fulfilled") {
        results.push(outcome.value);
      } else {
        console.error(`[sandbox] exploit run failed: ${outcome.reason}`);
      }
    }
  }

  return results;
}

export { runExploit };
