import { exec } from "node:child_process";
import { promisify } from "node:util";
import { stat } from "node:fs/promises";
import type { ScanConfig } from "../types/index.js";

const execAsync = promisify(exec);

export interface PreflightResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
}

async function checkEnv(): Promise<{ errors: string[]; warnings: string[] }> {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!process.env.ANTHROPIC_API_KEY) errors.push("ANTHROPIC_API_KEY is not set");
  if (!process.env.NICO_EXPLOIT_MODEL) {
    warnings.push("NICO_EXPLOIT_MODEL not set — defaulting to claude-sonnet-4-6");
  }
  return { errors, warnings };
}

async function checkDocker(): Promise<string | null> {
  try {
    await execAsync("docker info");
    return null;
  } catch {
    return "Docker daemon is not reachable — sandbox cannot run. Start Docker Desktop or the docker service.";
  }
}

async function checkSourcePath(sourcePath: string): Promise<string | null> {
  try {
    const s = await stat(sourcePath);
    if (!s.isDirectory()) return `Source path is not a directory: ${sourcePath}`;
    return null;
  } catch {
    return `Source path does not exist or is not readable: ${sourcePath}`;
  }
}

async function checkTargetReachable(targetUrl: string, timeoutMs = 5000): Promise<string | null> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return `Invalid target URL: ${targetUrl}`;
  }
  if (!/^https?:$/.test(parsed.protocol)) {
    return `Target URL must use http or https: ${targetUrl}`;
  }
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(targetUrl, { method: "GET", signal: ctrl.signal });
    clearTimeout(timer);
    // Any HTTP response counts — even 404. We only care that something is listening.
    void res.status;
    return null;
  } catch {
    return `Target URL is not reachable: ${targetUrl} — is the application running?`;
  }
}

export async function preflight(config: ScanConfig): Promise<PreflightResult> {
  const errors: string[] = [];
  const warnings: string[] = [];

  const env = await checkEnv();
  errors.push(...env.errors);
  warnings.push(...env.warnings);

  const checks = await Promise.all([
    checkDocker(),
    checkSourcePath(config.sourcePath),
    checkTargetReachable(config.targetUrl),
  ]);
  for (const err of checks) if (err) errors.push(err);

  return { ok: errors.length === 0, errors, warnings };
}
