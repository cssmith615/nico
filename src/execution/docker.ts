import { exec } from "child_process";
import { promisify } from "util";
import { writeFile, readFile, mkdir, rm } from "fs/promises";
import { join } from "path";
import os from "os";
import crypto from "crypto";

const execAsync = promisify(exec);

export const SANDBOX_IMAGE = "nico-sandbox";

export async function imageExists(): Promise<boolean> {
  try {
    await execAsync(`docker image inspect ${SANDBOX_IMAGE}`);
    return true;
  } catch {
    return false;
  }
}

export async function buildImage(dockerfilePath: string): Promise<void> {
  const context = join(dockerfilePath, "..");
  await execAsync(`docker build -t ${SANDBOX_IMAGE} -f "${dockerfilePath}" "${context}"`);
}

function toDockerVolumePath(hostPath: string): string {
  if (process.platform !== "win32") return hostPath;
  // Convert C:\Users\... → //c/Users/... for Docker Desktop on Windows
  return hostPath.replace(/\\/g, "/").replace(/^([A-Za-z]):/, (_, d) => `//${d.toLowerCase()}`);
}

function adaptForDocker(script: string): string {
  // On non-Linux, localhost inside Docker doesn't reach the host
  if (process.platform === "linux") return script;
  return script
    .replace(/\blocalhost\b/g, "host.docker.internal")
    .replace(/127\.0\.0\.1/g, "host.docker.internal");
}

export interface ContainerResult {
  evidenceJson: string;
  screenshotPath?: string;
  timedOut: boolean;
}

export async function runInContainer(
  script: string,
  scriptType: "curl" | "playwright",
  timeoutMs: number
): Promise<ContainerResult> {
  const id = crypto.randomUUID();
  const workdir = join(os.tmpdir(), `nico-${id}`);
  await mkdir(workdir, { recursive: true });

  const ext = scriptType === "playwright" ? "js" : "sh";
  await writeFile(join(workdir, `exploit.${ext}`), adaptForDocker(script), "utf-8");

  const dockerWorkdir = toDockerVolumePath(workdir);
  const cmd = scriptType === "playwright"
    ? "node /workspace/exploit.js"
    : "bash /workspace/exploit.sh";

  // --add-host ensures host.docker.internal resolves on Linux too
  const dockerRun = `docker run --rm --add-host=host.docker.internal:host-gateway -v "${dockerWorkdir}:/workspace" ${SANDBOX_IMAGE} ${cmd}`;

  let timedOut = false;
  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => {
      timedOut = true;
      reject(new Error("sandbox timeout"));
    }, timeoutMs)
  );

  try {
    await Promise.race([execAsync(dockerRun), timeout]);
  } catch (err) {
    if (!timedOut) {
      // Non-zero exit is expected when exploits fail — evidence file may still be written
    }
  }

  const evidencePath = join(workdir, "evidence.json");
  let evidenceJson = '{"confirmed":false,"payload":"","response":"script did not produce evidence","statusCode":0}';
  try {
    evidenceJson = await readFile(evidencePath, "utf-8");
  } catch {
    // Script crashed before writing evidence
  }

  let screenshotPath: string | undefined;
  try {
    await readFile(join(workdir, "evidence.png"));
    screenshotPath = join(workdir, "evidence.png");
  } catch {
    // No screenshot (curl exploits, or playwright didn't confirm)
  }

  try {
    await rm(workdir, { recursive: true, force: true });
  } catch {
    // Non-fatal
  }

  return { evidenceJson, screenshotPath, timedOut };
}
