import { exec, spawn } from "child_process";
import { promisify } from "util";
import { writeFile, readFile, mkdir, rm, copyFile } from "fs/promises";
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
  const containerName = `nico-${id}`;
  const workdir = join(os.tmpdir(), `nico-${id}`);
  await mkdir(workdir, { recursive: true });

  const ext = scriptType === "playwright" ? "js" : "sh";
  await writeFile(join(workdir, `exploit.${ext}`), adaptForDocker(script), "utf-8");

  const dockerWorkdir = toDockerVolumePath(workdir);
  const cmd = scriptType === "playwright"
    ? ["node", "/workspace/exploit.js"]
    : ["bash", "/workspace/exploit.sh"];

  const timedOut = await runDockerContainer(containerName, dockerWorkdir, cmd, timeoutMs);

  const evidencePath = join(workdir, "evidence.json");
  let evidenceJson = '{"confirmed":false,"payload":"","response":"script did not produce evidence","statusCode":0}';
  try {
    evidenceJson = await readFile(evidencePath, "utf-8");
  } catch {
    // Script crashed before writing evidence
  }

  let screenshotPath: string | undefined;
  const containerScreenshotPath = join(workdir, "evidence.png");
  try {
    await readFile(containerScreenshotPath);
    screenshotPath = join(os.tmpdir(), `nico-evidence-${id}.png`);
    await copyFile(containerScreenshotPath, screenshotPath);
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

async function runDockerContainer(
  containerName: string,
  dockerWorkdir: string,
  cmd: string[],
  timeoutMs: number
): Promise<boolean> {
  const args = [
    "run",
    "--rm",
    "--name", containerName,
    "--add-host=host.docker.internal:host-gateway",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--read-only",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
    "--tmpfs", "/home/pwuser:rw,nosuid,nodev,size=128m",
    "--memory=512m",
    "--cpus=1",
    "--pids-limit=128",
    "--network=bridge",
    "--shm-size=256m",
    "-e", "HOME=/tmp",
    "-v", `${dockerWorkdir}:/workspace:rw`,
    SANDBOX_IMAGE,
    ...cmd,
  ];

  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    const child = spawn("docker", args, { stdio: "ignore" });

    const timer = setTimeout(() => {
      timedOut = true;
      exec(`docker rm -f ${containerName}`, () => undefined);
      child.kill("SIGKILL");
    }, timeoutMs);

    child.on("error", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(false);
    });

    child.on("close", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(timedOut);
    });
  });
}
