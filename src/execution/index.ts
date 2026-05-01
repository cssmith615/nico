import type { ExploitScript, ExploitResult } from "../types/index.js";

// Sprint 3 implementation target
export async function runInSandbox(
  script: ExploitScript,
  _timeoutMs: number
): Promise<ExploitResult> {
  // TODO Sprint 3:
  // 1. Spin up Docker container with sandbox image
  // 2. Write script to container
  // 3. Execute with Playwright or curl
  // 4. Capture evidence (screenshot, response body)
  // 5. Determine confirmed vs. not
  // 6. Tear down container
  void script;
  throw new Error("Execution sandbox not implemented — Sprint 3");
}
