import Anthropic from "@anthropic-ai/sdk";
import type { ScanConfig, AttackVector } from "../types/index.js";

// Sprint 1 implementation target
export async function runOrchestrator(
  _config: ScanConfig
): Promise<AttackVector[]> {
  const _client = new Anthropic();
  // TODO Sprint 1:
  // 1. Walk source files, build context
  // 2. Send to Claude with prompt caching (large source context)
  // 3. Parse attack surface map from response
  // 4. Return ordered task queue
  throw new Error("Orchestrator not implemented — Sprint 1");
}
