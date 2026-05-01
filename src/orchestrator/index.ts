import type { ScanConfig, AttackVector } from "../types/index.js";
import { walkSource } from "./walker.js";
import { analyzeAttackSurface } from "./analyzer.js";

export async function runOrchestrator(config: ScanConfig): Promise<AttackVector[]> {
  const files = await walkSource(config.sourcePath);
  if (files.length === 0) {
    throw new Error(`No source files found at: ${config.sourcePath}`);
  }
  return analyzeAttackSurface(files, config.scope);
}
