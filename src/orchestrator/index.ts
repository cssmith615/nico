import type { ScanConfig, AttackVector } from "../types/index.js";
import { walkSource } from "./walker.js";
import { analyzeAttackSurface } from "./analyzer.js";
import { ingestOpenAPI } from "./openapi.js";

export async function runOrchestrator(config: ScanConfig): Promise<AttackVector[]> {
  if (config.openApiPath) {
    return ingestOpenAPI(config.openApiPath, config.scope);
  }

  if (!config.sourcePath) {
    throw new Error("Either --source or --openapi must be provided");
  }

  const files = await walkSource(config.sourcePath);
  if (files.length === 0) {
    throw new Error(`No source files found at: ${config.sourcePath}`);
  }
  return analyzeAttackSurface(files, config.scope);
}
