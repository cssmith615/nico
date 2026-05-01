import type { Finding, ScanConfig } from "../types/index.js";

// Sprint 5 implementation target
export async function generateReport(
  findings: Finding[],
  _config: ScanConfig
): Promise<string> {
  // TODO Sprint 5:
  // 1. Build structured JSON report
  // 2. Generate markdown with PoC per finding
  // 3. CVSS-lite severity scoring
  // 4. Write to config.outputDir/<timestamp>/
  void findings;
  throw new Error("Reporter not implemented — Sprint 5");
}
