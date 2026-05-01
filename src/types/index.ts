import { z } from "zod";

export const VulnClass = z.enum(["sqli", "xss", "auth", "ssrf", "idor"]);
export type VulnClass = z.infer<typeof VulnClass>;

export const AttackVector = z.object({
  id: z.string(),
  vulnClass: VulnClass,
  route: z.string(),
  method: z.string(),
  inputName: z.string(),
  inputType: z.enum(["query", "body", "header", "cookie"]),
  sourceFile: z.string().optional(),
  sourceLine: z.number().nullable().optional(),
  riskScore: z.number().min(0).max(10),
  notes: z.string().optional(),
});
export type AttackVector = z.infer<typeof AttackVector>;

export const ExploitScript = z.object({
  vectorId: z.string(),
  type: z.enum(["playwright", "curl"]),
  script: z.string(),
  payload: z.string(),
});
export type ExploitScript = z.infer<typeof ExploitScript>;

export const BaselineEvidence = z.object({
  statusCode: z.number().optional(),
  responseBody: z.string().optional(),
  responseTimeMs: z.number().optional(),
});
export type BaselineEvidence = z.infer<typeof BaselineEvidence>;

export const DiffResult = z.object({
  statusChanged: z.boolean(),
  lengthDelta: z.number(),
  newSqlSignals: z.array(z.string()),
  responseTimeDeltaMs: z.number(),
  jsonLengthDelta: z.number(),
  confirmedByDiff: z.boolean(),
  diffSummary: z.string(),
});
export type DiffResult = z.infer<typeof DiffResult>;

export const ExploitResult = z.object({
  vectorId: z.string(),
  confirmed: z.boolean(),
  scriptConfirmed: z.boolean().optional(),
  evidence: z.object({
    screenshotPath: z.string().optional(),
    responseBody: z.string().optional(),
    statusCode: z.number().optional(),
    errorMessage: z.string().optional(),
    baseline: BaselineEvidence.optional(),
    diff: DiffResult.optional(),
  }),
  retryCount: z.number().default(0),
});
export type ExploitResult = z.infer<typeof ExploitResult>;

export const Finding = z.object({
  id: z.string(),
  vulnClass: VulnClass,
  title: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  route: z.string(),
  method: z.string(),
  payload: z.string(),
  poc: z.string(),
  evidence: ExploitResult.shape.evidence,
  sourceFile: z.string().optional(),
  sourceLine: z.number().nullable().optional(),
});
export type Finding = z.infer<typeof Finding>;

export interface ScanConfig {
  targetUrl: string;
  sourcePath: string;
  scope: VulnClass[];
  outputDir: string;
  maxRetries: number;
  timeoutMs: number;
}
