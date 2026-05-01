import { Finding, type ScanConfig } from "../types/index.js";
import type { ValidatedFinding } from "../validation/index.js";
import type { ReportEntry } from "./markdown.js";
import { findingId } from "./markdown.js";

export interface ReportJson {
  generatedAt: string;
  target: string;
  source: string;
  scope: string[];
  summary: {
    confirmed: number;
    inconclusive: number;
  };
  findings: Array<
    ReturnType<typeof toFinding> & {
      severity: string;
      score: number;
      rationale: string;
    }
  >;
  inconclusive: Array<{
    vulnClass: string;
    route: string;
    method: string;
    input: string;
    reasoning: string;
  }>;
}

function toFinding(entry: ReportEntry, idx: number) {
  const { finding, severity, screenshotRelPath } = entry;
  const v = finding.vector;
  const r = finding.result;
  const s = finding.script;

  const candidate = {
    id: findingId(entry, idx),
    vulnClass: v.vulnClass,
    title: `${v.vulnClass.toUpperCase()} in ${v.method} ${v.route} via ${v.inputName}`,
    severity: severity.severity,
    route: v.route,
    method: v.method,
    payload: s.payload,
    poc: s.script,
    evidence: {
      screenshotPath: screenshotRelPath ?? r.evidence.screenshotPath,
      responseBody: r.evidence.responseBody,
      statusCode: r.evidence.statusCode,
      errorMessage: r.evidence.errorMessage,
    },
    sourceFile: v.sourceFile,
    sourceLine: v.sourceLine,
  };

  return Finding.parse(candidate);
}

export function buildReportJson(
  confirmed: ReportEntry[],
  inconclusive: ValidatedFinding[],
  config: ScanConfig,
  generatedAt: Date
): ReportJson {
  return {
    generatedAt: generatedAt.toISOString(),
    target: config.targetUrl,
    source: config.sourcePath,
    scope: config.scope,
    summary: {
      confirmed: confirmed.length,
      inconclusive: inconclusive.length,
    },
    findings: confirmed.map((entry, idx) => ({
      ...toFinding(entry, idx),
      severity: entry.severity.severity,
      score: entry.severity.score,
      rationale: entry.severity.rationale,
    })),
    inconclusive: inconclusive.map((f) => ({
      vulnClass: f.vector.vulnClass,
      route: f.vector.route,
      method: f.vector.method,
      input: f.vector.inputName,
      reasoning: f.reasoning,
    })),
  };
}
