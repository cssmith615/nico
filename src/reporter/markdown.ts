import type { ValidatedFinding } from "../validation/index.js";
import type { ScanConfig } from "../types/index.js";
import type { SeverityScore } from "./severity.js";

export interface ReportEntry {
  finding: ValidatedFinding;
  severity: SeverityScore;
  screenshotRelPath?: string;
}

function severityBadge(sev: SeverityScore["severity"]): string {
  const tag = sev.toUpperCase();
  return `**[${tag}]**`;
}

function fence(lang: string, body: string): string {
  return "```" + lang + "\n" + body.trimEnd() + "\n```";
}

function findingId(entry: ReportEntry, idx: number): string {
  const cls = entry.finding.vector.vulnClass.toUpperCase();
  return `NICO-${cls}-${String(idx + 1).padStart(3, "0")}`;
}

function summaryRow(entry: ReportEntry, idx: number): string {
  const { finding, severity } = entry;
  return `| ${findingId(entry, idx)} | ${severity.severity.toUpperCase()} | ${severity.score.toFixed(1)} | ${finding.vector.vulnClass.toUpperCase()} | ${finding.vector.method} ${finding.vector.route} | ${finding.vector.inputName} (${finding.vector.inputType}) |`;
}

function findingBlock(entry: ReportEntry, idx: number): string {
  const { finding, severity, screenshotRelPath } = entry;
  const v = finding.vector;
  const r = finding.result;
  const s = finding.script;

  const lines: string[] = [];
  lines.push(`## ${findingId(entry, idx)} — ${severityBadge(severity.severity)} ${v.vulnClass.toUpperCase()} in \`${v.method} ${v.route}\``);
  lines.push("");
  lines.push(`**Severity:** ${severity.severity} (${severity.score.toFixed(1)} / 10)`);
  lines.push(`**Rationale:** ${severity.rationale}`);
  lines.push(`**Verdict reasoning:** ${finding.reasoning}`);
  lines.push("");
  lines.push("### Attack vector");
  lines.push("");
  lines.push(`- **Route:** \`${v.method} ${v.route}\``);
  lines.push(`- **Input:** \`${v.inputName}\` (${v.inputType})`);
  if (v.sourceFile) {
    const loc = v.sourceLine != null ? `${v.sourceFile}:${v.sourceLine}` : v.sourceFile;
    lines.push(`- **Source:** \`${loc}\``);
  }
  if (v.notes) lines.push(`- **Notes:** ${v.notes}`);
  lines.push("");
  lines.push("### Proof of concept");
  lines.push("");
  lines.push(`**Payload:** \`${s.payload || "(not extracted)"}\``);
  lines.push("");
  lines.push(fence(s.type === "playwright" ? "javascript" : "bash", s.script));
  lines.push("");
  lines.push("### Evidence");
  lines.push("");
  if (r.evidence.statusCode !== undefined) lines.push(`- **HTTP status:** ${r.evidence.statusCode}`);
  if (r.evidence.responseBody) {
    const body = r.evidence.responseBody.slice(0, 1000);
    lines.push("- **Response body (truncated to 1000 chars):**");
    lines.push("");
    lines.push(fence("text", body));
  }
  if (screenshotRelPath) {
    lines.push("");
    lines.push(`- **Screenshot:** [\`${screenshotRelPath}\`](${screenshotRelPath})`);
  }
  if (r.evidence.errorMessage) lines.push(`- **Error:** ${r.evidence.errorMessage}`);
  lines.push("");

  return lines.join("\n");
}

function inconclusiveRow(finding: ValidatedFinding): string {
  const v = finding.vector;
  return `| ${v.vulnClass.toUpperCase()} | ${v.method} ${v.route} | ${v.inputName} | ${finding.reasoning} |`;
}

export function renderMarkdown(
  confirmed: ReportEntry[],
  inconclusive: ValidatedFinding[],
  config: ScanConfig,
  generatedAt: Date
): string {
  const out: string[] = [];
  out.push("# Nico Scan Report");
  out.push("");
  out.push(`**Generated:** ${generatedAt.toISOString()}`);
  out.push(`**Target:** ${config.targetUrl}`);
  out.push(`**Source:** ${config.sourcePath}`);
  out.push(`**Scope:** ${config.scope.join(", ")}`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push(`- **Confirmed findings:** ${confirmed.length}`);
  out.push(`- **Inconclusive:** ${inconclusive.length}`);
  out.push("");

  if (confirmed.length > 0) {
    out.push("| ID | Severity | Score | Class | Endpoint | Input |");
    out.push("|---|---|---|---|---|---|");
    for (let i = 0; i < confirmed.length; i++) {
      out.push(summaryRow(confirmed[i], i));
    }
    out.push("");
    out.push("---");
    out.push("");
    out.push("# Findings");
    out.push("");
    for (let i = 0; i < confirmed.length; i++) {
      out.push(findingBlock(confirmed[i], i));
      out.push("---");
      out.push("");
    }
  } else {
    out.push("_No confirmed vulnerabilities._");
    out.push("");
  }

  if (inconclusive.length > 0) {
    out.push("## Inconclusive");
    out.push("");
    out.push("These vectors triggered the sandbox but the judge could not confirm exploitation.");
    out.push("");
    out.push("| Class | Endpoint | Input | Reasoning |");
    out.push("|---|---|---|---|");
    for (const f of inconclusive) out.push(inconclusiveRow(f));
    out.push("");
  }

  return out.join("\n");
}

export { findingId };
