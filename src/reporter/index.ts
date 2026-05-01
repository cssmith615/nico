import { mkdir, writeFile, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, basename, resolve } from "node:path";
import type { ScanConfig } from "../types/index.js";
import type { ValidatedFinding } from "../validation/index.js";
import { confirmedOnly } from "../validation/index.js";
import { scoreFinding } from "./severity.js";
import { renderMarkdown, type ReportEntry } from "./markdown.js";
import { buildReportJson } from "./json.js";
import { renderHtml } from "./html.js";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 } as const;

export interface ReportOutput {
  reportDir: string;
  markdownPath: string;
  jsonPath: string;
  htmlPath: string;
  confirmedCount: number;
  inconclusiveCount: number;
}

function timestampSlug(date: Date): string {
  // ISO with colons stripped to keep the path Windows-safe
  return date.toISOString().replace(/[:.]/g, "-");
}

async function copyScreenshot(srcPath: string, destDir: string): Promise<string | undefined> {
  if (!existsSync(srcPath)) return undefined;
  const fileName = basename(srcPath);
  const destPath = join(destDir, "evidence", fileName);
  await mkdir(join(destDir, "evidence"), { recursive: true });
  await copyFile(srcPath, destPath);
  return join("evidence", fileName).replace(/\\/g, "/");
}

export async function generateReport(
  findings: ValidatedFinding[],
  config: ScanConfig,
  now: Date = new Date()
): Promise<ReportOutput> {
  const reportDir = resolve(config.outputDir, timestampSlug(now));
  await mkdir(reportDir, { recursive: true });

  const confirmed = confirmedOnly(findings);
  const inconclusive = findings.filter((f) => f.verdict === "inconclusive");

  const entries: ReportEntry[] = [];
  for (const finding of confirmed) {
    const severity = scoreFinding(finding);
    let screenshotRelPath: string | undefined;
    if (finding.result.evidence.screenshotPath) {
      screenshotRelPath = await copyScreenshot(
        finding.result.evidence.screenshotPath,
        reportDir
      );
    }
    entries.push({ finding, severity, screenshotRelPath });
  }
  entries.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity.severity] - SEVERITY_ORDER[b.severity.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.finding.vector.id.localeCompare(b.finding.vector.id);
  });

  const markdown = renderMarkdown(entries, inconclusive, config, now);
  const json = buildReportJson(entries, inconclusive, config, now);
  const html = renderHtml(entries, inconclusive, config, now);

  const markdownPath = join(reportDir, "report.md");
  const jsonPath = join(reportDir, "report.json");
  const htmlPath = join(reportDir, "report.html");

  await writeFile(markdownPath, markdown, "utf-8");
  await writeFile(jsonPath, JSON.stringify(json, null, 2), "utf-8");
  await writeFile(htmlPath, html, "utf-8");

  return {
    reportDir,
    markdownPath,
    jsonPath,
    htmlPath,
    confirmedCount: confirmed.length,
    inconclusiveCount: inconclusive.length,
  };
}
