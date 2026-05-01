import type { ScanConfig } from "../types/index.js";
import type { ValidatedFinding } from "../validation/index.js";
import type { ReportEntry } from "./markdown.js";
import { findingId } from "./markdown.js";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(value: unknown): string {
  return escapeHtml(value);
}

const CSS = `
:root {
  --bg: #f6f7f9;
  --panel: #ffffff;
  --panel-strong: #111827;
  --border: #d7dde5;
  --border-strong: #aeb9c8;
  --text: #172033;
  --muted: #667085;
  --accent: #2563eb;
  --critical: #d92d20;
  --high: #c25700;
  --medium: #946200;
  --low: #087443;
  --critical-soft: #fff1f0;
  --high-soft: #fff4e6;
  --medium-soft: #fff8db;
  --low-soft: #eaf8ef;
  --code-bg: #111827;
  --code-text: #f9fafb;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
header {
  background: var(--panel-strong);
  color: #ffffff;
  border-bottom: 1px solid var(--border);
  padding: 28px 32px;
}
header h1 { margin: 0 0 10px 0; font-size: 24px; }
header .meta {
  color: #cbd5e1;
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  font-size: 13px;
}
header .meta span { overflow-wrap: anywhere; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 32px; }
.summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}
.count-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 16px;
  text-align: center;
}
.count-card .num { font-size: 28px; font-weight: 600; }
.count-card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0; }
.count-card.critical .num { color: var(--critical); }
.count-card.high .num { color: var(--high); }
.count-card.medium .num { color: var(--medium); }
.count-card.low .num { color: var(--low); }
.controls {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.controls input, .controls select {
  background: var(--panel);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 12px;
  font: inherit;
  min-height: 42px;
}
.controls input { flex: 1; min-width: 200px; }
details.finding {
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 4px solid var(--border);
  border-radius: 6px;
  margin-bottom: 12px;
  overflow: hidden;
}
details.finding[data-severity="critical"] { border-left-color: var(--critical); }
details.finding[data-severity="high"] { border-left-color: var(--high); }
details.finding[data-severity="medium"] { border-left-color: var(--medium); }
details.finding[data-severity="low"] { border-left-color: var(--low); }
details.finding summary {
  padding: 14px 18px;
  cursor: pointer;
  list-style: none;
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}
details.finding summary::-webkit-details-marker { display: none; }
.severity-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0;
  white-space: nowrap;
}
.severity-badge.critical { background: var(--critical); color: #fff; }
.severity-badge.high { background: var(--high); color: #fff; }
.severity-badge.medium { background: var(--medium); color: #fff; }
.severity-badge.low { background: var(--low); color: #fff; }
.score { font-size: 12px; color: var(--muted); }
.endpoint {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px;
  overflow-wrap: anywhere;
  min-width: 0;
}
.finding-id { color: var(--muted); font-size: 12px; margin-left: auto; font-family: ui-monospace, monospace; }
.finding-body {
  padding: 0 18px 18px 18px;
  border-top: 1px solid var(--border);
  padding-top: 16px;
}
.finding-body h3 { font-size: 13px; text-transform: uppercase; color: var(--muted); margin: 16px 0 8px 0; letter-spacing: 0; }
.kv { display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; font-size: 13px; }
.kv .k { color: var(--muted); }
.kv .v { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
pre {
  background: var(--code-bg);
  color: var(--code-text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  overflow-x: auto;
  font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  margin: 8px 0;
}
.inconclusive {
  margin-top: 32px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 16px 20px;
}
.inconclusive h2 { margin-top: 0; font-size: 16px; }
.inconclusive table { width: 100%; font-size: 13px; border-collapse: collapse; table-layout: fixed; }
.inconclusive td, .inconclusive th { padding: 6px 8px; text-align: left; border-bottom: 1px solid var(--border); }
.inconclusive th { color: var(--muted); font-weight: normal; font-size: 11px; text-transform: uppercase; letter-spacing: 0; }
.inconclusive td { overflow-wrap: anywhere; vertical-align: top; }
.inconclusive .reasoning-cell {
  color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  line-height: 1.45;
  white-space: pre-wrap;
}
.empty {
  text-align: center;
  padding: 40px;
  color: var(--muted);
  background: var(--panel);
  border: 1px dashed var(--border);
  border-radius: 6px;
}
.hidden { display: none !important; }
.no-match { text-align: center; padding: 24px; color: var(--muted); display: none; }
.no-match.show { display: block; }
footer { text-align: center; color: var(--muted); font-size: 12px; padding: 24px; }
footer a { color: var(--accent); }
@media (max-width: 720px) {
  header, main { padding-left: 18px; padding-right: 18px; }
  details.finding summary { align-items: flex-start; flex-wrap: wrap; }
  .finding-id { margin-left: 0; width: 100%; }
  .kv { grid-template-columns: 1fr; }
  .controls input, .controls select { width: 100%; }
  .inconclusive table, .inconclusive thead, .inconclusive tbody, .inconclusive tr, .inconclusive th, .inconclusive td {
    display: block;
    width: 100%;
  }
  .inconclusive thead { display: none; }
  .inconclusive tr { padding: 10px 0; border-bottom: 1px solid var(--border); }
  .inconclusive td { border-bottom: 0; padding: 3px 0; }
}
`;

const JS = `
(function () {
  const search = document.getElementById('q');
  const sevFilter = document.getElementById('sev');
  const classFilter = document.getElementById('cls');
  const findings = Array.from(document.querySelectorAll('details.finding'));
  const noMatch = document.getElementById('no-match');

  function apply() {
    const q = (search.value || '').toLowerCase();
    const sev = sevFilter.value;
    const cls = classFilter.value;
    let visible = 0;
    for (const f of findings) {
      const matchSev = !sev || f.dataset.severity === sev;
      const matchCls = !cls || f.dataset.class === cls;
      const haystack = (f.dataset.search || '').toLowerCase();
      const matchQ = !q || haystack.indexOf(q) !== -1;
      const show = matchSev && matchCls && matchQ;
      f.classList.toggle('hidden', !show);
      if (show) visible++;
    }
    noMatch.classList.toggle('show', visible === 0 && findings.length > 0);
  }

  for (const el of [search, sevFilter, classFilter]) {
    el.addEventListener('input', apply);
    el.addEventListener('change', apply);
  }
})();
`;

function renderFinding(entry: ReportEntry, idx: number): string {
  const id = findingId(entry, idx);
  const v = entry.finding.vector;
  const r = entry.finding.result;
  const s = entry.finding.script;
  const sev = entry.severity.severity;
  const score = entry.severity.score;
  const haystack = [
    id,
    v.route,
    v.method,
    v.inputName,
    v.vulnClass,
    v.notes ?? "",
    v.sourceFile ?? "",
    s.payload ?? "",
    entry.finding.reasoning,
  ]
    .join(" ")
    .toLowerCase();

  const lines: string[] = [];
  lines.push(
    `<details class="finding" data-severity="${escapeAttr(sev)}" data-class="${escapeAttr(v.vulnClass)}" data-search="${escapeAttr(haystack)}">`
  );
  lines.push("  <summary>");
  lines.push(`    <span class="severity-badge ${escapeAttr(sev)}">${escapeHtml(sev)}</span>`);
  lines.push(`    <span class="score">${score.toFixed(1)} / 10</span>`);
  lines.push(`    <span class="endpoint">${escapeHtml(v.method)} ${escapeHtml(v.route)}</span>`);
  lines.push(`    <span class="finding-id">${escapeHtml(id)}</span>`);
  lines.push("  </summary>");
  lines.push('  <div class="finding-body">');
  lines.push("    <h3>Attack vector</h3>");
  lines.push('    <div class="kv">');
  lines.push(`      <div class="k">Class</div><div class="v">${escapeHtml(v.vulnClass)}</div>`);
  lines.push(`      <div class="k">Route</div><div class="v">${escapeHtml(v.method)} ${escapeHtml(v.route)}</div>`);
  lines.push(`      <div class="k">Input</div><div class="v">${escapeHtml(v.inputName)} (${escapeHtml(v.inputType)})</div>`);
  if (v.sourceFile) {
    const loc = v.sourceLine != null ? `${v.sourceFile}:${v.sourceLine}` : v.sourceFile;
    lines.push(`      <div class="k">Source</div><div class="v">${escapeHtml(loc)}</div>`);
  }
  if (v.notes) lines.push(`      <div class="k">Notes</div><div class="v">${escapeHtml(v.notes)}</div>`);
  lines.push("    </div>");
  lines.push("    <h3>Severity</h3>");
  lines.push(`    <div class="kv"><div class="k">Score</div><div class="v">${score.toFixed(1)} / 10 (${escapeHtml(sev)})</div></div>`);
  lines.push(`    <div class="kv"><div class="k">Rationale</div><div class="v">${escapeHtml(entry.severity.rationale)}</div></div>`);
  lines.push(`    <div class="kv"><div class="k">Verdict</div><div class="v">${escapeHtml(entry.finding.reasoning)}</div></div>`);
  lines.push("    <h3>Proof of concept</h3>");
  lines.push(`    <div class="kv"><div class="k">Payload</div><div class="v">${escapeHtml(s.payload || "(not extracted)")}</div></div>`);
  lines.push(`    <pre>${escapeHtml(s.script)}</pre>`);
  lines.push("    <h3>Evidence</h3>");
  if (r.evidence.statusCode !== undefined) {
    lines.push(`    <div class="kv"><div class="k">HTTP status</div><div class="v">${escapeHtml(r.evidence.statusCode)}</div></div>`);
  }
  if (r.evidence.responseBody) {
    lines.push(`    <pre>${escapeHtml(r.evidence.responseBody.slice(0, 1000))}</pre>`);
  }
  if (entry.screenshotRelPath) {
    lines.push(`    <div class="kv"><div class="k">Screenshot</div><div class="v"><a href="${escapeAttr(entry.screenshotRelPath)}">${escapeHtml(entry.screenshotRelPath)}</a></div></div>`);
  }
  if (r.evidence.errorMessage) {
    lines.push(`    <div class="kv"><div class="k">Error</div><div class="v">${escapeHtml(r.evidence.errorMessage)}</div></div>`);
  }
  lines.push("  </div>");
  lines.push("</details>");
  return lines.join("\n");
}

export function renderHtml(
  confirmed: ReportEntry[],
  inconclusive: ValidatedFinding[],
  config: ScanConfig,
  generatedAt: Date
): string {
  const sorted = [...confirmed].sort((a, b) => {
    const order = SEV_ORDER[a.severity.severity] - SEV_ORDER[b.severity.severity];
    if (order !== 0) return order;
    return a.finding.vector.id.localeCompare(b.finding.vector.id);
  });

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const e of sorted) counts[e.severity.severity]++;

  const classes = Array.from(new Set(sorted.map((e) => e.finding.vector.vulnClass)));

  const body: string[] = [];
  body.push("<header>");
  body.push("  <h1>Nico Scan Report</h1>");
  body.push('  <div class="meta">');
  body.push(`    <span>Generated: ${escapeHtml(generatedAt.toISOString())}</span>`);
  body.push(`    <span>Target: ${escapeHtml(config.targetUrl)}</span>`);
  body.push(`    <span>Source: ${escapeHtml(config.sourcePath ?? config.openApiPath ?? "(none)")}</span>`);
  body.push(`    <span>Scope: ${escapeHtml(config.scope.join(", "))}</span>`);
  body.push("  </div>");
  body.push("</header>");
  body.push("<main>");
  body.push('  <section class="summary">');
  for (const sev of ["critical", "high", "medium", "low"] as const) {
    body.push(`    <div class="count-card ${sev}"><div class="num">${counts[sev]}</div><div class="label">${sev}</div></div>`);
  }
  body.push("  </section>");

  if (sorted.length === 0) {
    body.push('  <div class="empty">No confirmed vulnerabilities.</div>');
  } else {
    body.push('  <section class="controls">');
    body.push('    <input id="q" type="search" placeholder="Filter by route, payload, source...">');
    body.push('    <select id="sev"><option value="">All severities</option>');
    for (const sev of ["critical", "high", "medium", "low"]) {
      body.push(`      <option value="${sev}">${sev}</option>`);
    }
    body.push("    </select>");
    body.push('    <select id="cls"><option value="">All classes</option>');
    for (const cls of classes) {
      body.push(`      <option value="${escapeAttr(cls)}">${escapeHtml(cls)}</option>`);
    }
    body.push("    </select>");
    body.push("  </section>");
    body.push('  <section class="findings">');
    for (let i = 0; i < sorted.length; i++) {
      body.push(renderFinding(sorted[i], i));
    }
    body.push('    <div class="no-match" id="no-match">No findings match the current filters.</div>');
    body.push("  </section>");
  }

  if (inconclusive.length > 0) {
    body.push('  <section class="inconclusive">');
    body.push("    <h2>Inconclusive</h2>");
    body.push("    <table>");
    body.push("      <colgroup><col style=\"width:9%\"><col style=\"width:24%\"><col style=\"width:15%\"><col style=\"width:52%\"></colgroup>");
    body.push("      <thead><tr><th>Class</th><th>Endpoint</th><th>Input</th><th>Reasoning</th></tr></thead>");
    body.push("      <tbody>");
    for (const f of inconclusive) {
      body.push("        <tr>");
      body.push(`          <td>${escapeHtml(f.vector.vulnClass)}</td>`);
      body.push(`          <td>${escapeHtml(f.vector.method)} ${escapeHtml(f.vector.route)}</td>`);
      body.push(`          <td>${escapeHtml(f.vector.inputName)}</td>`);
      body.push(`          <td class="reasoning-cell">${escapeHtml(f.reasoning)}</td>`);
      body.push("        </tr>");
    }
    body.push("      </tbody>");
    body.push("    </table>");
    body.push("  </section>");
  }

  body.push("</main>");
  body.push('<footer>Generated by <a href="https://github.com/cssmith615/nico">Nico</a></footer>');
  if (sorted.length > 0) body.push(`<script>${JS}</script>`);

  return [
    "<!DOCTYPE html>",
    '<html lang="en">',
    "<head>",
    '  <meta charset="utf-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1">',
    "  <title>Nico Scan Report</title>",
    `  <style>${CSS}</style>`,
    "</head>",
    "<body>",
    body.join("\n"),
    "</body>",
    "</html>",
    "",
  ].join("\n");
}
