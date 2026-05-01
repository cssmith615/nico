import type { BaselineEvidence, DiffResult } from "../types/index.js";

const SQL_ERROR_SIGNALS = [
  "syntax error",
  "mysql",
  "postgresql",
  "sqlite",
  "ora-",
  "sequelize",
  "unclosed quotation",
  "unterminated string",
  "you have an error in your sql",
  "pg_query",
  "division by zero",
];

// Signals that indicate real data was returned (auth bypass, data leak)
const DATA_EXFIL_SIGNALS = [
  "token",
  "password",
  "email",
  "admin",
  "secret",
  "role",
  "bearer",
];

interface CorsEvidence {
  acao?: string;
  acac: boolean;
  origin?: string;
}

interface ExploitEvidence {
  statusCode?: number;
  responseBody?: string;
  responseTimeMs?: number;
}

function parseJsonLength(body: string): number {
  try {
    const parsed = JSON.parse(body);
    if (Array.isArray(parsed)) return parsed.length;
    if (parsed && typeof parsed === "object") return Object.keys(parsed).length;
  } catch {
    // Not JSON
  }
  return -1;
}

function parseCorsEvidence(body: string): CorsEvidence | undefined {
  const parts = body
    .split("|")
    .map((part) => part.trim())
    .filter(Boolean);
  const values = new Map<string, string>();
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    values.set(part.slice(0, idx).trim().toLowerCase(), part.slice(idx + 1).trim());
  }

  const acao = values.get("acao");
  const acac = /^true$/i.test(values.get("acac") ?? "");
  const origin = values.get("origin");
  if (!acao && !acac && !origin) return undefined;
  return { acao, acac, origin };
}

function isCorsMisconfig(cors: CorsEvidence | undefined): boolean {
  if (!cors?.acao || !cors.acac) return false;
  const acao = cors.acao.toLowerCase();
  const origin = cors.origin?.toLowerCase();
  return (
    acao === "*" ||
    acao === "null" ||
    (origin !== undefined && origin.length > 0 && acao === origin) ||
    /evil|attacker/.test(acao)
  );
}

export function compareResponses(
  baseline: BaselineEvidence,
  exploit: ExploitEvidence
): DiffResult {
  const baseBody = (baseline.responseBody ?? "").toLowerCase();
  const exploitBody = (exploit.responseBody ?? "").toLowerCase();

  const statusChanged = (baseline.statusCode ?? 0) !== (exploit.statusCode ?? 0);
  const lengthDelta = exploitBody.length - baseBody.length;
  const responseTimeDeltaMs =
    (exploit.responseTimeMs ?? 0) - (baseline.responseTimeMs ?? 0);

  // SQL error keywords that appear in exploit response but NOT in baseline
  const newSqlSignals = SQL_ERROR_SIGNALS.filter(
    (kw) => exploitBody.includes(kw) && !baseBody.includes(kw)
  );

  // JSON array/object size change — data exfil signal
  const baseJsonLen = parseJsonLength(baseline.responseBody ?? "");
  const exploitJsonLen = parseJsonLength(exploit.responseBody ?? "");
  const jsonLengthDelta =
    baseJsonLen >= 0 && exploitJsonLen >= 0 ? exploitJsonLen - baseJsonLen : 0;

  // Auth bypass signal: new data-exfil keywords in exploit response only
  const newDataSignals = DATA_EXFIL_SIGNALS.filter(
    (kw) => exploitBody.includes(kw) && !baseBody.includes(kw)
  );

  // Time-based blind: exploit took >2s longer than baseline
  const timeBased = responseTimeDeltaMs > 2000;
  const corsEvidence = parseCorsEvidence(exploit.responseBody ?? "");
  const corsMisconfig = isCorsMisconfig(corsEvidence);

  // Determine confirmation by diff — independent of what the script claimed
  const confirmedByDiff =
    newSqlSignals.length > 0 ||       // new SQL error in exploit only
    corsMisconfig ||                  // CORS header reflection + credentials
    timeBased ||                        // time-based blind detected
    jsonLengthDelta > 1 ||             // more JSON items returned (threshold avoids single-key object growth)
    (newDataSignals.length >= 2 && lengthDelta > 50) || // auth bypass data
    (statusChanged &&
      exploit.statusCode === 200 &&
      (baseline.statusCode ?? 0) !== 200 &&
      exploitBody.length > 20);       // previously blocked route now returns data

  // Human-readable summary for reporter and judge context
  const signals: string[] = [];
  if (newSqlSignals.length > 0) signals.push(`new SQL signals: ${newSqlSignals.join(", ")}`);
  if (corsMisconfig && corsEvidence) {
    signals.push(`CORS misconfig: ACAO=${corsEvidence.acao ?? "?"}, ACAC=${corsEvidence.acac}`);
  }
  if (timeBased) signals.push(`time delta: +${responseTimeDeltaMs}ms`);
  if (jsonLengthDelta > 0) signals.push(`JSON grew by ${jsonLengthDelta} items`);
  if (newDataSignals.length > 0) signals.push(`new data keywords: ${newDataSignals.join(", ")}`);
  if (statusChanged) signals.push(`status ${baseline.statusCode ?? "?"} → ${exploit.statusCode ?? "?"}`);
  if (lengthDelta !== 0) signals.push(`body length delta: ${lengthDelta > 0 ? "+" : ""}${lengthDelta}`);

  const diffSummary = signals.length > 0 ? signals.join("; ") : "no meaningful diff vs baseline";

  return {
    statusChanged,
    lengthDelta,
    newSqlSignals,
    responseTimeDeltaMs,
    jsonLengthDelta,
    confirmedByDiff,
    diffSummary,
  };
}
