import { readFile } from "node:fs/promises";
import type { AttackVector, VulnClass } from "../types/index.js";

const SSRF_KW = ["url", "webhook", "redirect", "endpoint", "callback", "href", "uri", "host", "server", "target", "dest", "destination", "proxy", "fetch", "src", "link", "path"];
const IDOR_KW = ["id", "uuid", "guid", "uid", "account", "record", "user", "document", "file", "resource", "object"];
const SQLI_KW = ["q", "query", "search", "filter", "where", "sort", "order", "name", "email", "username", "login", "keyword", "term", "text", "field", "column", "username"];
const XSS_KW = ["message", "comment", "description", "content", "body", "note", "html", "markup", "template", "bio", "about", "profile", "title", "subject"];

const HTTP_METHODS = ["get", "post", "put", "delete", "patch", "options", "head"] as const;
type HttpMethod = (typeof HTTP_METHODS)[number];

function matches(paramName: string, kw: string[]): boolean {
  const lower = paramName.toLowerCase();
  return kw.some((k) => lower === k || lower.includes(k));
}

function isIdLike(paramName: string): boolean {
  const lower = paramName.toLowerCase();
  return lower === "id" || lower.endsWith("id") || lower.endsWith("_id") || lower.startsWith("id_");
}

function inferVulnClasses(
  paramName: string,
  paramIn: string,
  method: HttpMethod,
  scope: VulnClass[]
): VulnClass[] {
  const result: VulnClass[] = [];
  const loc = paramIn;

  if (scope.includes("ssrf") && matches(paramName, SSRF_KW)) result.push("ssrf");

  if (scope.includes("idor") && (loc === "path" || loc === "query") && isIdLike(paramName)) {
    result.push("idor");
  }

  if (scope.includes("sqli") && matches(paramName, SQLI_KW)) result.push("sqli");

  if (scope.includes("xss") && matches(paramName, XSS_KW) &&
    ["post", "put", "patch"].includes(method)) {
    result.push("xss");
  }

  // Fallback: any string query or body param is a potential sqli surface
  if (result.length === 0 && scope.includes("sqli") && (loc === "query" || loc === "body")) {
    result.push("sqli");
  }

  return result;
}

function baseRisk(vulnClass: VulnClass, method: HttpMethod): number {
  const scores: Record<VulnClass, number> = { ssrf: 9, sqli: 8, auth: 8, idor: 7, xss: 6 };
  const boost = ["post", "put", "delete", "patch"].includes(method) ? 1 : 0;
  return Math.min(10, scores[vulnClass] + boost);
}

function mapInputType(paramIn: string): "query" | "body" | "header" | "cookie" | "path" {
  switch (paramIn) {
    case "path": return "path";
    case "header": return "header";
    case "cookie": return "cookie";
    case "body":
    case "requestBody": return "body";
    default: return "query";
  }
}

interface OpenApiParam { name: string; in: string }

export async function ingestOpenAPI(specPath: string, scope: VulnClass[]): Promise<AttackVector[]> {
  if (/\.(ya?ml)$/i.test(specPath)) {
    throw new Error(
      `YAML specs are not yet supported — convert to JSON first:\n` +
      `  npx @apidevtools/swagger-cli bundle -o openapi.json ${specPath}`
    );
  }

  const raw = await readFile(specPath, "utf-8");
  let spec: { paths?: Record<string, Record<string, unknown>> };
  try {
    spec = JSON.parse(raw) as typeof spec;
  } catch {
    throw new Error(`Failed to parse OpenAPI spec as JSON: ${specPath}`);
  }

  if (!spec.paths || typeof spec.paths !== "object") {
    throw new Error(`OpenAPI spec has no paths defined: ${specPath}`);
  }

  const vectors: AttackVector[] = [];
  const counters: Partial<Record<VulnClass, number>> = {};

  for (const [route, pathItem] of Object.entries(spec.paths)) {
    if (!pathItem || typeof pathItem !== "object") continue;

    const pathParams = ((pathItem as Record<string, unknown>).parameters as OpenApiParam[] | undefined) ?? [];

    for (const method of HTTP_METHODS) {
      const op = (pathItem as Record<string, unknown>)[method] as Record<string, unknown> | undefined;
      if (!op || typeof op !== "object") continue;

      const params: OpenApiParam[] = [
        ...pathParams,
        ...((op.parameters as OpenApiParam[] | undefined) ?? []),
      ];

      if (op.requestBody && ["post", "put", "patch"].includes(method)) {
        params.push({ name: "body", in: "body" });
      }

      const seen = new Set<string>();
      for (const param of params) {
        if (!param.name || !param.in) continue;
        const key = `${param.name}:${param.in}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const classes = inferVulnClasses(param.name, param.in, method, scope);
        for (const vulnClass of classes) {
          counters[vulnClass] = (counters[vulnClass] ?? 0) + 1;
          vectors.push({
            id: `${vulnClass}-${String(counters[vulnClass]).padStart(3, "0")}`,
            vulnClass,
            route,
            method: method.toUpperCase(),
            inputName: param.name,
            inputType: mapInputType(param.in),
            riskScore: baseRisk(vulnClass, method),
            notes: `OpenAPI spec — ${param.in} parameter`,
          });
        }
      }
    }
  }

  return vectors.sort((a, b) => b.riskScore - a.riskScore);
}
