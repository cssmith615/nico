import Anthropic from "@anthropic-ai/sdk";
import { AttackVector, VulnClass } from "../types/index.js";
import type { SourceFile } from "./walker.js";

const SYSTEM_PROMPT = `You are a senior penetration tester and secure code reviewer. Analyze web application source code and identify attack surfaces for a given set of vulnerability classes.

Return ONLY a valid JSON array. No explanation, no markdown, no code fences. Raw JSON only.

Each element must match this exact schema:
{
  "id": "string — unique, e.g. sqli-001",
  "vulnClass": "sqli" | "xss" | "auth" | "ssrf" | "idor",
  "route": "string — HTTP path, e.g. /api/users",
  "method": "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
  "inputName": "string — exact parameter name",
  "inputType": "query" | "body" | "header" | "cookie",
  "sourceFile": "string — relative file path",
  "sourceLine": number or null,
  "riskScore": number between 0 and 10,
  "notes": "string — specific reason this is exploitable"
}

Rules:
- Only include vectors with a realistic exploitation path
- Be specific: name the exact input, route, and the vulnerable code pattern
- Order by riskScore descending
- Omit theoretical findings with no clear sink`;

function extractJson(text: string): string {
  const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) return fenceMatch[1].trim();
  const arrayMatch = text.match(/\[[\s\S]*\]/);
  if (arrayMatch) return arrayMatch[0];
  return text.trim();
}

export async function analyzeAttackSurface(
  files: SourceFile[],
  scope: VulnClass[]
): Promise<AttackVector[]> {
  const client = new Anthropic({
    defaultHeaders: { "anthropic-beta": "prompt-caching-2024-07-31" },
  });

  const sourceContext = files
    .map((f) => `// FILE: ${f.relativePath}\n\`\`\`${f.language}\n${f.content}\n\`\`\``)
    .join("\n\n---\n\n");

  const response = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 4096,
    system: [
      {
        type: "text",
        text: SYSTEM_PROMPT,
        // @ts-expect-error cache_control not yet in SDK types for system blocks
        cache_control: { type: "ephemeral" },
      },
    ],
    messages: [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: sourceContext,
            // @ts-expect-error cache_control not yet in SDK types for content blocks
            cache_control: { type: "ephemeral" },
          },
          {
            type: "text",
            text: `Identify attack vectors for these vulnerability classes: ${scope.join(", ")}.\n\nReturn the JSON array.`,
          },
        ],
      },
    ],
  });

  const raw = response.content[0].type === "text" ? response.content[0].text : "[]";
  const json = extractJson(raw);

  let parsed: unknown[];
  try {
    parsed = JSON.parse(json) as unknown[];
  } catch {
    throw new Error(`Orchestrator returned unparseable JSON:\n${raw.slice(0, 500)}`);
  }

  return parsed.map((v, i) => {
    const result = AttackVector.safeParse(v);
    if (!result.success) {
      throw new Error(`Vector ${i} failed validation: ${result.error.message}`);
    }
    return result.data;
  });
}
