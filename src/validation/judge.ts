import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";
import type { ExploitResult, AttackVector, ExploitScript } from "../types/index.js";

const JudgeResponse = z.object({
  verdict: z.enum(["confirmed", "false_positive", "inconclusive"]),
  reasoning: z.string(),
});

export type JudgeVerdict = z.infer<typeof JudgeResponse>;

function buildPrompt(
  result: ExploitResult,
  vector: AttackVector,
  script: ExploitScript
): string {
  return `You are a senior penetration tester reviewing an automated exploit result.

Attack vector:
- Route: ${vector.route}
- Method: ${vector.method}
- Input: ${vector.inputName} (${vector.inputType})
- Vuln class: ${vector.vulnClass}
- Notes: ${vector.notes ?? "none"}

Payload used: ${script.payload || "(not extracted)"}
Script type: ${script.type}

Evidence:
- HTTP status: ${result.evidence.statusCode ?? "unknown"}
- Response body (first 500 chars): ${result.evidence.responseBody?.slice(0, 500) ?? "(empty)"}
- Screenshot captured: ${result.evidence.screenshotPath ? "yes" : "no"}
- Retry count: ${result.retryCount}

The sandbox marked this as CONFIRMED. Is this a genuine vulnerability, a false positive, or inconclusive?

Common false positive patterns:
- Server always returns 500 (broken app, not injection)
- Response body is a generic error page unrelated to the payload
- Payload appears in response but is HTML-escaped (not a real XSS)
- Status 200 but response is empty or identical to a non-injected baseline

Respond with ONLY valid JSON — no explanation, no markdown:
{"verdict":"confirmed"|"false_positive"|"inconclusive","reasoning":"one concise sentence"}`;
}

export async function judgeResult(
  result: ExploitResult,
  vector: AttackVector,
  script: ExploitScript
): Promise<JudgeVerdict> {
  const client = new Anthropic({ maxRetries: 5 });

  const response = await client.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 256,
    messages: [{ role: "user", content: buildPrompt(result, vector, script) }],
  });

  const text = response.content[0].type === "text" ? response.content[0].text.trim() : "";

  // Strip fences if the model ignores the instruction
  const json = text.replace(/```(?:json)?\s*([\s\S]*?)```/, "$1").trim();

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return { verdict: "inconclusive", reasoning: "Judge returned unparseable response" };
  }

  const checked = JudgeResponse.safeParse(parsed);
  if (!checked.success) {
    return { verdict: "inconclusive", reasoning: "Judge response did not match expected schema" };
  }

  return checked.data;
}
