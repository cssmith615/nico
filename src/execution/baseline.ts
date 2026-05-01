import type { AttackVector } from "../types/index.js";

const SAFE_VALUE = "nico_baseline_safe_abc123";

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function joinTargetRoute(targetUrl: string, route: string): string {
  const base = targetUrl.replace(/\/+$/, "");
  const path = route.startsWith("/") ? route : `/${route}`;
  return `${base}${path}`;
}

export function generateBaselineScript(
  vector: AttackVector,
  targetUrl: string
): string {
  const { route, method, inputName, inputType } = vector;
  const url = joinTargetRoute(targetUrl, route);

  const curlArgs = buildCurlArgs(url, method, inputName, inputType);

  return `#!/bin/bash
START=$(date +%s%N 2>/dev/null || date +%s)
STATUS=$(curl -s -o /tmp/nico_baseline_body.txt -w "%{http_code}" \\
  --max-time 10 \\
  ${curlArgs})
END=$(date +%s%N 2>/dev/null || date +%s)

if [[ "$START" =~ ^[0-9]{19}$ ]]; then
  ELAPSED=$(( (END - START) / 1000000 ))
else
  ELAPSED=$(( (END - START) * 1000 ))
fi

NICO_BASELINE_STATUS="$STATUS" NICO_BASELINE_ELAPSED="$ELAPSED" python3 - <<'PYEOF'
import json, os

status_raw = os.environ.get('NICO_BASELINE_STATUS', '')
elapsed_raw = os.environ.get('NICO_BASELINE_ELAPSED', '')

try:
    body = open('/tmp/nico_baseline_body.txt').read()[:500]
except Exception:
    body = ''

evidence = {
    'statusCode': int(status_raw) if status_raw.isdigit() else 0,
    'responseBody': body,
    'responseTimeMs': int(elapsed_raw) if elapsed_raw.lstrip('-').isdigit() else 0,
}

os.makedirs('/workspace', exist_ok=True)
with open('/workspace/baseline.json', 'w') as f:
    json.dump(evidence, f)
PYEOF
`;
}

function buildCurlArgs(
  url: string,
  method: string,
  inputName: string,
  inputType: "query" | "body" | "header" | "cookie" | "path"
): string {
  switch (inputType) {
    case "query": {
      const sep = url.includes("?") ? "&" : "?";
      const queryUrl = `${url}${sep}${encodeURIComponent(inputName)}=${encodeURIComponent(SAFE_VALUE)}`;
      return `-X ${method} ${shellQuote(queryUrl)}`;
    }
    case "path": {
      const placeholder = `{${inputName}}`;
      const safeUrl = url.includes(placeholder)
        ? url.split(placeholder).join(encodeURIComponent(SAFE_VALUE))
        : url;
      return `-X ${method} ${shellQuote(safeUrl)}`;
    }
    case "body": {
      const body = JSON.stringify({ [inputName]: SAFE_VALUE });
      return `-X ${method} \\
  -H "Content-Type: application/json" \\
  -d ${shellQuote(body)} \\
  ${shellQuote(url)}`;
    }
    case "header":
      return `-X ${method} \\
  -H ${shellQuote(`${inputName}: ${SAFE_VALUE}`)} \\
  ${shellQuote(url)}`;
    case "cookie":
      return `-X ${method} \\
  -H ${shellQuote(`Cookie: ${inputName}=${SAFE_VALUE}`)} \\
  ${shellQuote(url)}`;
  }
}
