import type { AttackVector } from "../types/index.js";

const SAFE_VALUE = "nico_baseline_safe_abc123";

export function generateBaselineScript(
  vector: AttackVector,
  targetUrl: string
): string {
  const { route, method, inputName, inputType } = vector;
  const url = `${targetUrl}${route}`;

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

python3 - <<'PYEOF'
import json, os

status_raw = "$STATUS"
elapsed_raw = "$ELAPSED"

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
  inputType: "query" | "body" | "header" | "cookie"
): string {
  switch (inputType) {
    case "query":
      return `-X ${method} "${url}?${inputName}=${SAFE_VALUE}"`;
    case "body":
      return `-X ${method} \\
  -H "Content-Type: application/json" \\
  -d '{"${inputName}": "${SAFE_VALUE}"}' \\
  "${url}"`;
    case "header":
      return `-X ${method} \\
  -H "${inputName}: ${SAFE_VALUE}" \\
  "${url}"`;
    case "cookie":
      return `-X ${method} \\
  -H "Cookie: ${inputName}=${SAFE_VALUE}" \\
  "${url}"`;
  }
}
