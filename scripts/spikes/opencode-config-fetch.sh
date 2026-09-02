#!/usr/bin/env bash
# Prove that a config hook owns the SDK fetch after OpenCode's provider loaders run.
#
# The fixture is deliberately disposable: no vendor endpoint, credential, or user
# XDG directory is touched. The mutation arm proves the assertion can observe the
# missing wrapper rather than passing because the stub answered successfully.
set -euo pipefail

umask 077
mkdir -p /tmp/opencode
ROOT="$(mktemp -d /tmp/opencode/oc-spike.XXXXXX)"
export XDG_CONFIG_HOME="$ROOT/config"
export XDG_DATA_HOME="$ROOT/data"
export XDG_CACHE_HOME="$ROOT/cache"
export XDG_STATE_HOME="$ROOT/state"

rm -rf "$ROOT"
mkdir -p "$XDG_CONFIG_HOME/opencode" "$XDG_DATA_HOME/opencode" "$XDG_CACHE_HOME" "$XDG_STATE_HOME"

STUB_PID=""
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$STUB_PID" ]]; then
    kill "$STUB_PID" >/dev/null 2>&1 || true
    wait "$STUB_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$ROOT"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

version="$(opencode --version)"
if [[ "$version" != "1.18.25" ]]; then
  printf 'SPIKE FAIL stock_version=%s expected=1.18.25\n' "$version" >&2
  exit 1
fi

cat > "$ROOT/stub.ts" <<'EOF'
const root = Bun.argv[2]
if (!root) throw new Error("stub root is required")

const portFile = `${root}/port`
const requestLog = `${root}/stub-requests.log`
const headerLog = `${root}/stub-headers.log`
let requests: string[] = []
let headers: string[] = []

async function append(path: string, line: string, current: string[]) {
  current.push(line)
  await Bun.write(path, current.join("\n") + "\n")
}

function json(value: unknown) {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
  })
}

function openaiStream() {
  const body = [
    `data: ${JSON.stringify({ id: "spike-chat", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`,
    `data: ${JSON.stringify({ id: "spike-chat", object: "chat.completion.chunk", choices: [{ index: 0, delta: { content: "SPIKE_OK" }, finish_reason: null }] })}\n\n`,
    `data: ${JSON.stringify({ id: "spike-chat", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`,
    "data: [DONE]\n\n",
  ].join("")
  return new Response(body, { headers: { "content-type": "text/event-stream" } })
}

function responsesStream() {
  const item = { id: "spike-item", type: "message", status: "completed", role: "assistant", content: [{ type: "output_text", text: "SPIKE_OK", annotations: [] }] }
  const pendingItem = { ...item, status: "in_progress", content: [] }
  const part = { type: "output_text", text: "SPIKE_OK", annotations: [] }
  const body = [
    `event: response.created\ndata: ${JSON.stringify({ type: "response.created", response: { id: "spike-response", object: "response", status: "in_progress", output: [] } })}\n\n`,
    `event: response.output_item.added\ndata: ${JSON.stringify({ type: "response.output_item.added", item: pendingItem, output_index: 0 })}\n\n`,
    `event: response.content_part.added\ndata: ${JSON.stringify({ type: "response.content_part.added", item_id: item.id, output_index: 0, content_index: 0, part: { type: "output_text", text: "", annotations: [] } })}\n\n`,
    `event: response.output_text.delta\ndata: ${JSON.stringify({ type: "response.output_text.delta", item_id: item.id, output_index: 0, content_index: 0, delta: "SPIKE_OK" })}\n\n`,
    `event: response.output_text.done\ndata: ${JSON.stringify({ type: "response.output_text.done", item_id: item.id, output_index: 0, content_index: 0, text: "SPIKE_OK" })}\n\n`,
    `event: response.content_part.done\ndata: ${JSON.stringify({ type: "response.content_part.done", item_id: item.id, output_index: 0, content_index: 0, part })}\n\n`,
    `event: response.output_item.done\ndata: ${JSON.stringify({ type: "response.output_item.done", item, output_index: 0 })}\n\n`,
    `event: response.completed\ndata: ${JSON.stringify({ type: "response.completed", response: { id: "spike-response", object: "response", status: "completed", output: [item] } })}\n\n`,
    "data: [DONE]\n\n",
  ].join("")
  return new Response(body, { headers: { "content-type": "text/event-stream" } })
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(request) {
    const url = new URL(request.url)
    const body = await request.text()
    const record = JSON.stringify({ method: request.method, path: url.pathname, headers: Object.fromEntries(request.headers), body })
    await append(headerLog, record, headers)

    if (url.pathname.endsWith("/models")) return json({ object: "list", data: [] })
    if (url.pathname.endsWith("/chat/completions")) {
      await append(requestLog, url.pathname, requests)
      return openaiStream()
    }
    if (url.pathname.endsWith("/responses")) {
      await append(requestLog, url.pathname, requests)
      return responsesStream()
    }
    return new Response("not found", { status: 404 })
  },
})

await Bun.write(portFile, String(server.port))
EOF

cat > "$ROOT/plugin.ts" <<'EOF'
const root = process.env.XDG_STATE_HOME?.replace(/\/state$/, "") ?? "/tmp/opencode/oc-spike"
const providers = ["deepseek", "xai"]

function authorization(input: any, init: any) {
  const source = init?.headers ?? (input instanceof Request ? input.headers : undefined)
  return new Headers(source).get("authorization") ?? ""
}

async function log(path: string, line: string) {
  const prior = await Bun.file(path).text().catch(() => "")
  await Bun.write(path, prior + line + "\n")
}

export const SpikePlugin = async (input: any) => ({
  config: async (cfg: any) => {
    for (const provider of providers) {
      const configured = cfg.provider?.[provider]
      if (!configured) continue
      configured.options = { ...(configured.options ?? {}) }
      configured.options.apiKey = `claustrum-tombstone:v1:${provider}`
      if (process.env.SPIKE_DISABLE_CUSTOM_FETCH === "1") continue
      const upstream = globalThis.fetch
      configured.options.fetch = async (request: any, init?: any) => {
        await log(`${root}/fetch.log`, `SPIKE_FETCH provider=${provider} auth=${authorization(request, init)}`)
        return upstream(request, init)
      }
    }
  },
})
EOF

bun "$ROOT/stub.ts" "$ROOT" &
STUB_PID=$!
for _ in {1..100}; do
  [[ -s "$ROOT/port" ]] && break
  sleep 0.01
done
if [[ ! -s "$ROOT/port" ]]; then
  printf 'SPIKE FAIL stub_not_ready\n' >&2
  exit 1
fi
PORT="$(< "$ROOT/port")"
BASE_URL="http://127.0.0.1:${PORT}/v1"

cat > "$XDG_CONFIG_HOME/opencode/opencode.json" <<EOF
{
  "plugin": ["file://${ROOT}/plugin.ts"],
  "provider": {
    "deepseek": {
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "${BASE_URL}" },
      "models": {
        "spike": {
          "name": "Spike",
          "id": "spike",
          "limit": { "context": 4096, "output": 256 },
          "modalities": { "input": ["text"], "output": ["text"] }
        }
      }
    },
    "xai": {
      "npm": "@ai-sdk/xai",
      "options": { "baseURL": "${BASE_URL}" },
      "models": {
        "spike": {
          "name": "Spike",
          "id": "spike",
          "limit": { "context": 4096, "output": 256 },
          "modalities": { "input": ["text"], "output": ["text"] }
        }
      }
    }
  }
}
EOF

cat > "$XDG_DATA_HOME/opencode/auth.json" <<'EOF'
{
  "deepseek": { "type": "api", "key": "claustrum-tombstone:v1:deepseek" },
  "xai": { "type": "oauth", "refresh": "claustrum-tombstone:v1:xai", "access": "claustrum-tombstone:v1:xai", "expires": 0 }
}
EOF
chmod 600 "$XDG_DATA_HOME/opencode/auth.json"

run_provider() {
  local provider="$1"
  local output
  if ! output="$(opencode run -m "${provider}/spike" 'Return the stub response.' 2>&1)"; then
    printf '%s\n' "$output" > "$ROOT/run-${provider}.log"
    printf 'SPIKE FAIL %s run_failed\n' "$provider" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  printf '%s\n' "$output" > "$ROOT/run-${provider}.log"
  if ! grep -q 'SPIKE_OK' "$ROOT/run-${provider}.log"; then
    printf 'SPIKE FAIL %s missing_stub_response\n' "$provider" >&2
    exit 1
  fi
}

run_provider deepseek

if [[ "${SPIKE_DISABLE_CUSTOM_FETCH:-0}" == "1" ]]; then
  fetch_log="$(cat "$ROOT/fetch.log" 2>/dev/null || true)"
  if grep -q 'SPIKE_FETCH provider=deepseek ' <<<"$fetch_log"; then
    printf 'SPIKE FAIL deepseek custom_fetch=1\n' >&2
    exit 1
  fi
  printf 'SPIKE FAIL deepseek custom_fetch=0\n'
  exit 1
fi

run_provider xai

fetch_log="$(cat "$ROOT/fetch.log" 2>/dev/null || true)"
stub_summary="$(python3 - "$ROOT/stub-requests.log" "$ROOT/stub-headers.log" <<'PY'
import json
import pathlib
import sys

header_lines = pathlib.Path(sys.argv[2]).read_text().splitlines() if pathlib.Path(sys.argv[2]).exists() else []
request_lines = [line for line in header_lines if json.loads(line).get("path") in ("/v1/chat/completions", "/v1/responses")]
for provider, sentinel in (("deepseek", "claustrum-tombstone:v1:deepseek"), ("xai", "claustrum-tombstone:v1:xai")):
    matches = [line for line in request_lines if sentinel in json.loads(line).get("headers", {}).get("authorization", "")]
    auth = ""
    for line in matches:
        headers = json.loads(line)["headers"]
        auth = headers.get("authorization", auth)
    print(f"{provider}\t{len(matches)}\t{auth}")
print(f"requests\t{len(request_lines)}")
PY
)"

deepseek_fetch=0
xai_fetch=0
grep -q '^SPIKE_FETCH provider=deepseek ' <<<"$fetch_log" && deepseek_fetch=1
grep -q '^SPIKE_FETCH provider=xai ' <<<"$fetch_log" && xai_fetch=1
deepseek_auth="$(grep '^SPIKE_FETCH provider=deepseek ' <<<"$fetch_log" | head -1 | sed 's/.* auth=//')"
xai_auth="$(grep '^SPIKE_FETCH provider=xai ' <<<"$fetch_log" | head -1 | sed 's/.* auth=//')"
deepseek_wire="$(awk -F '\t' '$1 == "deepseek" { print $2 }' <<<"$stub_summary")"
xai_wire="$(awk -F '\t' '$1 == "xai" { print $2 }' <<<"$stub_summary")"
stub_requests="$(awk -F '\t' '$1 == "requests" { print $2 }' <<<"$stub_summary")"

if [[ "$deepseek_fetch" != 1 || "$deepseek_auth" != 'Bearer claustrum-tombstone:v1:deepseek' || "$deepseek_wire" != 1 ]]; then
  printf 'SPIKE FAIL deepseek custom_fetch=%s auth=%s stub_requests=%s\n' "$deepseek_fetch" "$deepseek_auth" "$deepseek_wire" >&2
  exit 1
fi
if [[ "$xai_fetch" != 1 || "$xai_auth" != 'Bearer claustrum-tombstone:v1:xai' || "$xai_wire" != 1 ]]; then
  printf 'SPIKE FAIL xai custom_fetch=%s auth=%s stub_requests=%s\n' "$xai_fetch" "$xai_auth" "$xai_wire" >&2
  exit 1
fi
if [[ "$stub_requests" != 2 ]]; then
  printf 'SPIKE FAIL total_stub_requests=%s\n' "$stub_requests" >&2
  exit 1
fi

printf 'SPIKE deepseek stub_saw_sentinel=1\n'
printf 'SPIKE xai stub_saw_sentinel=1\n'
printf 'SPIKE deepseek custom_fetch=1 auth=%s stub_requests=1\n' "$deepseek_auth"
printf 'SPIKE xai custom_fetch=1 auth=%s stub_requests=1\n' "$xai_auth"
printf 'SPIKE xai shipped_refresh=0 proof=expired-oauth-succeeded-offline\n'
printf 'SPIKE PASS 2/2 stock=%s\n' "$version"
