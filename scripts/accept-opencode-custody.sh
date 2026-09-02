#!/usr/bin/env bash
set -euo pipefail

WT="${WT:-$(cd "$(dirname "$0")/.." && pwd -P)}"
CK_AUTH="$WT/target/release/ck-auth"
umask 077
ROOT="$(mktemp -d)"
PROVIDER=synthetic
# Derive the subc connection path the way `ck` itself does, so the acceptance rig
# works on hosts whose runtime dir is not `/run/user/1000`. Order matches
# crates/credentials-module/src/bin/credentials_cli.rs `discover_subc_connection_file`:
#   1. explicit `CLAUSTRUM_SUBC_CONNECTION` / `SUBC` overrides (operator pin),
#   2. `$XDG_RUNTIME_DIR/subc-connection.json` (the standard location),
#   3. `$HOME/.local/share/cortexkit/run/subc-connection.json` (production fallback),
#   4. `<tempdir>/subc-*.connection.json` (last-resort, globbed for the daemon token).
if [[ -n "${CLAUSTRUM_SUBC_CONNECTION:-}" ]]; then
  SUBC="$CLAUSTRUM_SUBC_CONNECTION"
elif [[ -n "${SUBC:-}" ]]; then
  SUBC="$SUBC"
elif [[ -s "${XDG_RUNTIME_DIR:-}/subc-connection.json" ]]; then
  SUBC="$XDG_RUNTIME_DIR/subc-connection.json"
elif [[ -s "${HOME}/.local/share/cortexkit/run/subc-connection.json" ]]; then
  SUBC="$HOME/.local/share/cortexkit/run/subc-connection.json"
else
  # The daemon's last-resort location is `<tempdir>/subc-<token>.connection.json` where
  # the token comes from a UID probe (or a sanitized USER/USERNAME, on macOS the default).
  # A literal `ls | head -n 1` would silently pick one of N candidates and route admin
  # operations at whichever user's daemon the shell saw first; that file is then bound
  # to the acceptance rig's CLAUSTRUM_SUBC_CONNECTION export through the same root.
  # REFUSE the ambiguous case so the acceptance run cannot cross users.
  TEMP_BASE="${TMPDIR:-/tmp}"
  matches="$(ls -1 "$TEMP_BASE"/subc-*.connection.json 2>/dev/null || true)"
  count="$(printf '%s\n' "$matches" | grep -c . || true)"
  case "$count" in
    0) SUBC="" ;;
    1) SUBC="$matches" ;;
    *) printf 'ACCEPT FAIL ambiguous subc connection files in %s (%d candidates); set CLAUSTRUM_SUBC_CONNECTION or SUBC to choose:\n' "$TEMP_BASE" "$count" >&2
       printf '%s\n' "$matches" >&2
       exit 1
       ;;
  esac
fi
# Last-resort absent marker; matches the highest-priority production slot so the rig's
# refusal/retry paths run against the same path `ck` would resolve.
SUBC="${SUBC:-${XDG_RUNTIME_DIR:-}/subc-connection.json}"
KEY_PATH=/etc/cortexkit/master.key

if [[ "$(pwd -P)" != "$WT" ]]; then
  printf 'ACCEPT FAIL worktree=%s expected=%s\n' "$(pwd -P)" "$WT" >&2
  exit 1
fi
if [[ "$(opencode --version)" != "1.18.25" ]]; then
  printf 'ACCEPT FAIL opencode_version=%s expected=1.18.25\n' "$(opencode --version)" >&2
  exit 1
fi

cargo build --release --locked --offline -p credentials-module --bin ck-auth
bun run build

REAL_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
REAL_AUTH="$REAL_DATA_HOME/opencode/auth.json"
mkdir -p "$ROOT/config/opencode" "$ROOT/data/opencode" "$ROOT/cache" "$ROOT/state"
export XDG_CONFIG_HOME="$ROOT/config"
export XDG_DATA_HOME="$ROOT/data"
export XDG_CACHE_HOME="$ROOT/cache"
export XDG_STATE_HOME="$ROOT/state"

AUTH_FILE="$XDG_DATA_HOME/opencode/auth.json"
HANDLE_FILE="$XDG_CONFIG_HOME/cortexkit/opencode-handles.json"
PRIVATE_ENTRY="$ROOT/synthetic-entry.json"
EXPECTED_TOMBSTONE="$ROOT/expected-tombstone.json"
MINTED=0
RESTORED=0

ck_auth() {
  XDG_DATA_HOME="$REAL_DATA_HOME" "$CK_AUTH" "$@" --subc "$SUBC" --key-path "$KEY_PATH"
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 && "$MINTED" -eq 1 && "$RESTORED" -eq 0 ]]; then
    if ! ck_auth migrate-opencode --restore "$PROVIDER" \
      --auth-file "$AUTH_FILE" --handle-file "$HANDLE_FILE" > "$ROOT/restore-on-failure.log" 2>&1; then
      printf 'ACCEPT FAIL rollback_restore_failed root=%s\n' "$ROOT" >&2
      exit 1
    fi
  fi
  [[ "$status" -eq 0 ]] && rm -rf "$ROOT"
  exit "$status"
}
trap cleanup EXIT INT TERM
trap 'printf "ACCEPT FAIL command=%s\n" "$BASH_COMMAND" >&2' ERR

status_line() {
  ck_auth status | awk -v credential_id="$1" '$NF == credential_id { print }'
}

require_status_line() {
  local line
  line="$(status_line "$1")"
  if [[ -z "$line" ]]; then
    printf 'ACCEPT FAIL missing_status=%s\n' "$1" >&2
    exit 1
  fi
  printf '%s' "$line"
}

LEGACY_SYNTHETIC_BEFORE="$(require_status_line 'apikey:synthetic')"
ANTHROPIC_BEFORE="$(require_status_line 'oauth:anthropic')"
ANTHROPIC_WORK_ALT_BEFORE="$(require_status_line 'oauth:anthropic:work-alt')"

jq '{synthetic: .synthetic}' "$REAL_AUTH" > "$AUTH_FILE"
chmod 600 "$AUTH_FILE"
jq -e '.synthetic.type == "api"' "$AUTH_FILE" >/dev/null
jq -cS '.synthetic' "$AUTH_FILE" > "$PRIVATE_ENTRY"
chmod 600 "$PRIVATE_ENTRY"
jq --arg provider "$PROVIDER" \
  '.fixtures.api.entry | .key = ("claustrum-tombstone:v1:" + $provider)' \
  "$WT/packages/opencode/golden/tombstone.json" > "$EXPECTED_TOMBSTONE"
chmod 600 "$EXPECTED_TOMBSTONE"

MINTED=1
ck_auth migrate-opencode --auth-file "$AUTH_FILE" --handle-file "$HANDLE_FILE" \
  --provider "$PROVIDER" > "$ROOT/migrate.log" 2>&1

jq -e --slurp '.[0].synthetic == .[1]' "$AUTH_FILE" "$EXPECTED_TOMBSTONE" >/dev/null
[[ "$(stat -c '%a' "$HANDLE_FILE")" == "600" ]]
jq -e --arg provider "$PROVIDER" \
  '.version == 1 and ([.providers[] | select(.provider == $provider and .serve == "opencode-claustrum")] | length == 1)' \
  "$HANDLE_FILE" >/dev/null

cat > "$XDG_CONFIG_HOME/opencode/opencode.json" <<EOF
{
  "plugin": ["file://$WT/packages/opencode/dist/opencode-plugin.js"]
}
EOF
chmod 600 "$XDG_CONFIG_HOME/opencode/opencode.json"

MODEL_ID="$(opencode models | awk '$1 == "synthetic/hf:moonshotai/Kimi-K3" { print; exit }')"
if [[ -z "$MODEL_ID" ]]; then
  printf 'ACCEPT FAIL synthetic_model=missing\n' >&2
  exit 1
fi

if ! timeout 180 opencode run -m "$MODEL_ID" 'Reply exactly CUSTODY_ACCEPTED.' > "$ROOT/arm1.log" 2>&1; then
  printf 'ACCEPT FAIL arm1_model_call\n' >&2
  cat "$ROOT/arm1.log" >&2
  if [[ -d "$XDG_DATA_HOME/opencode/log" ]]; then
    grep -R -Ei 'plugin|import|resolve|opencode-claustrum' "$XDG_DATA_HOME/opencode/log" >&2 || true
  fi
  exit 1
fi
if ! grep -q 'CUSTODY_ACCEPTED' "$ROOT/arm1.log"; then
  printf 'ACCEPT FAIL arm1_sentinel_missing\n' >&2
  exit 1
fi

SYNTHETIC_MAIN_AFTER="$(require_status_line 'apikey:synthetic:main')"
if [[ "$SYNTHETIC_MAIN_AFTER" != active* ]]; then
  printf 'ACCEPT FAIL synthetic_main_not_active\n' >&2
  exit 1
fi
[[ "$(require_status_line 'apikey:synthetic')" == "$LEGACY_SYNTHETIC_BEFORE" ]]
[[ "$(require_status_line 'oauth:anthropic')" == "$ANTHROPIC_BEFORE" ]]
[[ "$(require_status_line 'oauth:anthropic:work-alt')" == "$ANTHROPIC_WORK_ALT_BEFORE" ]]

jq -n --slurpfile entry "$PRIVATE_ENTRY" '{synthetic: $entry[0]}' > "$AUTH_FILE"
chmod 600 "$AUTH_FILE"
if timeout 180 opencode run -m "$MODEL_ID" 'Reply exactly CUSTODY_ACCEPTED.' > "$ROOT/arm2.log" 2>&1; then
  printf 'ACCEPT FAIL split_custody_allowed\n' >&2
  exit 1
fi
if ! grep -Eqi 'CustodySplitError|split custody|local credential is real while custody handles remain' "$ROOT/arm2.log"; then
  printf 'ACCEPT FAIL split_custody_unnamed\n' >&2
  exit 1
fi
if grep -q 'CUSTODY_ACCEPTED' "$ROOT/arm2.log"; then
  printf 'ACCEPT FAIL split_custody_sent_sentinel\n' >&2
  exit 1
fi
ck_auth migrate-opencode --auth-file "$AUTH_FILE" --handle-file "$HANDLE_FILE" \
  --provider "$PROVIDER" > "$ROOT/reconverge.log" 2>&1
if ! grep -q 'identical' "$ROOT/reconverge.log"; then
  printf 'ACCEPT FAIL reconverge_not_identical\n' >&2
  exit 1
fi
jq -e --slurp '.[0].synthetic == .[1]' "$AUTH_FILE" "$EXPECTED_TOMBSTONE" >/dev/null

ck_auth migrate-opencode --restore "$PROVIDER" --auth-file "$AUTH_FILE" \
  --handle-file "$HANDLE_FILE" > "$ROOT/restore.log" 2>&1
RESTORED=1
jq -cS '.synthetic' "$AUTH_FILE" > "$ROOT/restored-entry.json"
cmp -s "$ROOT/restored-entry.json" "$PRIVATE_ENTRY"
jq -e --arg provider "$PROVIDER" \
  '[.providers[] | select(.provider == $provider)] | length == 0' "$HANDLE_FILE" >/dev/null
SYNTHETIC_MAIN_FINAL="$(require_status_line 'apikey:synthetic:main')"
if [[ "$SYNTHETIC_MAIN_FINAL" != active* ]]; then
  printf 'ACCEPT FAIL synthetic_main_missing_after_restore\n' >&2
  exit 1
fi
[[ "$(require_status_line 'apikey:synthetic')" == "$LEGACY_SYNTHETIC_BEFORE" ]]
[[ "$(require_status_line 'oauth:anthropic')" == "$ANTHROPIC_BEFORE" ]]
[[ "$(require_status_line 'oauth:anthropic:work-alt')" == "$ANTHROPIC_WORK_ALT_BEFORE" ]]
ck_auth verify-audit > "$ROOT/audit.log" 2>&1

printf 'ACCEPT scratch_auth=tombstone provider=synthetic\n'
printf 'ACCEPT vault=apikey:synthetic:main state=active\n'
printf 'CUSTODY_ACCEPTED\n'
printf 'ACCEPT split_custody=refused sentinel_not_sent=1 reconverged=1\n'
printf 'ACCEPT restore=ok handle_revoked=1 record_kept=1 legacy_synthetic_untouched=1 oauth_untouched=2 audit=valid\n'
printf 'ACCEPT PASS\n'
