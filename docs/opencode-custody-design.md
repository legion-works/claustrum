# OpenCode vault-custody plugin — design (shape-driven, provider-agnostic)

Status: DESIGN v2 · approved in dialogue 2026-09-01 (v1 + Anthropic Legion review + operator
direction "shape, not provider") · implements slice 2 of claustrum#17
First delivery: `type=api` entries. `type=oauth` is designed here and lands when a
dedicated-plugin owner (anthropic-auth) lifts its freeze; Claude Code / Codex are §9.

## 1. Goal

**Architecture in one line: an in-process auth proxy on OpenCode's `fetch` seam.** OpenCode's
SDK builds every request believing the credential is the sentinel; the plugin intercepts
each outbound request for a slot it owns, exchanges the sentinel for live material from the
vault at that moment, forwards, and observes the response. Which material, from which
account, refreshed when — all decided at request time, never at load. The vault performs
every upstream exchange (refresh, latch); the proxy only asks for the current material and
reports what it saw. Nothing about a provider is known to the proxy.

Serve OpenCode MAIN slots from the Claustrum vault instead of `~/.local/share/opencode/auth.json`
on a **stock** OpenCode build via the documented plugin API only — no core change, no fork, no
upstream dependency. The plugin knows nothing about providers: it acts on the SHAPE of an
`auth.json` entry (`api` | `oauth` | future shapes) and on a handle file the CLI writes. The
vault owns every provider specific (adapters, refresh, latching). Multiple keys/accounts per
provider with in-request failover for providers the generic plugin serves.

## 2. Decisions taken (settled)

| Fork | Decision |
|---|---|
| Scope of first delivery | `type=api` entries (no token family, no treadmill) |
| Provider knowledge | NONE in the plugin. Shape-driven. Ownership per provider lives in the handle file |
| Registration mechanism | `config` hook injecting provider options (§3, spike-gated); NOT `auth.loader` |
| Migration ownership | CLI-owned under the admin gate; plugin is read-only |
| Code home | `claustrum` repo: `packages/client` + `packages/opencode` + CLI verbs |
| Multi-account | One vault record per key/account; ordered priority list per provider |
| Dedicated-plugin providers | Served by THEIR plugin consuming this client + handle file + tombstone convention; never by the generic closure |

### Seam boundary

This is a config-hook/fetch-seam integration, **not provider-universal custody**. The generic
plugin does not know provider names and never consults the provider-shape table. The CLI that
creates tombstones owns that provider knowledge as data in
`crates/credentials-module/src/bin/cli_support/opencode-provider-shapes.json`, maintained from
OpenCode source on every base update. It records source sites, the deliberately servable negative
determinations, and the availability-only consequence of `--force-shape`.

| shape | why |
| --- | --- |
| `api-env` | OpenCode copies the key into `process.env` at provider load, so custody material would enter the environment. |
| `api-discovery` | Model discovery or a loader closure consumes the key outside `options.fetch`; provider options can then be serialized. |
| `api-metadata` | The provider reads API auth metadata that a metadata-less tombstone does not carry. |

An unlisted provider defaults to the `api` fetch seam. A listed provider is servable only when its
shape list is exactly `[api]`; multiple listed shapes are orthogonal and refuse together. The
table's method has a stated edge: it covers consumers found in upstream `provider/provider.ts` and
`plugin/` at its pinned commit, not every possible consumer elsewhere in the tree.

## 3. Verified mechanism (OpenCode `a184b7a718`, installed 1.18.25)

- `plugin/index.ts:247` — every plugin's `config(cfg)` hook receives the live config object.
- `provider.ts:1439` — provider list is built from `cfg.provider` AFTER the hooks, comment:
  "includes any modifications from plugin config() hook". `1485` and `1646` merge
  `provider.options` into the SDK options bag with no re-validation in between.
- `provider.ts:1794-1800` — `getSDK` lifts `options.fetch` into `customFetch` for providers
  whose live credential path remains the generic AI SDK seam. This is not a provider-wide
  guarantee: provider-specific loaders, model discovery, environment credentials, transforms,
  and native runtime paths can bypass or alter it. The generic provider allowlist is open.
- `provider.ts:1777` — `options.apiKey` defaults to `provider.key`; a config-supplied
  `options.apiKey` wins. The SDK places that value wherever the provider expects a key.
- `provider.ts:1643-1650` — config provider options are RE-APPLIED after every `auth.loader`
  has run, via remeda `mergeDeep` where a non-object value on the right wins (verified:
  `mergeDeep({options:{fetch:loader}}, {options:{fetch:config}}).options.fetch` → config).
  A config-hook-injected `fetch` therefore REPLACES a shipped plugin's loader-set `fetch`.
  This only makes a provider reachable when its live credential path is the generic fetch
  seam. Do not infer reachability for xai, codex, copilot, snowflake, or any other provider
  from config re-apply precedence alone.
- `provider.ts:1611` `if (!stored) continue` — an `auth.json` entry is required for any
  `auth.loader` to run; dedicated plugins keep needing the tombstone for that reason.
- `plugin/index.ts:103` — plugin exports are static; N runtime-discovered providers cannot
  be N `auth.loader`s. Hence the config hook.
- OpenCode reads `OPENCODE_AUTH_CONTENT` before disk auth, and workspace children inherit it;
  custody mirrors that source order. Stock 1.18.25's `Auth.set` is a whole-file RMW. Newer
  upstream #46131 adds flock plus atomic writes, which narrows torn writes but does not solve
  environment snapshots or ownership disagreement; `auth.json` remains shared state.
- Vault: `apikey:<provider>:<account>` / `oauth:<provider>:<account>` parse today; a
  non-refresh `credential.get` writes no chain row; limiter 64/60s per connection shared by
  `get`/`status`/`report_auth_failure`/`sign`/`public_key`, and a timed-out get still
  counts; static-key `report_auth_failure` latches immediately
  (`stale_nonrefreshable_latch`); `report_auth_failure` takes `reporter_source`.
- Anthropic-auth production facts carried in: tool-spawned shells inherit
  `SUBC_MODULE_ID`/`SUBC_LAUNCH_NONCE` and authenticate as the wrong module unless scrubbed;
  the daemon rejects `route.open` without `BindIdentity{project_root, session}`; a resident
  client can wedge with no daemon-visible disconnect; `credential.get` is bimodal
  (0.035 ms resident vs seconds when it lands in expiry skew).

**SPIKE (plan task 0, gates everything):** on stock 1.18.25, two arms. (1) A `config` hook
that sets `cfg.provider["deepseek"].options = { apiKey: SENTINEL, fetch }` must result in
`fetch` being invoked for a real request with `SENTINEL` present in the outgoing headers.
(2) The same injection for `xai` (a provider whose SHIPPED plugin sets its own `fetch` in
`auth.loader`) must result in OUR `fetch` being the one invoked and the shipped plugin's
refresh never firing. Pass both → proceed. Fail → stop and redesign registration; nothing
below is built on an unproven seam.

## 4. Components

```
claustrum/
  packages/client/                 @cortexkit/claustrum-client   TS, node built-ins only
    src/detect.ts                  $CLAUSTRUM_SUBC_CONNECTION, else the subc default path
    src/identity.ts                consumerIdentity scrub (SUBC_MODULE_ID / SUBC_LAUNCH_NONCE)
                                   + BindIdentity { project_root, session: "store-<sha256(path)>" }
    src/wire.ts                    handshake, route.open, credential.get / status /
                                   report_auth_failure; reconnect-with-backoff (60 s) on
                                   terminal SubcCallError; payload = JSON byte array;
                                   errors nest at result.error
    src/errors.ts                  ERROR_CLASS_WIRE_SET; ClaustrumCredentialError
                                   { code, class, action }; UNKNOWN CLASS → transient
    README.md                      contract facts (§3 limiter/bimodal/timeout) — every
                                   caller's retry policy is shaped by them
  packages/opencode/               @cortexkit/opencode-claustrum  the generic plugin
    src/index.ts                   one plugin; config hook; owns providers per handle file
    src/handles.ts                 handle-file reader: mode 600, ownership, priority order
    src/tombstone.ts               isTombstone(entry, provider) for every shape; SENTINEL(p)
    src/serve.ts                   sentinel-substituting fetch closure + per-account state
    src/freshness.ts               shape → policy (api: observe; oauth: tick + min_ttl)
    golden/tombstone.json          shared golden, all shapes (§6)
  crates/credentials-module/src/bin/credentials_cli.rs
    migrate-opencode, opencode-account {add,remove,list}      (§5)
```

The client is EXTRACTED from anthropic-auth `packages/core/src/claustrum.ts`: detect, wire,
identity, reconnect, error set. NOT extracted (policy, stays in anthropic-auth):
single-flight dedup, expiry-bounded cache, min-TTL scheduling, reauth-warm backoff.
Dependency direction: anthropic-auth will depend on this client; never the reverse.

## 5. CLI verbs (Rust, admin-gated, online or offline like every other verb)

```
ck auth migrate-opencode [--auth-file <p>] [--handle-file <p>] [--provider <id>]...
                         [--serve-by <plugin-id>] [--replace] [--dry-run]
                         [--force-shape]
ck auth migrate-opencode --restore <provider>
ck auth opencode-account add    <provider> --account <label> --key-file <path|-> [--before <label>]
ck auth opencode-account remove <provider> --account <label>
ck auth opencode-account list   <provider>
ck auth migrate-plugin --serve <tenant> --provider <p> --from <export.json>
                       [--replace | --skip-existing] [--dry-run] [--allow-expired]
```

Defaults: `--auth-file` = OpenCode's own resolution of `auth.json`; `--handle-file
$XDG_CONFIG_HOME/cortexkit/opencode-handles.json`; `--serve-by opencode-claustrum`. A key is
NEVER accepted on argv.

Eligibility is by SHAPE: any entry whose `type` the verb has a mapping for (`api` now;
`oauth` when §9's owner is ready) and that is not already a tombstone. `--provider`
restricts; there is no allow-list of provider names.

Before that generic eligibility check, `migrate-opencode` reads the provider-shape table. Known
API entries that leave `options.fetch` are refused per provider with the shape, why, source site,
and `--force-shape` remedy; other providers in the same invocation still migrate. Forcing remains
availability-only because the sentinel is non-secret, but it can put that sentinel in an
environment, discovery request, or metadata-dependent loader. `opencode-account add` refuses the
same providers rather than treating account failover as a seam fix.

Per provider, in order, each step idempotent (crash anywhere → re-run converges):

1. **Import** as `<kind>:<provider>:main` (`apikey:` for `api`, `oauth:` for `oauth`),
   payload = the material the shape carries. Existing record: decrypt + compare; identical
   → reuse; different → abort unless `--replace`. Chain: `import`.
2. **Mint** a handle → handle file via temp + fsync + rename, mode 600. An old handle for
   the same account is revoked only AFTER the new file has been RE-READ and matches.
   Chain: `mint_handle`, `revoke_handle`.
3. **Tombstone** the entry (§6), atomic temp + rename, mode preserved, only after step 2's
   re-read succeeded. Re-read `auth.json` after write; mismatch is reported, not retried.
4. **Report**. `--dry-run` stops before step 1 and prints the plan with compare verdicts.

Refuses: `auth.json` not mode 600; a shape with no mapping; a tombstone that does not
round-trip `isTombstone`.

`--restore <provider>`: REFUSES if the vault record is `needs_reauth` (writing a dead key
back is a silent failure). Otherwise decrypt `main`, rewrite the real entry, revoke all the
provider's handles, drop it from the handle file. Vault records are kept.

`opencode-account`: `add` imports `<kind>:<provider>:<label>`, mints, inserts in priority
order; `remove` revokes and drops the list entry (record kept); `list` prints label,
record_version, state — no material.

### Tenant plugin OAuth migration

A dedicated tenant plugin exports a normalized, secret-bearing 0600 JSON file (maximum 256 KiB):

```json
{
  "version": 1,
  "provider": "anthropic",
  "serve": "anthropic-auth",
  "accounts": [
    {
      "label": "work",
      "kind": "oauth",
      "access": "…",
      "refresh": "…",
      "expires_ms": 1735689600000,
      "account_id": "optional-stable-id",
      "email": "optional@example.test"
    }
  ]
}
```

`ck auth migrate-plugin` validates the complete export before its first vault write, imports each
account as `oauth:<provider>:<label>`, mints a capability, and writes its `{ provider, shape:
"oauth", serve }` block through the tenant-scoped manifest lock. It never reads or writes
OpenCode `auth.json`; `main` is deliberately excluded from this fallback path. Flow: **plugin
export → ck auth migrate-plugin → tenant enroll sweep sees the entries**. Re-run with
`--replace` to advance an existing record and rewrite its manifest entry, or `--skip-existing` to
leave an existing record alone (its manifest entry is skipped too, whether present or absent).
Without either flag an existing record or manifest label refuses the whole run before any write.

Handle file (ordered = priority order; `serve` = the plugin id that owns the provider):

```json
{ "version": 1,
  "providers": [
    { "provider": "deepseek",  "shape": "api",   "serve": "opencode-claustrum",
      "accounts": [ { "label": "main", "handle": "ckh_…", "credential_id": "apikey:deepseek:main" },
                    { "label": "alt",  "handle": "ckh_…", "credential_id": "apikey:deepseek:alt" } ] },
    { "provider": "anthropic", "shape": "oauth", "serve": "anthropic-auth",
      "accounts": [ { "label": "main", "handle": "ckh_…", "credential_id": "oauth:anthropic:main" } ] } ] }
```

(Arrays, not maps, at both levels: array position is priority order and survives Rust↔TS
round-trips without relying on object-key ordering. `serve` is REQUIRED; empty/missing fails
validation on both sides. An account MAY carry an optional `superseded: ["ckh_…"]` journal —
raw old handles awaiting revocation during a `--replace`, written BEFORE the tombstone step and
cleared AFTER revocation succeeds, so a crash in between leaves them recoverable and every rerun's
first action is to revoke what is journaled. Consumers never serve a superseded handle; readers
must accept and ignore the field. Found during implementation: without it a failed post-tombstone
re-read orphaned the old raw handle with no admin op able to name it.)

Lineage is `(label, record_version)` — a `--replace` bumps `record_version` and that is the
replacement discriminator. No separate lineage id is introduced.

## 6. Tombstone (one convention, every shape)

```json
"deepseek":  { "type": "api",   "key": "claustrum-tombstone:v1:deepseek" }
"anthropic": { "type": "oauth", "access":  "claustrum-tombstone:v1:anthropic",
                                 "refresh": "claustrum-tombstone:v1:anthropic",
                                 "expires": 0 }
```

- `SENTINEL(p) = "claustrum-tombstone:v1:<provider>"` — non-secret, versioned,
  provider-bound (copy-paste onto another provider fails `isTombstone`).
- `api`: `key` = sentinel. `oauth`: `access` = sentinel (if it ever reaches the network the
  request itself names the cause); `refresh` = sentinel and NON-EMPTY (OpenCode `Auth.all()`
  drops entries with missing/null refresh, and then no loader runs); `expires: 0` so any
  reader that forgets its guard sees an always-expired token and takes the refresh path —
  which is exactly where the owning plugin's guard lives. A far-future `expires` would let
  an unguarded reader serve the sentinel to the wire.
- `isTombstone(entry, provider)` is an EXACT match on `type` and on every sentinel-bearing
  field. Not `OAUTH_DUMMY_KEY`: core does not special-case it.
- `packages/opencode/golden/tombstone.json` holds the canonical instance of every shape.
  Rust `include_str!`s it; this plugin imports it; anthropic-auth pins the same file.
  Three suites, one shape.

A lost tombstone (#46128 clobber) disables the provider for that session and re-running
`migrate-opencode` converges. A tombstone overwritten by a REAL credential is split custody
and is detected per request (§7).

## 7. Serve closure (generic plugin, providers it owns)

Load (config hook, once per OpenCode start): read the handle file AND `auth.json`. Injection
requires the CONJUNCTION of two independent signals — the tombstone is the sole source of
truth for ABSENCE of a local credential, the handle file the sole source of truth for
OWNERSHIP; neither is ever inferred from the other, and no slot is served on one signal.
Six states, all explicit: four ownership cells plus the unowned-real and operator-disabled cases.

| `auth.json` entry | handle file `serve` | action |
|---|---|---|
| tombstone | `opencode-claustrum` | inject `cfg.provider[p].options = { apiKey: SENTINEL(p), fetch }` |
| tombstone | absent or unreadable handle file | `CustodyOrphan`: log loud, name the fix (`migrate-opencode --serve-by …`), inject a REFUSING fetch because no live owner can be proven |
| tombstone | other owner | not ours — inject nothing, debug log only; the named owner serves it |
| real credential | `opencode-claustrum` | `SplitCustody`: log loud; inject a REFUSING `fetch` that rejects with `CustodySplitError` before any request leaves the process (`apiKey` untouched). Serving either copy is wrong: the local key rotates the family away from the vault; the vault copy ignores what the operator just wrote. Never throw from the `config` hook itself: that takes down every provider, not the split one. |
| real credential | absent | not ours; untouched |
| any | any, with `CLAUSTRUM_CUSTODY_DISABLE=1` | fail-open by operator instruction; the plugin warns that tombstones go to the wire and fail with 401 until restore or re-enable |

The SplitCustody row is the hazard specific to the config hook: `1485`/`1646` merge unvalidated,
so a stale `serve` entry after `--restore` (or a hand-restored key) would otherwise inject
the sentinel over a real credential with no tombstone left to flag it. Dedicated-plugin
owners implement the same table for their own `serve` value (anthropic-auth: trigger =
`isTombstone`, authorization = `serve`, same four cells, same typed errors).

### Auth-read conjunction and bounded recovery

The handle reader treats an absent file as an empty provider list. Separately, an auth-read
failure refuses only providers the handle file names. Those paths are individually correct but
their conjunction is not: an oversized or malformed auth source containing a tombstone plus an
absent handle file used to leave no provider to refuse, so OpenCode sent the tombstone as the key.
When the selected auth source cannot be fully read, parsed, or validated, scan its raw source in
bounded chunks for `claustrum-tombstone:v1:<provider>` and refuse those providers, unioned with
any readable `serve: opencode-claustrum` handles. No scan hit with no owned handle leaves a
never-migrated user alone deliberately; refusing all configured providers there would turn a
large local `auth.json` into an unrelated outage.

A sentinel under the wrong key is not ownership proof for the key: if
`claustrum-tombstone:v1:A` sits under key B, the scan refuses A while B (the entry actually
carrying the tombstone) is NOT refused and 401s with the sentinel as its key. This is acceptable
only because the sentinel is NON-SECRET: the worst case is availability loss on two providers, no
credential exposed. The plugin deliberately does not refuse on bare prefix presence: that is a
hand-edit-only scenario, and doing so would degrade this path to refusing owners plus all
configured providers.

The raw-byte scan does not recognize JSON escapes: `"\\u0063laustrum-tombstone:v1:deepseek"`
parses to the sentinel but has no raw prefix. It requires an absent handle file, a parse failure,
and a hand edit or foreign writer because the CLI writes unescaped sentinels. This known hole and
the never-migrated accommodation are the same no-hit branch from two sides: closing the hole by
refusing owned plus configured providers silently breaks the accommodation, so a change to either
requires deciding both.

The vault connect (`detect` + route + identity per §4) is LAZY: it happens on the first
request that actually needs a credential or on the oauth tick (if `setInterval` is wired),
NOT at config-hook load. The config hook only reads handles and `auth.json`. Warming is
retried per request: a vault that is unreachable at load keeps the cache cold; the first
request re-attempts and warms with one `credential.get` under a bounded await (≤100 ms).
Warm attempts are once per account per tick with per-handle backoff on transient failure
(13 gets → 1 measured upstream when this was added).

Per request:

```
entry = getAuth(p)                                   // re-read EVERY call
if !isTombstone(entry, p): throw                     // split custody: real credential present
for account in priority order, skipping cooldown/unusable:
    material = peek(account) ?? await get(account)   // request path prefers peek (§3 bimodal)
    substitute SENTINEL(p) → material in EVERY header value and URL query parameter
    res = forward(request)
    2xx / other      → return res
    401              → report_auth_failure(handle, 401, served record_version, "direct");
                       mark unusable (OBSERVATION of the vault latch, not a decision); next
    429              → cooldown = Retry-After ?? 60 s; next
    402              → cooldown 1 h; next
exhausted → throw naming provider, per-account state, and the fix
```

Rules:
- Sentinel substitution is how the plugin stays provider-agnostic: OC's SDK already put the
  key where that provider wants it; the closure never learns header names.
- ONLY 401 is reported; 402/403/429/5xx are never a credential verdict. Reports carry the
  record_version of the material actually sent on THAT response (per-Response provenance —
  if a second material source is ever added, the fence must be keyed on the Response object,
  never inferred from "this account has a handle").
- Failover completes before any body is streamed to the caller.
- Per-account state is per-process, in memory only — deliberately NOT persisted (a persisted
  error state needs an older-writer fence across concurrent processes; v1 sidesteps it).
- Freshness by shape (`freshness.ts`): `api` → opportunistic re-get every 10 min per account
  (observes operator rotation/revocation). `oauth` → 60 s unref'd tick calling `get` with
  `min_ttl_ms ≥ refresh-before-expiry + margin` (the vault refreshes inside its window; the
  plugin only ticks; runs with ZERO traffic — the idle-account case that killed the first
  custody round). The vault does every refresh; the plugin never holds a refresh token.
- Two operator-facing states in logs: `vault_latched` (record `needs_reauth` → re-import) vs
  `handle_revoked` (`permanent + not_found` → re-run `migrate-opencode`).
- Never logged: handles, material, sentinels' substituted values. Logged: provider, account
  label, record_version, error class.

Providers with `serve != "opencode-claustrum"` are untouched by this plugin: their owner
(e.g. anthropic-auth) reads the same handle file and tombstone, uses this client, and runs
its own `auth.loader`, router, and refresh policy (account-scoped prompt cache, quota-header
harvest, killswitch thresholds — none expressible as an ordered list, so no selection hook
is offered; ownership is the seam).

## 8. Verification

**Spike (task 0):** config-hook-injected `fetch` observed on a real request on stock
1.18.25, with the sentinel visible in the outgoing headers. Recorded as an executed arm with
its output, not as a code read.

**Rust unit** (scratch vault + fixture `auth.json`): dry-run writes nothing · first run →
`import`/`mint_handle` rows, tombstone, handle file with `serve` + `shape` · re-run no-op ·
differing key aborts without `--replace`, versions with it · `--restore` round-trips exact
bytes, revokes, and REFUSES on `needs_reauth` · mode ≠ 600 refused · unmapped shape refused ·
step-2 re-read gate · `opencode-account add/remove/list` · golden pin for every shape.
`scripts/gate.sh` floors raised.

**TS unit** (`bun test`, offline, network-namespace-safe): wire codec against captured frames
· identity scrub (a poisoned `SUBC_LAUNCH_NONCE` in env must not reach the handshake) ·
unknown error class → transient · reconnect after a terminal `SubcCallError` · `isTombstone`
exact match for `api` and `oauth`, wrong-provider rejection · sentinel substitution in
`Authorization`, `x-api-key`, and a URL query param · closure state machine with a stubbed
upstream: 401 → report + next, 429 → cooldown + next, 402 → long cooldown, exhaustion,
report fires ONLY on 401, split-custody throw · `oauth` tick issues `get` with `min_ttl`
and no traffic · the four-cell injection table: exactly one cell injects, the two disagreement
cells raise typed `CustodyOrphan` / `SplitCustody` · logger capture asserting no handle/material is ever emitted.

**Live acceptance** on this box, stock 1.18.25, rollback = `--restore`:
1. migrate the `api` providers → tombstones in `auth.json`, handle file with ownership;
2. one real routed request per provider succeeds; chain shows only `import`/`mint_handle`;
3. revoke one handle → next request fails `handle_revoked`; re-run migrate converges;
4. `opencode-account add deepseek --account alt` with a dead key at priority 1 → 401 → chain
   `report_auth_failure reporter_source=direct` + `stale_nonrefreshable_latch` → failover to
   `main` completes the SAME request;
5. handle file marks a provider `serve: "someone-else"` → this plugin injects nothing for it;
   an absent or unreadable handle file instead receives a refusing fetch (`CustodyOrphan` logged);
6. restore a real key into `auth.json` by hand while the handle file still says
   `serve: "opencode-claustrum"` → `SplitCustody` logged, refusing fetch injected, the real key is
   NOT sent by anyone (the request is refused before it leaves the process) and the sentinel is NOT sent.

## 9. Out of scope, seams reserved

- **`oauth` on dedicated-plugin providers (anthropic first):** anthropic-auth adds
  `assertNotCustodyTombstone` at the head of its six refresh entrypoints (typed
  custody-misconfiguration error, explicitly NOT `permanent`/`invalid_grant`), branches its
  loader on `isTombstone` before the expiry check, consumes this client, reads this handle
  file. Co-owned: the golden file and that guard PR. `migrate-opencode --serve-by
  anthropic-auth` writes the ownership.
- **Provider-specific and native paths:** generic custody applies only after a per-provider
  proof that the live credential path is the AI SDK fetch seam. xai, codex, copilot,
  snowflake, model-discovery paths, custom loaders, and environment-backed paths are not
  implied by config precedence. The provider allowlist is deliberately open pending operator
  adjudication; providers needing transforms or dedicated auth get a dedicated owner.
- **Claude Code / Codex:** different integration shape, separate spec.
- **Upstream #46131:** flock plus atomic auth writes reduce torn reads on newer OpenCode, but
  custody still treats environment snapshots and ownership disagreement as independent seams.
- **Status UI / slash command:** not in v1; state changes are logged.

## 10. Risks named

- The config-hook seam is a source read until the spike runs; the plan stops on failure.
- Sentinel substitution assumes the SDK sends the key verbatim; a provider that transforms
  it (e.g. base64 basic auth) would not match — detected by the request failing loudly with
  the sentinel in the failure, never by serving anything.
- The sentinel reaches the network if the plugin fails to load: a 401 whose request names
  the cause; there is no report path from a naive reader, so no spurious report.
- `Provider.Info.key` is serialized through OpenCode provider API/UI payloads, so a tombstone
  can look configured. It is non-secret; upstream redaction/status separation remains a
  possible later improvement.
- Native LLM mode bypasses generic provider `options.fetch` for API auth on stock 1.18.25;
  custody serves only when `OPENCODE_EXPERIMENTAL_NATIVE_LLM` is absent or exactly `false`, `no`,
  `off`, `0`, or `n`, and otherwise refuses observed entries.
- Two languages and three suites pin one tombstone shape; the golden file is the only defence.
