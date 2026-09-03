# OpenCode Claustrum plugin

This plugin owns only providers whose live credential path remains OpenCode's generic AI SDK `fetch` seam. It reads the handle file during OpenCode configuration and injects a tombstone API key plus a fetch hook only when the local auth entry is a Claustrum tombstone and the handle file assigns that provider to `opencode-claustrum`. Provider-specific loaders and credential paths need dedicated ownership; the provider allowlist question remains open.

## Seam boundary

This is a config-hook/fetch-seam integration, **not provider-universal custody**. A `type:"api"`
entry is servable only when OpenCode keeps its key inside the generic `options.fetch` path. The CLI
refuses known counter-shapes before it writes a tombstone:

| shape | why |
| --- | --- |
| `api-env` | OpenCode copies the key into `process.env` at provider load; serving it would put material in the environment. |
| `api-discovery` | Model discovery or a loader closure uses the key outside the fetch seam, where provider options can be serialized. |
| `api-metadata` | The provider reads API auth metadata that a metadata-less tombstone cannot supply. |

`crates/credentials-module/src/bin/cli_support/opencode-provider-shapes.json` is data maintained
from OpenCode source for every base update; it records source sites, negative determinations, and
the concrete effect of `--force-shape`. Unlisted providers default to `api`/fetch-seam eligibility.
The plugin never reads this table: only the CLI that creates tombstones does.

| `auth.json` | handle `serve` | action |
| --- | --- | --- |
| tombstone | `opencode-claustrum` | inject the Claustrum fetch hook |
| tombstone | absent | log `CustodyOrphanError`; inject a refusing fetch |
| tombstone | unreadable handle file | log `CustodyOrphanError`; inject a refusing fetch |
| tombstone | another owner | leave it for that owner |
| real credential | `opencode-claustrum` | log `CustodySplitError`; inject a refusing fetch |
| real credential | absent | leave the stock provider alone |
| real credential | another owner | leave the stock provider alone |
| absent | `opencode-claustrum` | log `CustodyOrphanError`; do not inject |
| any | any, with `CLAUSTRUM_CUSTODY_DISABLE=1` | fail-open by operator instruction; tombstoned providers fail with a 401 until restored or custody is re-enabled |

| credential shape | freshness policy |
| --- | --- |
| `api` | Re-observe the served credential on the next request after 10 minutes. |
| `oauth` | Run one unref'd 60-second warm tick, requesting at least 270 minutes of TTL by default. Each warm waits at most 100 ms on the request path and continues detached. |

The handle file comes from `CLAUSTRUM_OPENCODE_HANDLES`, or from `${XDG_CONFIG_HOME:-$HOME/.config}/cortexkit/opencode-handles.json`. It must be a regular file owned by the current user with mode `0600`; symlinks are refused. Provider ids and account labels must match `^[a-z0-9][a-z0-9._-]{0,63}$` and cannot be `__proto__`, `constructor`, or `prototype`. OpenCode auth is read from `OPENCODE_AUTH_CONTENT` when it is set, otherwise from `${XDG_DATA_HOME:-$HOME/.local/share}/opencode/auth.json`.

The plugin remains a read-only manifest consumer. Tenant writers such as `anthropic-auth`, `openai-auth`, and `ck-auth` use the client manifest lock before the read-modify-write, renew its owner lease while held, publish with an explicit `0600` mode, and preserve every other tenant block.

If the selected auth source cannot be parsed or validated, the plugin scans it in bounded chunks for self-describing tombstones and refuses the named providers. No scan hit leaves a never-migrated oversized auth source alone. A raw scan does not recognize JSON-escaped sentinel bytes; that hand-edit/foreign-writer limitation shares the same no-hit branch, so changing either behavior requires deciding both.

OpenCode's provider API and UI serialize `Provider.Info.key`, so a tombstone can look like a configured credential. It is non-secret and does not grant access; custody still refuses when ownership cannot be proven.

`OPENCODE_EXPERIMENTAL_NATIVE_LLM` bypasses this plugin's generic fetch seam when set to an enabling or unrecognized value on stock OpenCode 1.18.25. The plugin serves only when it is absent or exactly `false`, `no`, `off`, `0`, or `n`; it otherwise refuses observed custody entries and names the observed value.

Run `ck auth migrate-opencode` to create or repair the tombstones and handle file. `superseded` handles remain in the file for migration history. They are not servable accounts.

For a manual handoff, use `ck auth login … → ck auth mint-handle <id> --out <file> → tenant enroll reads the file`; the output file is newly created with mode `0600` and the handle is not printed.

## Maintenance

Keep the sweep's control-flow smoke signal on two greps -- one for branches (`if (`),
one for exits (`return` / `continue` / `catch`). Each grep returns exactly one number
per file, so the table stays checkable by reading; the previous format used X/Y pairs
that did not match the documented greps and could be copied forward stale.

```sh
grep -cE '^\s*if \(' packages/opencode/src/{plugin,serve}.ts
grep -cE '^\s*(catch|} catch)|^\s*return[; ]|^\s*continue;' packages/opencode/src/{plugin,serve}.ts
```

| revision | `plugin.ts` branches | `plugin.ts` exits | `serve.ts` branches | `serve.ts` exits |
| --- | --- | --- | --- | --- |
| `eb034af` | 22 | 14 | 13 | 9 |
| `57ce561` | 22 | 14 | 13 | 9 |
| closing-wave worktree | 27 | 18 | 13 | 9 |
| custody review triage | 27 | 18 | 13 | 9 |
| `a3b3a6c` | 27 | 21 | 13 | 10 |
| current (this commit) | 32 | 41 | 13 | 14 |

A changed count without a matching sweep row is a review failure, not harmless churn.

The branches/exits census cannot see a subcondition inside a counted branch. The containment
property test is the invariant; this census remains the drift canary.
