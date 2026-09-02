# OpenCode Claustrum plugin

This plugin owns only providers whose live credential path remains OpenCode's generic AI SDK `fetch` seam. It reads the handle file during OpenCode configuration and injects a tombstone API key plus a fetch hook only when the local auth entry is a Claustrum tombstone and the handle file assigns that provider to `opencode-claustrum`. Provider-specific loaders and credential paths need dedicated ownership; the provider allowlist question remains open.

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

| credential shape | freshness policy |
| --- | --- |
| `api` | Re-observe the served credential on the next request after 10 minutes. |
| `oauth` | Run one unref'd 60-second warm tick, requesting at least 270 minutes of TTL by default. Each warm waits at most 100 ms on the request path and continues detached. |

The handle file comes from `CLAUSTRUM_OPENCODE_HANDLES`, or from `${XDG_CONFIG_HOME:-$HOME/.config}/cortexkit/opencode-handles.json`. It must be a regular file owned by the current user with mode `0600`; symlinks are refused. Provider ids and account labels must match `^[a-z0-9][a-z0-9._-]{0,63}$` and cannot be `__proto__`, `constructor`, or `prototype`. OpenCode auth is read from `OPENCODE_AUTH_CONTENT` when it is set, otherwise from `${XDG_DATA_HOME:-$HOME/.local/share}/opencode/auth.json`.

OpenCode's provider API and UI serialize `Provider.Info.key`, so a tombstone can look like a configured credential. It is non-secret and does not grant access; custody still refuses when ownership cannot be proven.

`OPENCODE_EXPERIMENTAL_NATIVE_LLM` bypasses this plugin's generic fetch seam when set to an enabling or unrecognized value on stock OpenCode 1.18.25. The plugin serves only when it is absent or exactly `false`, `no`, `off`, `0`, or `n`; it otherwise refuses observed custody entries and names the observed value.

Run `ck auth migrate-opencode` to create or repair the tombstones and handle file. `superseded` handles remain in the file for migration history. They are not servable accounts.
