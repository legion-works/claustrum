# OpenCode Claustrum plugin

This plugin owns OpenCode providers whose credentials live in Claustrum. It reads the handle file during OpenCode configuration and injects a tombstone API key plus a fetch hook only when the local auth entry is a Claustrum tombstone and the handle file assigns that provider to `opencode-claustrum`.

| `auth.json` | handle `serve` | action |
| --- | --- | --- |
| tombstone | `opencode-claustrum` | inject the Claustrum fetch hook |
| tombstone | absent | log `CustodyOrphanError`; do not inject |
| tombstone | another owner | leave it for that owner |
| real credential | `opencode-claustrum` | log `CustodySplitError`; do not inject |
| real credential | absent | leave the stock provider alone |
| real credential | another owner | leave the stock provider alone |

The handle file comes from `CLAUSTRUM_OPENCODE_HANDLES`, or from `${XDG_CONFIG_HOME:-$HOME/.config}/cortexkit/opencode-handles.json`. It must be a regular file owned by the current user with mode `0600`. OpenCode auth is read from `${XDG_DATA_HOME:-$HOME/.local/share}/opencode/auth.json`.

Run `ck auth migrate-opencode` to create or repair the tombstones and handle file. `superseded` handles remain in the file for migration history. They are not servable accounts.
