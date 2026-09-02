# Operator runbook — claustrum (the credential vault)

How an operator provisions the credential vault and wires a consumer to it. The
vault is a subc-supervised daemon plus an admin CLI; this is the end-to-end flow
from an empty machine to a consumer reading a credential.

There are two programs:

- **`ck-claustrum`** — the daemon. subc supervises it; it serves the
  read surface (`credential.get` / `get_many` / `status` / `report_auth_failure`)
  over the route channel, and the authenticated admin surface described below.
  (Built from the `credentials-module` crate; the module id remains
  `claustrum`.)
- **`ck-auth`** — the admin tool, invoked as `ck auth <verb>`. The **only** write
  surface (login, import, invalidate, rotate, mint/revoke handles, audit). Most
  verbs commit through the **running** daemon with no downtime; a few are
  offline-only (see "The single-writer rule" below).

> On a standard install, admin commands need **no flags at all** — both the vault
> data directory and the running daemon's connection file are auto-discovered.
> The flags below matter only for a non-default location (a test vault, a second
> vault on the same machine, or a key held outside the keychain).
>
> All admin commands accept `--data-dir <dir>` (the vault's data directory, holding
> `store.db`) and a key source: `--key-path <file>` for an operator-path key, or
> nothing for the macOS keychain default.
>
> **The DAEMON has no such flag — it reads `CK_MASTER_KEY_PATH` from its
> environment instead**, set in `subc.jsonc`. Same choice, two different
> mechanisms, and they must agree: if the CLI is given `--key-path` while the
> daemon has no `CK_MASTER_KEY_PATH`, the daemon looks in the keychain, finds
> nothing for that vault, and fails closed with `vault_locked` while every CLI
> command works. On this host neither is set — both halves use the keychain — so
> the variable matters only for a headless or CI deployment.
>
> The OTHER environment variables the vault is sensitive to are supplied by the
> supervisor, not by you: `XDG_DATA_HOME` and `XDG_RUNTIME_DIR` (which move the
> data directory and the connection file), and `SUBC_MODULE_ID` / `SUBC_LAUNCH_NONCE`
> (identity, echoed at HELLO). **Moving the data directory does not silently start
> a fresh vault**: the daemon never bootstraps — only `ck auth bootstrap` creates a
> key — so a relocated vault finds no key for its new keychain scope and refuses to
> serve rather than coming up empty. Verified at the boot path, and worth knowing
> because the opposite behaviour (start fresh, look healthy) is the common one for
> state directories and is what a sibling module's redemption journal does.
>
> `CK_GOOGLE_OAUTH_CLIENT_ID` / `_SECRET` and the `CK_ANTIGRAVITY_*` pair override
> the embedded public OAuth clients. Deliberately left out of the procedures below:
> a wrong value fails loudly at the provider with a reason, so it needs no runbook
> entry — recorded here so a later sweep does not re-open the question.
>
> **`--data-dir` must be `<data_home>/cortexkit/<module_id>`**, where `<module_id>`
> is the subc.jsonc module key — **`claustrum`**, NOT a shortened
> `credentials`. The supervised daemon derives its store path from the module id
> verbatim, so the CLI must use the same full id or it opens a *different*
> (empty) vault under a different keychain scope. On a default desktop:
>
> ```sh
> DATA_DIR=~/.local/share/cortexkit/claustrum
> ```

---

## Deploy artifacts: what to keep, and why the pile is a hazard

Two things accumulate every time a binary is placed, and nothing in the loop
removed either until 2026-08-15, when 21 rollback copies and 15 staged trees
(407MB) had built up unnoticed.

**Staged trees** (`target/staged/<rev>/`) are pruned automatically by
`scripts/release-build.sh`: it keeps the three newest AND, whatever its age, the
stage matching the currently deployed binary. It learns which that is by running
`ck-auth --version`, the same ask-the-artifact instrument the acceptance legs
use. The deployed one is exempt because it is the stage you would diff against
during an incident, and it ages out exactly when several later revs were staged
and never deployed — which is the case where you most want it.

**Rollback copies** (`~/.local/share/cortexkit/bin/ck-auth.pre-<rev>-<ts>`) are
created by hand at placement and are NOT pruned automatically, because deleting
from the fleet bin path should be a deliberate act. Keep the two most recent;
delete the rest.

The retention rule is not about disk. A rollback copy is useful only until the
next deploy is accepted, and every one is reproducible by re-running
`release-build.sh` at its rev. **The real cost of the pile is that the fleet bin
path ends up holding twenty similarly-named `ck-auth` binaries, which is a place
where somebody eventually runs the wrong one.**

One that will not be reproducible from its name: a copy named for an event
rather than a rev, e.g. `ck-auth.pre-claustrum-*` from the module rename. That
one also targeted the pre-rename data directory, so running it would have been
actively wrong rather than merely old — worth deleting on sight rather than
keeping for sentiment.

## The single-writer rule (read this first)

There is exactly one writer at a time, always. What changes is **who** it is.

When the daemon is running it holds the vault's single-writer lease, so the CLI
cannot open the store directly. Instead the CLI sends the operation **to** the
daemon over the route plane, and the daemon — the lease holder — performs the
write, serialized against any in-flight token refresh. This is the normal path and
it needs no downtime: re-logging in a provider while agents are actively reading
credentials is safe and expected.

The daemon does not take the operator's word for it. Each op is authenticated by a
challenge-response MAC over the exact operation bytes, keyed by the **master key** —
so the caller proves possession of the key that the vault's contents are sealed
under, per operation, with a single-use nonce. A compromised daemon cannot
authorize a mutation it was not given, and a caller without the master key cannot
mutate anything.

When the daemon is **not** running, the CLI takes the lease itself and writes
directly. Same operations, same audit chain, same master-key requirement.

**Offline-only verbs.** Four commands always require the daemon stopped, because
they operate on the store as a whole rather than on one credential:

| verb | why it is offline-only |
|------|------------------------|
| `bootstrap` | creates the vault; there is no daemon yet |
| `rotate-master-key` | re-wraps every record and the sealed audit key in one transaction |

Run these with the daemon stopped. Every other write verb — `login`, `logout`,
`remove`, `put`, `import`, `invalidate`, `mint-handle`, `revoke-handle`,
`revoke-all-handles` — commits through the running daemon, and falls back to the
offline lease path automatically when no daemon is reachable.

Exit codes:

| code | meaning | what to do |
|-----:|---------|------------|
| 0 | success | — |
| 3 | the daemon holds the lease and this verb is offline-only | stop the daemon, retry |
| 4 | master key could not be resolved (locked keychain / absent / wrong) | unlock the keychain, or check `--key-path` |
| 5 | **indeterminate** — the op reached the daemon but the reply was lost | see below |
| 1 | usage / IO / other error | read the message |

**Exit code 5 is the one that needs care.** It means the operation was sent to the
running daemon and the connection dropped before the outcome came back, so it may
or may not have committed. Do **not** blindly retry — check first with `ck auth
list` (did the credential's version change?) or `ck auth audit` (is there an entry
for it?), then act on what you find.

The other two outcomes are unambiguous by construction. A **refusal** from a live
daemon is terminal and safe — the daemon was alive and said no, so nothing was
written and the CLI never falls back. **No reachable daemon** means nothing was
dispatched at all, which is why falling back to the offline path cannot
double-execute.

---

## 1. Bootstrap the master key (once per machine)

The master key encrypts every credential at rest. Provision it once. It is created
once and never regenerated; a second bootstrap is refused rather than clobbering
the existing key (which would brick the vault).

**Keychain (desktop default, macOS):**

```sh
ck auth bootstrap --data-dir "$DATA_DIR"
```

**Operator-path (headless / server):** the key file **must live outside the data
directory** (co-locating the key with the ciphertext defeats at-rest encryption);
the CLI refuses a key path inside `--data-dir`.

```sh
ck auth bootstrap --data-dir "$DATA_DIR" --key-path /etc/cortexkit/master.key
```

`$DATA_DIR` is the vault's data directory. Under subc supervision the daemon
resolves it to `<data_home>/cortexkit/claustrum/` — the admin CLI must
point `--data-dir` at that **same** directory so both operate on one vault.

---

## 2. Import or put a credential

**Import an existing OAuth login** (e.g. an opencode `auth.json` entry — the shared
`{ refresh, access, expires }` shape):

```sh
ck auth import \
  --source opencode \
  --provider anthropic \
  --id oauth:anthropic \
  --json /path/to/auth.json
```

`--source` is one of `opencode | pi | gemini-cli | antigravity`. The provider's
token URL and client id are supplied by the refresh adapter, not the file.

**The credential `--id` is `<method>:<provider>[:<account>]`** (e.g. `oauth:anthropic`,
`apikey:deepseek`, `antigravity:google`). The `<method>` selects the credential kind
and the refresh adapter the record stores — `oauth`→the provider-named adapter,
`antigravity`→the `antigravity` adapter, `apikey`→a static key (no adapter). It is
NOT derived from the id by position (no positional rule is uniform — `oauth:anthropic`
wants the provider segment, `antigravity:google` the method segment); pass
`--adapter <name>` to override the method default. A legacy `<provider>[:<account>]`
id (first segment not a known method) defaults to the provider's oauth adapter.

Source-specific notes:

- **API keys:** an `apikey:<provider>` id imports a `{ "type": "api", "key": "..." }`
  entry as a static key. The real `auth.json` is a map keyed by provider, so
  `--provider <key>` selects the entry (`--source opencode --provider deepseek
  --id apikey:deepseek`). `credential.get` returns the key bytes verbatim.
- **OAuth (auth.json):** `--provider <key>` selects one provider's
  `{ refresh, access, expires }` entry from the map. Without it, `--json` must point
  at a single provider's object.
- **Google must be imported from `gemini-cli` or `antigravity`, not opencode.** A
  Google refresh token only refreshes against the OAuth client that minted it.
  `--source gemini-cli` reads `~/.gemini/oauth_creds.json` (the gemini-cli Code-Assist
  login, single credential, no `--provider`). `--source antigravity` reads
  `~/.config/opencode/antigravity-accounts.json` (the antigravity plugin's accounts
  array; `--provider` selects an account by email or index, default the active one)
  and is the source for an `antigravity:google` id. An opencode-minted google token
  cannot be refreshed by either and fails closed to `needs_reauth`.
- `--replace` overwrites an existing id unconditionally (re-seal at version+1,
  reset to active), for fixing a credential imported from the wrong source. Existing
  handles keep resolving to the id — **no re-mint needed**. Without `--replace`,
  `import` is create-only and an existing id is refused. `--account-id <id>` attaches
  non-secret account metadata; `--email` and `--org-name` require it, while
  `--clear-identity` is mutually exclusive with all three. A token-only
  `import --replace` preserves the existing identity; explicit identity flags override
  it and `--clear-identity` drops it. To label a vault-custodied credential without
  replacing its token family from a source file, use `ck auth set-identity
  <credential-id> --account-id <id> [--email <email>] [--org-name <name>]` (or
  `--clear`): it re-seals unchanged material, keeps lifecycle state, and bumps
  `record_version`.

**Put a static credential** (API key / DSN / opaque). Use `--payload-file <path>`
for a secret so it never appears in the process list or shell history; `--payload
<value>` passes the exact bytes inline. A bare key file (e.g. `~/.config/openai.key`)
is read with trailing whitespace stripped:

```sh
ck auth put \
  --id apikey:openai \
  --payload-file ~/.config/openai.key \
  --kind api_key
```

`put` is create-only; an existing id is refused. To rotate a static key in place,
pass `--replace` (unconditional, keeps existing handles) or `--expected-hash <hex>`
(a compare-and-set guard, for when you know the current value).

**Vault-native login — the preferred path, and the one to reach for first.** Import
exists for bootstrapping from another tool's files; `login` mints a NEW, independent
credential that the vault solely custodies, so there is no dual-custody rotation race
with a tool that holds the same provider login.

Run it with no flags at all for an interactive picker over every provider, showing
which already have a credential:

```sh
ck auth login
```

The picker covers OAuth (`anthropic`, `openai`, `xai`, `google`, `antigravity`),
device-flow (`github-copilot`, `kimi`, and `--device` for openai/xai), custom
browser flows (`cursor`, `devin`, `snowflake`, `digitalocean`), and API-key
providers (`zai`, `openrouter`, `deepseek`, `groq`, …), which are validated against
the provider before being stored.

OAuth logins open a browser and complete automatically: a one-shot CLI-local
listener on the loopback redirect captures the code, so **when the browser shows a
paste code, ignore it — the CLI has already finished.** If the port is busy, the
listen fails, or you pass `--no-listener`, the flow falls back to pasting the
address-bar URL. Pasted values are read from stdin only — never argv, never logged.

```sh
ck auth login --provider xai --replace
```

**Multiple accounts per provider** each get their own labeled id, with an
independent refresh chain and its own handles:

```sh
ck auth login --provider anthropic --id oauth:anthropic:work
```

Default ids are `oauth:anthropic`, `chatgpt:openai`, `oauth:xai` (note: a bare
`--provider openai` means the ChatGPT subscription login, not `apikey:openai`).
`--replace` swaps the credential on an existing id and **keeps its handles** — the
usual recovery for a `needs_reauth` credential, and the reason a re-login never
requires re-distributing handles. Without it, `login` is create-only. A native login
records a distinct `Login` audit entry (not `Import`).

---

## 3. Mint a handle and give it to the consumer

A consumer never names a credential directly; it presents a **capability handle**.
Mint one per consumer:

```sh
ck auth mint-handle --id oauth:anthropic
```

The command prints the raw handle (`ckh_...`) to **stdout exactly once** — only its
hash is stored, so it cannot be recovered later. Write it into the consumer's
config (a `0600` file). To rotate a consumer's access, `revoke-handle --handle
<ckh_...>` (or `revoke-all-handles --id <id>`) and mint a fresh one — no re-login.

Mint a **separate handle per consumer** rather than sharing one. Handles are the
revocation unit: with one each, cutting off a single consumer is one `revoke-handle`
and nobody else notices. Handles also survive `login --replace`, so re-authenticating
a provider never means re-distributing them.

---

## 4. Start the daemon; the consumer reads over the route channel

subc supervises the daemon from its `subc.jsonc` (the vault module marked
`reserved: true`, with a `sqlite` storage section). Once it is up, a consumer reads
a credential over the route channel:

```
catalog.list
  → route.open(ManagementSurface, module_id = "claustrum")
  → credential.get { handle: "ckh_..." }   // returns the opaque payload
```

The daemon resolves the handle, refreshes the token if stale (vault-owned OAuth
refresh, single-flight), and returns the credential payload. An unknown or revoked
handle is a uniform `not_found` (no enumeration).

A consumer that observes a 401/403 should call `credential.report_auth_failure
{ handle, provider_status, record_version }` so the vault marks the credential
`needs_reauth` rather than serving a dead token. **`record_version` is required and
is the version the consumer was served.** If the vault has since refreshed to a newer
version, the report is a silent no-op — which is what stops a stale 401 from
invalidating a credential that has already been repaired.

---

## 5. See what the vault holds, and what needs action

```sh
ck auth status   # health ladder + inventory
ck auth list     # one row per credential: <state> v<version> <credential_id>
ck auth grants   # one row per principal-scoped grant
```

None of these commands prints a secret. All read the running daemon when one is up and
fall back to the store directly when it is not.

`status` is the one to run when something is wrong. It reports the same health the
supervisor probes:

| status | meaning | what to do |
|--------|---------|------------|
| `ok` | store readable, lease held, every credential active | — |
| `degraded` | serving, but ≥1 credential is `needs_reauth` or `corrupt` | re-login the named credential |
| `failing` | the store is unreadable, **or** this daemon lost write authority to a newer instance, **or** its background health refresher has stalled | check disk and lease; a stalled refresher means restart the module |

**A degraded vault is still serving every healthy credential** — it names the broken
ones rather than failing whole, which is why a single dead credential never takes the
vault down.

The supervisor logs every non-ok probe, so its log is the history behind that table.
**Strip the colour escapes before searching it**, or field-name patterns match nothing
and return a confident zero:

```sh
sed -E 's/\x1b\[[0-9;]*m//g' ~/.local/share/cortexkit/run/subc.log \
  | grep 'module reported non-ok health' | grep 'module_id=claustrum'
```

Without the `sed`, `status=` never appears as literal bytes — on disk it is
`status\e[0m\e[2m=\e[0m` — so a search for it finds nothing whether or not the
condition ever occurred. That log is also SHARED and interleaved across every
supervised module, with lines spliced mid-field, so require both terms on one line
rather than counting matches anywhere in the file.

Measured 2026-08-11 across the whole log: 906 `Degraded` for this vault and no
`Failing`, so the stalled-refresher arm of that table has never fired in production.
The zero is only worth stating because the same predicate finds the one `Failing`
that does exist fleet-wide — a zero from a pattern that cannot match is not evidence.

To repair a flagged credential, re-login it and keep its handles:

```sh
ck auth login --provider <name> --replace
```

`grants` is read-only and lists the complete authority set. Each row contains the
principal kind and id, credential prefix, operation (`read` or `sign`), and creation
time. The rows are sorted by principal, prefix, then operation, so repeated runs are
stable and a grant differing only by operation remains visible. An empty table prints
`no grants` rather than silently producing no output.

Two verbs express intent that `--replace` does not:

- **`logout`** — stop serving a credential, reversibly. It marks the credential
  `needs_reauth` and revokes every handle in one atomic operation, keeping the record
  and its audit history. A later `login --replace` restores it, though consumers need
  freshly minted handles since the old ones are gone.
- **`remove`** — permanently delete the credential, its refresh intent and its
  handles. Audited, but not undoable.

### Is anything unrecoverable?

The health probe and `ck auth list` both read metadata only — they never open an
envelope, so neither can see a record that decrypts to nothing usable. One tool
answers that, by decrypting every record in memory:

```sh
ck auth usable
ck auth usable --data-dir /srv/vault --key-path /etc/cortexkit/master.key
```

Safe against a running vault: read-only connection, **no lease**, nothing written.
(`mode=ro`, not `immutable=1` — immutable skips the WAL and answers about a live
store's past.)

It scores **stranded** — a record holding neither a usable access token nor refresh
material, so no `get` can recover it without an operator login. **It deliberately
does NOT score access-token expiry**: an expired access token beside live refresh
material is the routine state of a healthy credential, and counting it would report
normal operation as a fault. It also flags an identity that renders a value while
resolving nothing (an email with no account id).

`stranded: 0` is the expected reading. A non-zero count is the signal that a
credential needs a re-login, and it is the one number the health gauge cannot
produce.

## 6. Verify the audit chain

Every durable mutation is recorded in a tamper-evident, HMAC-keyed audit chain.

```sh
ck auth verify-audit    # safe while the daemon runs
ck auth audit           # safe while the daemon runs
```

`verify-audit` reports the chain intact or names the first broken entry. **It takes
no lease**, so it runs against a live vault. It used to require the daemon stopped,
which is why the production chain went six weeks unverified: nobody takes the
credential vault down for an integrity check, and a tamper-evidence mechanism
nobody can afford to invoke provides evidence of nothing.

Four outcomes, deliberately distinct — the middle two are configuration problems
and say so rather than implying tampering:

| outcome | meaning |
|---------|---------|
| `audit chain verified: intact` | every MAC chains to its predecessor |
| `audit chain BROKEN at seq N` | the chain fails at N — inspect from there |
| `no master key slot holds the key this vault is sealed under` | wrong key or wrong vault, not tampering |
| `this vault has no audit key` | nothing to verify against; not an empty chain |

Note what the chain does **not** cover: it is tamper-evident against edits,
reorders and inserts, but not against TRUNCATION. An attacker with write access can
delete a suffix of recent entries and the remaining prefix still verifies. Detecting
that needs an external monotonic anchor (periodically recording the tip
`(last_seq, entry_mac)` off-box), which is out of scope here.
`audit` lists the entries (seq, op, credential, actor, and any alarm) and is also
lease-free. A flagged row prints its REASON in brackets, which matters because the
alarm column is set on every admin write by design: in this vault 169 of 172 flagged
rows are routine `[admin_write]` mints and revokes, and 3 are `[fetch_rate_anomaly]`
-- the real detection signal. Scan for the reason, not for the flag. An alarm row is
a durable signal surfaced here on demand, not a live notification.

### Why a credential stopped working

The chain says a credential was invalidated. It cannot say why — it records
mutations, and the reason lives in fields it has no room for. `ck auth events` answers
that instead:

```sh
ck auth events              # most recent first, 20 by default
ck auth events --limit 100
```

```
2026-08-11 07:58:09  chatgpt:openai   consumer_report  403        v7   applied=yes
2026-08-11 07:57:50  chatgpt:openai   consumer_report  401        v5   applied=no
2026-08-11 06:12:03  oauth:xai        refresh_failed   503 status v2   applied=no
```

- **`consumer_report`** — a consumer spent the token and the provider refused it. The
  status distinguishes a rejected token (401) from a forbidden request (403), which
  point at different causes. The reporter is whoever SAW the refusal, not whoever
  caused it: a report can arrive for a credential that was repaired in between, and
  that case shows as `applied=no` rather than being hidden.
- **`refresh_failed`** — the vault called the provider to refresh and the exchange
  failed. On a transient failure the record is left active and the intent cleared, so
  without this row nothing would show the attempt happened at all.
- **`applied`** — whether the event changed the credential. `no` on a report means the
  version it named had already been replaced, so the report was correctly ignored; a
  run of those is a consumer working from stale state, which nothing else surfaces.

**Unlike `audit`, this takes no lease and works against a running vault** — which is
the point, since the moment to ask is right after a credential fails. **And unlike
`audit`, these rows are not evidence:** they are not tamper-evident, they may be
pruned, and nothing should depend on them being complete. For what authoritatively
happened, read the chain.

Two empty results that mean different things, and the command distinguishes them:
`no authentication events recorded` (nothing has failed) versus `no
authentication-event table yet` (this store predates the migration, so an incident
would leave no trace until the daemon restarts).

**Only the most recent events per credential are kept** (64), because nothing refuses
a report: a consumer stuck in a retry loop would otherwise grow the store without
bound. The trim is per credential rather than global, so a flood against one cannot
evict another's history — which matters, since those are the rows being read during
the incident that caused the flood. A credential showing exactly 64 events has had at
least that many, not exactly that many.

### A 401 report no longer kills a refreshable credential (since `b977878`)

A consumer reporting a 401 at the **current** `record_version` against a **refreshable**
credential marks its token stale and leaves the record `active`. The next `get`
refreshes it. `invalid_grant` still latches `needs_reauth` through the path that
already existed. **Static credentials are unchanged** — they have no recovery path, so
a report still latches immediately.

The three sentences below are the measurement, run by the plexus seat against the live
vault on 2026-08-23 and reproduced verbatim. **They are observations, not predictions:**

> 1. A refreshable credential marked stale by a 401 report recovers inside the next
>    call that resolves it: measured end-to-end 1.5-1.8s per governed dispatch, of
>    which the vault's mark-to-committed-refresh is 1.1-1.3s; the remainder is client
>    overhead and the vendor round trip. The stale state adds no observable penalty to
>    that call versus a normal one.
>
> 2. On a host with active plexus connections, no attached credential waits for
>    deliberate traffic: the plexus health probe resolves every active connection's
>    credential roughly every 60 seconds, so ambient recovery completes within about
>    one probe cycle of the mark. Observed range 5.5-38.1s across three runs, uniform
>    in probe phase; the three recoveries landed exactly one probe period apart, which
>    is the probe's signature. The range is an observation, not a bound — the mechanism
>    (probe cadence + one refresh) is the bound.
>
> 3. The pre-revision behavior — a refreshable credential dead until an operator
>    re-ingests it — is no longer reachable from a 401 at current version.
>    `invalid_grant` still latches `needs_reauth` terminally, and the non-refreshable
>    backstop has never fired (0 events, all time).

**What this replaced, so the gain is legible:** `oauth:xai` went dark for **seven
hours** on 2026-08-21 in exactly this situation — latched by a report 93 minutes after
the vault had refreshed it successfully, and recovered only when a human re-
authenticated. The same event now costs about 1.2 seconds on the next call.

**The attribution the audit chain does NOT record.** `refresh_commit` carries
`actor=vault`, because the vault performs the refresh; nothing records which caller's
`get` triggered it. Sentence 2's mechanism was established without it — the three
ambient recoveries landed 60.2s and 61.1s apart while their marks were 76.9s and 77.1s
apart, so the recovering `get` ticks on a fixed cadence that the marks do not, which is
the probe's signature and not incidental traffic. **A timing signature can identify a
caller that a log field does not**, and that is worth reaching for before adding a
field.

### A consumer report put a credential in `needs_reauth`. Try `reactivate` first.

**Before re-authenticating, check whether the vault's own refreshes were healthy.** A
consumer report is a claim about a served token; it says nothing about the refresh
material, and the two die independently.

```sh
sqlite3 "file:$HOME/.local/share/cortexkit/claustrum/store.db?mode=ro" \
  "SELECT datetime(ts_ms/1000,'unixepoch','localtime'), op
     FROM audit_log WHERE credential_id='<id>' ORDER BY seq DESC LIMIT 8;"
```

**A `refresh_commit` shortly before the report means the refresh token was alive at
that moment**, so the credential was recoverable and a re-login is the expensive
repair for a verdict that may simply be wrong:

```sh
ck auth reactivate --id <id>     # clears needs_reauth, does NOT touch the secret
```

This is safe to try because **it is self-correcting**: the vault re-verifies on next
use, so a credential that really is dead returns to `needs_reauth` on its own and the
wrong guess costs one failed request. It is refused for `corrupt` records, where the
vault checked its own bytes and an operator assertion cannot make them decrypt.

**Why this matters more than it looks.** The vault cannot interpret a provider status.
GitHub returns 403 for a missing permission and for a rate limit; xAI uses it for an
entitlement lapse — same number, opposite meanings, and this surface sees only the
number. So a consumer reporting any refusal, rather than only the ones it believes
mean the credential is invalid, can kill a working credential.

Measured twice. On 2026-08-17 a GitHub App credential was killed seconds after being
minted, by a 403 that meant "this token is valid and lacks one permission". On
2026-08-21 `oauth:xai` was killed by a 403 **93 minutes after the vault had refreshed
it successfully**, having refreshed cleanly every ~6h for days; it stayed dark for
seven hours until a human ran `login`. `reactivate` would have been one command, and
it did not exist for the first incident.

If `reactivate` is followed within minutes by another report at the new version, the
credential is genuinely dead and `login --replace` is the repair.

### The four diagnostic string vocabularies

The vault has four separate string vocabularies that are easy to confuse. They live in
**different tables and columns**:

#### `audit_log.op`

**Table:** `audit_log`

**Column:** `op` (TEXT)

These values come from the closed `AuditOp` enum and name the mutation or chain event:

| Value | Meaning |
| --- | --- |
| `put` | Create a new credential without replacing an existing row. |
| `import` | Import a credential from an external source format. |
| `login` | Mint a vault-native first-party OAuth credential. |
| `overwrite` | Replace a credential under an unconditional or compare-and-set write path. |
| `set_identity` | Re-seal unchanged credential material with updated non-secret account identity. |
| `invalidate` | Mark a credential as needing re-authentication. |
| `rotate_master_key` | Re-wrap the vault under a new master key. |
| `refresh_commit` | Commit new tokens from a vault-owned refresh. |
| `report_auth_failure` | Record a consumer report that changes credential state. |
| `remove` | Permanently remove a credential row while retaining its audit history. |
| `reactivate` | Clear `needs_reauth` without changing the stored secret. |
| `mint_handle` | Mint a capability handle for a credential. |
| `revoke_handle` | Revoke one or all capability handles for a credential. |
| `fetch_anomaly` | Record a read-surface fetch-rate or enumeration anomaly. |
| `grant_create` | Create a principal-scoped credential-prefix read grant. |
| `grant_revoke` | Revoke a principal-scoped credential-prefix read grant. |
| `approval` | Record an approver's approval of the exact artifact bytes identified by a hash. |

#### `audit_log.alarm`

**Table:** `audit_log`

**Column:** `alarm_reason` (TEXT), paired with the `alarm` (INTEGER 0/1) flag

The `op` and `alarm` vocabularies are **different columns**. `op` says what the audit
entry records; an alarm reason says why that entry was flagged. In the schema, the
`alarm` column is only the presence flag, so the strings below are stored in
`alarm_reason` and come from the closed `AlarmReason` enum. Do not combine this list
with the `op` list when querying the audit log:

| Value | Meaning |
| --- | --- |
| `overwrite_without_cas` | An existing credential was overwritten without a compare-and-set guard. |
| `fetch_rate_anomaly` | A connection's credential-fetch rate or spread crossed the anomaly threshold. |
| `admin_write` | An administrative write occurred; admin activity is always flagged. |
| `reconcile_hash_mismatch` | Startup reconciliation found a stored refresh token hash that disagreed with its dangling intent. |

#### `auth_events.kind`

**Table:** `auth_events`

**Column:** `kind` (TEXT)

These values come from the `AuthEventKind` enum. This table is a separate, prunable
diagnostics table, not the tamper-evident audit chain:

| Value | Meaning |
| --- | --- |
| `refresh_failed` | A provider refresh attempt failed without producing a committed replacement. |
| `stale_nonrefreshable_latch` | A stale report on a non-refreshable credential was latched as `needs_reauth`. |
| `consumer_report_stale` | A consumer report marked a refreshable credential stale for its next read. |
| `consumer_report_latch` | A consumer report immediately latched a non-refreshable credential. |
| `scoped_read_refusal` | A principal-scoped read was refused; `detail` names the internal refusal reason. |
| `reconcile_needs_reauth` | Startup reconciliation forced a credential to `needs_reauth`. |
| `github_app_permissions_changed` | A successful GitHub App mint observed changed installation permissions. |

**Retired values you will still meet in the data.** The table above documents what the
CODE WRITES; the table on disk also holds what OLDER binaries wrote, and this table is
not rewritten:

| Retired value | What it was |
| --- | --- |
| `consumer_report` | The single kind that preceded the stale/latch split. A consumer report of an auth failure, before the vault distinguished "mark stale so the next read refreshes" from "latch immediately". Superseded by `consumer_report_stale` and `consumer_report_latch`. |

That one is named rather than left to the general disclaimer because it is not
hypothetical: this vault holds 24 such rows, last written 2026-08-21. An operator who
meets a kind in `ck auth events` and cannot find it here has no way to tell a retired
value from a corrupt one.

Other unknown kinds may still appear (a future retirement, a fixture from a test
harness). Treat them as diagnostics, never as audit-log operations or alarm reasons --
the vocabularies are separate and a value from one is not a value from another.

#### `auth_events.reporter_source`

**Table:** `auth_events`

**Column:** `reporter_source` (TEXT, nullable)

This is a consumer-asserted, unverified claim about where the reported failure was
observed. It is structurally separate from `detail`, which records what the vault
observed. The vault accepts only this closed vocabulary; any other wire string becomes
`unrecognised`, and the original string is never stored:

| Value | Meaning |
| --- | --- |
| `direct` | The consumer saw the provider status on a direct response. |
| `relay_status_field` | The consumer read a structured status field from a relay error event. |
| `relay_message_parse` | The consumer recovered the status by parsing relay message text. |
| `unrecognised` | The consumer supplied a source outside the vault's named vocabulary. |

`NULL` means the report predates this column or the consumer omitted the optional field;
it is normal, not invalid data. This differs from `unrecognised`, which means the consumer
sent a value that the vault refused to store.

### Reading the chain directly

The verbs above need the daemon stopped. To inspect a **running** vault — or to answer
"did that write actually commit?" from outside — read the store read-only. This takes no
lease and cannot disturb the daemon:

```sh
DB="$HOME/.local/share/cortexkit/claustrum/store.db"

# Recent events. `actor` distinguishes who caused them: `vault` is the refresh engine
# acting on its own, `route-admin` an operator through the running daemon, `offline-cli`
# an operator holding the lease directly.
#
# `conn-<N>` is NOT a consumer identity. N is the route channel number, assigned to a
# route binding and reused as bindings come and go: two rows sharing `conn-1` are not
# evidence of the same reporter, and one reporter across reconnects may appear under
# several numbers. A capability handle authorizes a read without identifying who
# presented it, so for a caller on a bare connection there is no identity to record.
#
# So for a CONSUMER-REPORTED invalidation (op `report_auth_failure`) this chain gives
# you the credential and the instant, never the reporter: correlate that timestamp
# against sources outside it, such as consumer or route-layer logs. Operator and
# vault-owned actions are attributable as usual.
#
# Note this is a property of what the vault RECORDS, not of what the route plane
# knows: a supervised consumer presents a module identity at bind time and the daemon
# stamps it -- confirmed with the main consumer, whose client attaches it on every
# route open, so real reports arrive from a named module. Do not read these rows as
# proof that the caller was unidentifiable; only that this record does not carry it.
sqlite3 "file:$DB?mode=ro" "SELECT seq, op, credential_id, actor,
  datetime(ts_ms/1000,'unixepoch','localtime') FROM audit_log ORDER BY seq DESC LIMIT 20;"

# When each credential last completed a real provider token exchange.
sqlite3 "file:$DB?mode=ro" "SELECT credential_id, MAX(datetime(ts_ms/1000,'unixepoch','localtime'))
  FROM audit_log WHERE op='refresh_commit' GROUP BY credential_id;"

# Write authority: the store's fence epoch against the daemon's lease.
sqlite3 "file:$DB?mode=ro" "SELECT epoch FROM cortexkit_fence WHERE id = 0;"
cat "$HOME/.local/share/cortexkit/claustrum"/*.lease
```

Three things that make these read wrong:

- **Use `mode=ro`, never `immutable=1`.** An immutable open tells SQLite the file cannot
  change, so it skips the write-ahead log — on a live vault that silently returns a
  pre-WAL snapshot, answering confidently about the past. `immutable=1` is for a store
  nobody is writing, such as a copy kept as a rollback target.

  **A `store.db` with no `store.db-wal` beside it is the dangerous case, and the
  danger is that it usually does NOT announce itself.** A WAL database keeps recent
  commits in the `-wal`; the main file alone holds only what was checkpointed. What
  happens when you open one depends entirely on which SQLite you are holding —
  measured here on one identical file:

  ```
  system sqlite3 (Apple 3.51.0)   Error: unable to open database file (14)
  the daemon's build (3.46.0)     opens, answers from pre-WAL state, integrity ok
  ```

  So the error-14 refusal is a property of the tool, not of the file. **Through the
  daemon's own build the same store opens without complaint and silently under-reports
  — in a probe here, a live copy taken with 50 rows committed answered as though the
  table did not exist.** It is missing data, it says nothing, and `PRAGMA
  integrity_check` returns `ok`, because the file it has is internally consistent.

  **`-wal` is the load-bearing companion; `-shm` is a rebuildable index over it.**
  Measured: `main+wal+shm` and `main+wal` both read correctly; `main+shm` and `main`
  alone both read stale.

  ```
  ls store.db-wal          # the check that matters, before opening anything
  ```

  **What a companion-less main file contains is exactly what had been CHECKPOINTED,
  and nothing else.** That is the whole rule, and every case follows from it:

  ```
  closed cleanly          everything was checkpointed      complete
  copied mid-write        nothing was checkpointed         reads as empty
  copied mid-write        a checkpoint had partly run      AN ARBITRARY PREFIX
  ```

  **The third is the dangerous one, because it is the only outcome that looks like a
  working database.** It opens, it answers, `integrity_check` says `ok`, and it is
  short by an amount nothing on the file can tell you — a probe here produced one row
  of fifty. Checkpoint timing leaves no trace in the file, so **completeness is not
  merely hard to infer from a store, it is absent from it.** The audit chain is not a
  fallback for answering this: `MAX(seq)` against what the vault should have is the
  only source that exists.

  **If you are copying a store, copy the directory, never the file.** The main file on
  its own is a partial artefact whose losses are silent.
- **`mode=ro` is also what makes the read INERT, and dropping it is not harmless just
  because the SQL is a `SELECT`.** SQLite checkpoints on close when the closing connection
  is the last one attached to the database, and that is a property of the CONNECTION, not
  of the statements run through it. Measured both ways on this platform, same database,
  same query, only the open mode differing: a read-write last closer truncated the WAL and
  removed it; a read-only last closer left it byte-for-byte intact. So a plain
  `sqlite3 store.db "SELECT ..."` against a **stopped** vault rewrites the main database
  file and deletes the WAL — an operator looking for evidence, modifying the evidence.
  Nothing is corrupted and nothing warns, which is exactly why it is worth a line here:
  the next reader sees a store whose file timestamps and WAL state were changed by the
  investigation. Against a *running* vault the daemon holds a connection, so a stray
  read-write visitor is not the last closer and this does not fire — meaning the dangerous
  case is the careful one, where the operator stopped the daemon first.
- **The table is `audit_log`, and its timestamp column is `ts_ms`.** A misspelled table
  errors, but a wrong *column* in a `WHERE` clause returns zero rows — indistinguishable
  from "nothing happened". Check the schema before believing an empty result.
- **The audit chain answers "what happened"; the fence epoch only answers "what is true
  now".** The fence row is rewritten only when a writer's epoch *exceeds* it, so an
  unchanged row is equally consistent with a rejected write and with a healthy writer that
  had nothing to claim. To ask whether a write committed, read the chain.

One honest limit: the chain is **tamper-evident, not truncation-proof**. No interior
edit, reorder or insertion survives verification without the audit key — but an
attacker with write access to the database file can delete a suffix of recent
entries, and the surviving prefix still verifies. Detecting that needs an external
monotonic anchor (periodically recording the tip `(last_seq, entry_mac)` off-box),
which is out of scope for the in-database chain.

---

## Rotating the master key

`ck auth rotate-master-key` performs a crash-safe two-slot handover: it stages a new
key, re-wraps every record and the sealed audit key under it in one atomic
transaction, then promotes the new key. A crash at any point reopens cleanly under
whichever key matches the database — the vault never bricks, including when a
previous rotation was itself interrupted (a staged-but-unpromoted rotation is healed
before a new one is staged). Offline-only: stop the daemon first.

---

## Deploying a new vault binary

The daemon and CLI are installed at `~/.local/share/cortexkit/bin/`, with `ck-auth`
also symlinked into `~/.local/bin/` for the `ck` dispatcher.

### Before building a release: the full gate

```sh
./scripts/gate.sh
```

### Building the release binaries

```sh
PROBE='<command> should print <X> against the live daemon' ./scripts/release-build.sh
```

Stamps the source revision into both binaries, signs each with its **pinned**
identifier, and prints the revision and sha256 it produced. It refuses on a dirty
tree: a stamped revision that names a commit whose contents are not what was built
is worse than no stamp, because the whole point is to be trusted during an
incident.

Artifacts land in `target/staged/<rev>/`, **not** `target/release/`. That
directory belongs to cargo, and any later `--release` command silently overwrites
what is in it — measured: an e2e run rebuilt a staged, signed daemon on top of
itself, so a published hash stopped describing the file within one command.

**A stage is safe from overwrite, NOT from `cargo clean`.** `target/staged` is
still under `target/`, and clean takes the whole tree — measured 2026-08-16 with
`cargo clean --dry-run -v`, which names the staged paths in its removal list.
The two hazards differ in severity and only the first is addressed here:

- **Overwrite** (`target/release/`) is SILENT. The artifact still exists, the
  published hash no longer describes it, and nothing errors. This is the one
  the placement fixes.
- **Deletion** (anywhere under `target/`) is LOUD. The file is gone and the
  stage is reproducible by re-running the release script at that rev.

So do not run `cargo clean` between staging and placement, and if a stage ever
needs to survive one, it has to leave `target/` entirely.

Copy the results into place with a plain `cp`. **Do not re-sign at the
destination** — a pinned identifier is not sticky, and one `codesign --force --sign
-` there reverts it to the derived form.

**The test suite cannot verify a staged artifact.** `CARGO_BIN_EXE_*` resolves
per-profile and cargo rebuilds before running, so even `cargo test --release`
spawns a binary it just built rather than the one you staged — verified by
destroying the staged file and watching all 8 e2e arms pass anyway. The suite
proves the SOURCE is good. The only checks that see the deployed bytes are the
acceptance legs below, which run after placement.

That is the gate. It runs all five suites with the right flags, asserts a minimum
count for each, and fails if any arm skipped — the three ways a green run can prove
nothing. Prefer it over composing the commands by hand, because the hand-composed
version is what drops a flag.

The individual commands are below for when you want one suite, and the paragraphs
after them explain what each guard is for.

`cargo test --workspace` is **not** the gate. It silently skips the two suites that
cover the properties a credential vault exists to guarantee — the real-daemon
end-to-end tests are `#[ignore]` by default, and the crash-safety proofs sit behind
feature flags. Run all four:

```sh
cargo test --workspace
CRED_REQUIRE_DAEMON=1 cargo test -p credentials-module --test real_daemon_e2e -- --ignored
cargo test -p credentials-core --features kill9-test-seam  --test kill9_mid_refresh
cargo test -p credentials-core --features rotate-test-seam --test rotate_crash_cut
cargo test -p credentials-core --features login-test-seam  --test login_crash_cut
```

`CRED_REQUIRE_DAEMON=1` is an anti-masking switch: without it, the end-to-end suite
is allowed to skip when it cannot build or reach the sibling `ck-subc`, which reads
as a pass. With it, an unreachable daemon is a failure.

**Setting the switch is not the same as knowing it works.** Prove it once, on any
machine where you are about to trust these runs — point `SUBCONSCIOUS_REL` in
`tests/real_daemon_e2e.rs` at a path that does not exist and run both ways:

```
guard on   thread ... panicked: the real-daemon ship-gate test must not be skipped
guard off  test result: ok. 1 passed; 0 failed                            0.00s
```

The second line is a test that never ran, reporting success. That is the state the
switch exists to prevent, and one deliberate break is what separates having a guard
from having a working one. A peer seat read four consecutive skips as four passes
with the same switch available but unset, and the guard's *existence* was what made
the runs feel accounted for.

**Duration is the corroborating tell.** These tests spawn a supervisor and a daemon,
so a real run takes seconds; a skip returns in milliseconds. Two rigs measured this
independently — 0.00s versus ~2s here, 0.06s versus 2.58s in the peer rig. If a
process-boundary suite finishes instantly, it did not spawn anything.

**The three crash-cut suites vanish without their feature flags, and say so only in
the counts.** Each is gated at file level (`#![cfg(all(unix, feature = "..."))]`), so
omitting the flag removes the whole file — there is no code left to print a warning,
and no switch can help:

```
cargo test -p credentials-core --test kill9_mid_refresh
running 0 tests
test result: ok. 0 passed; 0 failed
```

That is a passing run of nothing. **The `--features` argument in the commands above
is not optional decoration; it is what makes those lines mean anything.** CI always
passes them, so this bites a local run only — which is the run with nobody checking.
Expected counts are listed below; `0 passed` on any of them means the seam was not
compiled in.

**Read the counts, not the word `ok`.** Each of these lines is a passing run that
proved nothing:

```
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out
```

`0 passed` with a non-zero `filtered out` means the filter excluded everything —
usually a mistyped target name, or `--ignored` applied to tests that are not marked
ignored (that flag runs **only** ignored tests, so adding it to a normal suite runs
nothing). Expected counts at the time of writing: 7 end-to-end, 1 kill9, 4 rotate,
2 login. If a number drops, find out why before shipping; a suite that shrank is
indistinguishable from one that passed.

**Read the listing, not only the totals** — a test can leave the suite without the
total falling. A `#[test]` attribute binds to whatever function follows it, so
inserting a new test between an existing attribute and its function hands the
attribute to the newcomer and silently unregisters the original. Both counts stay
plausible (one test replaces another) and nothing fails. Measured here: a run
reported nine tests with one name printed twice and another absent, all green.

The cheap check is that every name appears exactly once, which the per-test lines
already show. To verify a whole target, compare the attributes against what the
runner registers:

```sh
grep -cE '^#\[(tokio::)?test(\(.*\))?\]' crates/credentials-module/tests/cli_admin.rs
cargo test -p credentials-module --test cli_admin -- --list | grep -c ': test'
```

Match the attribute pattern loosely: `#[tokio::test(flavor = "multi_thread")]` is a
test and an exact-string search for `#[tokio::test]` misses it, which reports a
mismatch in the file rather than in the search.

**Sign with a pinned identifier at build time, then place with a plain copy:**

```sh
codesign --force --sign - --identifier ck-claustrum   target/release/ck-claustrum
codesign --force --sign - --identifier ck-auth        target/release/ck-auth
```

This is not cosmetic. macOS's default ad-hoc identifier embeds the binary's
link-time UUID, so it **changes on every build** — and because macOS binds privacy
grants to that identifier and attributes them to the responsible process (the
supervisor), every unpinned release silently revokes those grants with no prompt and
no error. Pinning also makes the published hash equal the placed hash, so a plain
`shasum` comparison is a valid deployment check.

**When to cut a staging request: at the BEHAVIOURAL BOUNDARY, not on a timer.**
CLI-only commits accumulate freely — they change nothing the placer must act on.
The moment a commit touches daemon-linked source (`credentials-core/src`, or
anything under `credentials-module/src` outside `bin/`), that is the cut point and
the pair ships. Rate stays low without freshness suffering.

The failure this avoids is a rate one: three supersessions in a day trains a
reader to skip to the latest, and the next genuine *non*-supersession — "the
staged pair is still correct, do not churn your window" — stops being read.
A superseding chain only carries information while it is rare.

**Every staging request carries a reachability probe.** `release-build.sh`
refuses without one. It is the only check that proves a change is LIVE rather
than merely placed, and it cannot be derived: the placer knows which binaries
moved, and only the requester knows which behaviour to look for. "none: <reason>"
is a valid answer for a build with no observable change; silence is not.

**Acceptance, after restarting the module.** Run the ladder rather than retyping it:

```sh
scripts/accept-deploy.sh <rev> target/staged/<rev>
```

The legs below are what it runs, and the prose is why each discriminates — but
**run the script, not the commands.** These guards were all written down before
the day an inode leg was retyped by hand, took the wrong `lsof` field, and printed
a pid where an inode belonged: a plausible integer next to a real one. The written
form already said "second-to-last field", from an identical slip weeks earlier in
another repo. A script runs the form that was written after the lesson; muscle
memory runs the form you learned before it.

Each leg must be able to fail:

| check | why it discriminates |
|-------|----------------------|
| deployed hash equals the **new** build's hash, and differs from the **old** one | publish both values — comparing the system to itself passes trivially |
| `<dest> --version` reports the revision you built | the only check that asks the BINARY what it is, instead of inferring it from a path, a timestamp, or a hash you have to already hold |
| running process's image inode equals the deploy path's inode | proves the process is not still executing an unlinked predecessor |
| the open `store.db` is the one you expect (below) | every other check answers "is it healthy", not "is it the right vault" |
| `ck auth status` reports every credential serving | a daemon whose master key was unavailable at boot is alive and serving nothing |
| mint a throwaway handle, then revoke it | exercises the fenced write path and its atomic audit append |

```sh
lsof -p "$(pgrep -x ck-claustrum)" | awk '$NF ~ /store\.db$/ {print $NF}'
# /Users/<you>/.local/share/cortexkit/claustrum/store.db
```

**Ask the kernel, not the process.** This reads what the daemon actually has open
rather than what it believes it opened, so it survives a stale config, a
supervisor passing a different descriptor, and a second vault on the same host —
all cases where a self-reported path would agree with the wrong answer. The vault
never announces its store, and does not need to while this is available.

**`pgrep -x`, never `pgrep -f`, and this is not style.** `-f` matches the whole
command line, so it also matches any SHELL whose script text contains the name —
including the script running the check. Measured: inside a `bash -c` block that
mentions `ck-claustrum`, `-f` returned two pids (the daemon and the script) while
`-x` returned one. Piping that through `head -1` then hands `lsof` the wrong
process, which reports no `store.db` at all and reads as "the daemon has no vault
open". Worse than consistently wrong: it depends on the text of the script around
it, so it works until someone edits a comment.

**`pgrep` ALSO FALSE-NEGATIVES ON YOUR OWN ANCESTORS, and that direction is more
dangerous than the false positive above.** Measured 2026-08-16 on macOS: from an
agent shell whose ancestry is `bash -> sh -> ck-aft -> ck-subc(41345)`, both
`pgrep -x ck-subc` and `pgrep -f 'bin/ck-subc$'` returned EMPTY, while
`ps -o stat=,etime= -p 41345` showed the process alive, state `S`, 22h uptime.
The sibling `ck-subc-mcp` matched normally in the same call, so the discriminator
is ancestry rather than the name.

This is safe for `ck-claustrum`, which is a supervised module and never an
ancestor of an operator shell -- the acceptance script's use is sound. It is NOT
safe for checking the SUPERVISOR from an agent session, which is the natural
thing to do during an incident: the check reports the fleet's root process as
down while it is serving. That happened here, and the wrong conclusion ("the
supervisor is down, my daemon is orphaned") survived two follow-up commands
before `ps -p` contradicted it.

So: `pgrep` answers "is a process named X running" only for processes that are
not your own ancestors. **When the answer is empty and it matters, confirm with
`ps -p <pid>` against a pid from another source** -- the connection file, `lsof`,
or the module's own parent -- before concluding anything is down. An empty
`pgrep` is not evidence of absence.

Relocating the data directory is safe in the sense that matters: **the daemon
never bootstraps**, so a moved vault finds no key for its new keychain scope and
refuses to serve rather than coming up empty. That is worth knowing precisely
because the opposite — start fresh, look healthy — is the usual behaviour for a
state directory.

The last two are the ones that matter. A restarted daemon can be running, answering,
and serving nothing — so the acceptance assertion is **"N/N serving"**, never "the
process is up". And a read-only check cannot prove the vault can still write; the
mint/revoke pair can.

**What the ladder does NOT cover: whether the behaviour you shipped is reachable.**
Every leg asks whether the right bytes are in the right place. None asks whether
the CHANGE is live. Measured: a CLI fix was deployed and accepted on all legs while
its effect stayed invisible, because the logic ran inside the daemon and the daemon
half had not been placed — the new message simply did not appear. **A deployed CLI
is not a deployed behaviour** whenever the logic sits behind the route plane.
Exercise the specific change end to end, and if it does not show, check which
binary owns it before assuming the deploy failed.

A related trap when hunting for it: **which binary carries the user-visible string
is itself a design fact.** In that case the sentence lived in the CLI and the wire
field in the daemon, so grepping either binary alone for the operator-facing text
concludes the fix is absent from both.

If a hash comparison fails after someone re-signed the binary, re-sign a **copy** of
the known build with the known identifier and compare that — a legitimate re-sign and
a substituted binary are otherwise indistinguishable. `dwarfdump --uuid` (invariant
under signing) and a signature-stripped `shasum` also settle it.

**LC_UUID compares files; it cannot name a commit.** Measured 2026-08-12: the same
commit built in the main tree and in a git worktree produced two different UUIDs, so
it identifies a *(commit, path, toolchain)* triple. That is exactly what a deploy
needs — both sides are in hand — and useless in an incident, where only the running
binary is. Rebuilding candidate commits until a UUID matches does not work either,
for the same reason. Ask `--version` instead.

## A refresh-rate anomaly: ask for the denominator before building one

A credential refreshing far above its own token lifetime is the signature of a caller
whose `min_ttl_ms` demand is close to that lifetime — satisfiable, so it never trips
`ttl_unsatisfiable`, while forcing an upstream mint on nearly every get.

**The vault sees half of this and cannot see the other half.** It records refreshes and
NOT reads, so refreshes-per-read — the ratio that actually names the pathology — is not
computable here. `refresh_commit` also records `actor=vault`, so nothing names the
triggering caller.

**Do not respond by adding read recording.** That is a row per read on the hot path, and
it is the expensive fix that will look necessary in the moment. Ask the consumer
instead: a consumer that exports anything per admission already keeps the denominator
durably, for its own reasons, and can answer per-credential in one query.

Worked example, measured 2026-08-26 on the two credentials this vault shares with broca:

```
oauth:anthropic    3 refreshes/24h    35.1 reads/day    ratio 0.09
oauth:xai          4 refreshes/24h    55.4 reads/day    ratio 0.07
```

A tight demand drives that ratio toward 1.0. Both are an order of magnitude below it.

Two caveats that came with the numbers and matter for reading them later:

- **Take the ratio as of today, not the raw rates.** Consumer volume moves with fleet
  activity, so a stale denominator makes a healthy credential look sick.
- **This only works for consumers that keep a durable per-admission record.** It holds
  for broca because billing forces it. A consumer that reads credentials without
  exporting anything has no denominator to offer, and for those the anomaly stays
  detectable-but-unattributable.
