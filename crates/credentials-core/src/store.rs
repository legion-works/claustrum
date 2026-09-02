//! The encrypted credential store: durable custody of [`VaultRecord`]s, each
//! sealed value-level and written through the epoch-fenced path.
//!
//! This layer owns persistence and the at-rest crypto wiring; it does NOT own the
//! wire surfaces, the audit chain, or the refresh state machine (those live above
//! it). Every durable mutation goes through `cortexkit-store`'s `with_conn_fenced`
//! so a superseded writer (an old instance still draining after a lease handover)
//! is rejected at the database layer rather than silently clobbering a fresh write.
//!
//! ## Row layout
//!
//! One row per credential in the `credentials` table:
//! - `credential_id` (PK) — the stable id (e.g. `opencode:anthropic`).
//! - `record_version` (plaintext) — monotonic, bumped every write. Mirrored from
//!   the encrypted body and bound into the cipher AAD, so the column and the
//!   ciphertext always move together in one fenced transaction.
//! - `key_id` (plaintext hex) — which master key sealed this row, so a rotation
//!   scan finds old-key rows without decrypting them.
//! - `state` (plaintext) — `active` | `needs_reauth` | `retired` | `corrupt`. A row
//!   that fails to decrypt is quarantined here (per-record), never panics, and never takes
//!   down the rest of the vault.
//! - `stale_pending` (plaintext) — a consumer-reported refusal that forces the next
//!   refreshable read to exchange the token before serving it; it is not provider TTL.
//! - `envelope` (BLOB) — the sealed record (the only place plaintext fields live,
//!   and only in encrypted form).
//! - `updated_at_ms` — last-write wall clock (diagnostics only).
//! - `last_github_app_permissions` (plaintext) — the most recent canonical GitHub App
//!   installation grant. It is diagnostic metadata, not a token claim, and is only
//!   updated after a successful GitHub App mint.
//!
//! ## Fail-closed, never-panic
//!
//! A decrypt/parse failure on read marks that single id `corrupt` and returns a
//! typed [`StoreOpError`]; the vault keeps serving every other credential. This is
//! the per-record quarantine the availability contract requires (NOT a whole-DB
//! reset — auto-wiping on perceived corruption is itself a data-loss/DoS vector).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};

use cortexkit_store::{Migration, SqliteStore, StoreError};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::{
    self, AlarmReason, AuditCtx, AuditEntry, AuditOp, AuditRecord, AuthEventKind, ReporterSource,
};
use crate::envelope::{self, EnvelopeError, RecordBinding};
use crate::key::{KeyId, MasterKey};
pub use crate::record::RecordState;
use crate::record::{CredentialKind, VaultRecord};

/// The schema namespace for the credential vault's migrations (independent of any
/// other domain chain in the same database).
const SCHEMA_NAMESPACE: &str = "credentials";

/// The vault schema. The fence table is created lazily by `with_conn_fenced` on
/// the first fenced write and is not declared here.
///
/// `refresh_intent` is the durable crash-safety log for OAuth refresh: a row is
/// fsynced BEFORE the provider's rotating refresh endpoint is called, and cleared
/// in the same transaction that commits the new tokens. A row that survives a
/// restart means a refresh was interrupted between the provider call and the
/// commit (its outcome is INDETERMINATE — the provider may have rotated), which
/// startup reconciliation resolves fail-safe. At most one intent per credential
/// (the id is the primary key), matching the engine's single-flight.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        statements: "CREATE TABLE credentials (\
                         credential_id   TEXT PRIMARY KEY, \
                         record_version  INTEGER NOT NULL, \
                         key_id          TEXT NOT NULL, \
                         state           TEXT NOT NULL, \
                         envelope        BLOB NOT NULL, \
                         updated_at_ms   INTEGER NOT NULL\
                     ); \
                     CREATE TABLE refresh_intent (\
                         credential_id    TEXT PRIMARY KEY, \
                         record_version   INTEGER NOT NULL, \
                         old_refresh_hash TEXT NOT NULL, \
                         lease_epoch      INTEGER NOT NULL, \
                         started_at_ms    INTEGER NOT NULL\
                     );",
    },
    // Capability handles + the tamper-evident audit chain.
    //
    // `handles`: a credential is read by an unguessable 256-bit capability handle,
    // not its public alias. Only the handle's SHA-256 HASH is stored (the raw handle
    // is returned once at mint and written into the consumer's 0600 config), so a
    // database leak yields no usable handle — just which credential_ids exist and
    // how many handles each has (metadata, never a secret), which is why these are
    // plaintext columns while credential payloads stay value-encrypted. Handles are
    // per-credential revocable (revoke one, or all for a credential, and mint a fresh
    // one without re-login).
    //
    // `audit_log`: an append-only, HMAC-chained record of EVERY durable mutation
    // (admin writes, refresh commits, revocations), so every credential version is
    // accounted for and an unexplained version bump is a detectable chain gap. Each
    // entry's `entry_mac` is HMAC(audit_key, prev_mac || fields), keyed by a
    // master-key-derived audit key, so the log cannot be forged or repaired without
    // the master key. `alarm` flags a detected anomaly (overwrite-without-CAS,
    // fetch-rate anomaly, admin write) as a durable, queryable row rather than a live
    // notification.
    // `handles.created_at_ms` is WRITTEN AND NEVER READ, deliberately. The audit chain
    // already answers when a handle was minted -- a `mint_handle` entry carries the
    // same instant, written in the same transaction -- so this column is a
    // denormalized copy kept for forensic queries against the table alone, where
    // joining the chain for a timestamp would be the awkward path.
    //
    // Recorded here because a column with no reader is indistinguishable from an
    // abandoned one: a later cleanup would see an unread field and drop it, taking
    // the ability to date a handle from its own row along with it, and dropping a
    // column is not something a test would catch.
    Migration {
        version: 2,
        statements: "CREATE TABLE handles (\
                         handle_hash    TEXT PRIMARY KEY, \
                         credential_id  TEXT NOT NULL, \
                         created_at_ms  INTEGER NOT NULL, \
                         revoked        INTEGER NOT NULL DEFAULT 0\
                     ); \
                     CREATE INDEX idx_handles_credential ON handles(credential_id); \
                     CREATE TABLE audit_log (\
                         seq            INTEGER PRIMARY KEY AUTOINCREMENT, \
                         ts_ms          INTEGER NOT NULL, \
                         op             TEXT NOT NULL, \
                         credential_id  TEXT, \
                         payload_hash   TEXT, \
                         actor          TEXT NOT NULL, \
                         alarm          INTEGER NOT NULL DEFAULT 0, \
                         alarm_reason   TEXT, \
                         prev_mac       TEXT NOT NULL, \
                         entry_mac      TEXT NOT NULL\
                     ); \
                     CREATE TABLE vault_secrets (\
                         name      TEXT PRIMARY KEY, \
                         key_id    TEXT NOT NULL, \
                         envelope  BLOB NOT NULL\
                     );",
    },
    // `auth_events`: why a credential stopped working, which the audit chain cannot say.
    //
    // The chain records mutations, and that is the wrong shape for this question in two
    // specific ways, both measured after an incident where two OAuth credentials were
    // marked `needs_reauth` and nothing on disk could say why:
    //
    //   - It records only what CHANGED. A consumer's report naming a superseded
    //     `record_version` is a deliberate no-op, so it writes nothing at all -- the
    //     case where a consumer is reporting against stale state is exactly the one
    //     that leaves no trace. Likewise a refresh that fails transiently clears its
    //     intent and returns; nothing durable says the provider was ever called.
    //   - It has no field for the DETAIL. `provider_status` arrives on every report and
    //     is discarded, though 401 (token rejected) and 403 (request forbidden) point
    //     at different causes and different fixes.
    //
    // A field could not simply be added to `audit_log`: the entry MAC covers a fixed
    // field list, so a new column in the transcript changes the MAC of every historical
    // entry and breaks verification of the whole chain. Reusing `alarm_reason` fails
    // differently -- `alarm` is derived as `alarm_reason.is_some()`, so recording a
    // routine 401 there would raise an operator alarm for normal provider behaviour.
    //
    // Hence a separate table, deliberately NOT chained. These rows are diagnostics, not
    // evidence: they are not MAC-protected, they may be pruned, and nothing should
    // depend on them being complete. The chain remains the authority for what happened;
    // this only explains it.
    //
    // `detail` carries a TYPED VARIANT NAME and never provider body text. Adapters put
    // raw response bodies into their error values, and an OAuth error body can echo
    // submitted parameters -- so persisting one risks writing token material into a
    // plaintext column, which is the one thing this table must never do.
    Migration {
        version: 3,
        statements: "CREATE TABLE auth_events (\
                         seq             INTEGER PRIMARY KEY AUTOINCREMENT, \
                         ts_ms           INTEGER NOT NULL, \
                         credential_id   TEXT NOT NULL, \
                         kind            TEXT NOT NULL, \
                         provider_status INTEGER, \
                         detail          TEXT, \
                         record_version  INTEGER, \
                         applied         INTEGER NOT NULL DEFAULT 0\
                     ); \
                     CREATE INDEX idx_auth_events_credential ON auth_events(credential_id);",
    },
    // Principal-scoped read refusals must name the caller for the operator while the
    // wire remains uniformly `not_found`. These nullable columns preserve the older
    // non-principal auth-event rows and their existing diagnostics.
    Migration {
        version: 4,
        statements: "CREATE TABLE read_grants (\
                         principal_kind    TEXT NOT NULL, \
                         principal_id      TEXT NOT NULL, \
                         credential_prefix TEXT NOT NULL, \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, credential_prefix)\
                     ); \
                     ALTER TABLE auth_events ADD COLUMN principal_kind TEXT; \
                     ALTER TABLE auth_events ADD COLUMN principal_id TEXT;",
    },
    // A consumer can prove that the access token it received was refused, but cannot
    // prove that the durable refresh grant is dead. Keep that local assertion outside
    // the sealed provider facts so it can force the next read to refresh without
    // rewriting the envelope or moving its version fence.
    Migration {
        version: 5,
        statements: "ALTER TABLE credentials ADD COLUMN stale_pending INTEGER NOT NULL DEFAULT 0;",
    },
    // Grants are operation-scoped. Rebuild the table so one principal/prefix can hold
    // independent read and sign authorities, then visibly classify every legacy row as
    // read rather than silently relying on a default that could widen an old grant.
    Migration {
        version: 6,
        statements: "CREATE TABLE read_grants_v6 (\
                         principal_kind    TEXT NOT NULL, \
                         principal_id      TEXT NOT NULL, \
                         credential_prefix TEXT NOT NULL, \
                         operation         TEXT NOT NULL CHECK(operation IN ('read', 'sign')), \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, credential_prefix, operation)\
                     ); \
                     INSERT INTO read_grants_v6 \
                         (principal_kind, principal_id, credential_prefix, operation, created_at_ms) \
                     SELECT principal_kind, principal_id, credential_prefix, 'read', created_at_ms \
                     FROM read_grants; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v6 RENAME TO read_grants;",
    },
    // GitHub installation-token permissions are non-secret diagnostic metadata. Keep
    // only the latest observation on the credential row so repeated mints cannot grow
    // a table, while leaving historical audit-log MAC transcripts untouched.
    Migration {
        version: 7,
        statements: "ALTER TABLE credentials ADD COLUMN last_github_app_permissions TEXT;",
    },
    Migration {
        version: 8,
        statements: "ALTER TABLE auth_events ADD COLUMN reporter_source TEXT;",
    },
];

/// The newest store migration THIS BINARY knows how to apply.
///
/// Published so the module manifest can declare `store_schema_version` as a derived
/// fact. The number is not an implementation detail: it is a COMPATIBILITY MARKER,
/// monotone by construction, and the supervisor contract already treats it as a
/// fleet-visible value that modules are asked to state.
///
/// DERIVED FROM THE LIST, NEVER HAND-TYPED. A literal here would decay exactly the way
/// every other written-down count in this repo has: the issue asking for this accessor
/// cited 6 while the list already held 7, and the manifest comment beside the field
/// said 6 as well. Both were true when written. Deriving makes the drift impossible
/// rather than merely discouraged.
///
/// WHAT DECLARING IT BUYS, precisely, because it is easy to overstate: `run_migrations`
/// SKIPS every migration at or below the store's current version and returns `Ok`, so a
/// binary older than the store it opens proceeds silently -- there is no store-level
/// refusal to back this up. Declaring the number does not add one. It makes the
/// mismatch VISIBLE to a supervisor that compares declared against actual, which is the
/// right granularity: refusing outright would break binary rollback, and rollback is a
/// property this project deliberately preserves at every deploy.
pub const fn newest_migration_version() -> u32 {
    let mut newest = 0;
    let mut i = 0;
    while i < MIGRATIONS.len() {
        if MIGRATIONS[i].version > newest {
            newest = MIGRATIONS[i].version;
        }
        i += 1;
    }
    newest
}

/// The `vault_secrets` row name for the audit-chain HMAC key. The audit key is a
/// CSPRNG secret created once and SEALED under the master key (so the audit log is
/// unforgeable without the master key), re-sealed on master-key rotation but never
/// regenerated — keeping one continuously-verifiable chain across rotations. Its
/// envelope uses this fixed pseudo-id and version 0 as the AAD binding.
pub const AUDIT_KEY_SECRET_NAME: &str = "__vault_audit_key__";
const AUDIT_KEY_RECORD_VERSION: u64 = 0;

/// The non-secret metadata of a stored record, readable WITHOUT decrypting (the
/// plaintext columns). Used by rotation scans, status, and CAS pre-checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMeta {
    /// The stored record's monotonic version.
    pub record_version: u64,
    /// Hex fingerprint of the master key this row is sealed under.
    pub key_id_hex: String,
    /// The row's lifecycle state.
    pub state: RecordState,
    /// A consumer reported the current access token as refused, so the next read must
    /// refresh before serving it. This local assertion is not a provider expiry fact.
    pub stale_pending: bool,
}

/// The operation a principal-scoped credential-prefix grant permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantOperation {
    Read,
    Sign,
}

impl GrantOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Sign => "sign",
        }
    }
}

impl std::str::FromStr for GrantOperation {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "read" => Ok(Self::Read),
            "sign" => Ok(Self::Sign),
            _ => Err(format!(
                "unknown grant operation '{value}' (expected read or sign)"
            )),
        }
    }
}

/// One durable principal-scoped credential-prefix grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadGrant {
    pub principal_kind: String,
    pub principal_id: String,
    pub credential_prefix: String,
    pub operation: GrantOperation,
    pub created_at_ms: i64,
}

/// A durable refresh-intent row: the fsynced marker that a refresh is in flight
/// for a credential, written before the provider's rotating endpoint is called and
/// cleared in the same transaction that commits the new tokens. A row that
/// survives a restart marks an INDETERMINATE refresh (the provider may or may not
/// have rotated) that startup reconciliation resolves fail-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshIntent {
    /// The credential being refreshed.
    pub credential_id: String,
    /// The record version the refresh started FROM (the commit's CAS guard).
    pub record_version: u64,
    /// Hash of the refresh token about to be rotated (see [`refresh_token_hash`]).
    /// Reconciliation cross-checks it against the stored record's refresh token so
    /// a legitimate re-login (which clears the intent) is told apart from a rogue
    /// write that left a stale intent.
    pub old_refresh_hash: String,
    /// The store epoch that opened the intent. AUDIT-ONLY: recorded so the audit
    /// log can label a dangling intent as crash-vs-handover, but it is NEVER an
    /// input to the reconciliation resolution (kill-9 and lease-handover must
    /// resolve identically — the convergence property).
    pub lease_epoch: u64,
    /// When the intent was opened (Unix ms). Staleness / audit.
    pub started_at_ms: i64,
}

/// Domain-separated hash of a refresh token, stored in the intent so reconciliation
/// can compare it to the record's current refresh token WITHOUT either being a
/// reversible store of the secret. Hex SHA-256 over a domain label + the token.
pub fn refresh_token_hash(refresh_token: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"cortexkit-credentials/refresh-token-hash/v1");
    h.update(refresh_token.as_bytes());
    let digest = h.finalize();
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A store operation failure. Distinct, typed, fail-closed — never a panic.
#[derive(Debug)]
pub enum StoreOpError {
    /// The credential id does not exist.
    NotFound,
    /// A create was attempted for an id that already exists (create-only default).
    AlreadyExists,
    /// A CAS overwrite's `expected_payload_hash` did not match the current record.
    CasMismatch,
    /// The record is quarantined (`corrupt`) and cannot be served.
    Quarantined,
    /// The record is `needs_reauth` and must not be served until re-authenticated.
    NeedsReauth,
    /// The cipher envelope failed to decode/decrypt. The id has been quarantined.
    Decrypt(EnvelopeError),
    /// The decrypted body failed to parse as a record. The id has been quarantined.
    Corrupt(String),
    /// A fenced write was rejected because a newer writer holds the database (the
    /// lease-handover race). The write was NOT applied.
    Fenced { holder_epoch: u64, db_epoch: u64 },
    /// A serialization failure building the record body.
    Encode(String),
    /// The vault's sealed audit key is missing on a non-empty vault — a genuinely
    /// corrupt state (it is created once at init and never deleted). Fail-closed:
    /// the audit chain cannot be verified, so the vault refuses to open rather than
    /// silently regenerating the key (which would make all existing entries
    /// unverifiable).
    CorruptVault(String),
    /// An underlying storage/backend error.
    Store(String),
}

impl std::fmt::Display for StoreOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreOpError::NotFound => f.write_str("credential not found"),
            StoreOpError::AlreadyExists => {
                f.write_str("credential already exists (create-only; use a CAS overwrite)")
            }
            StoreOpError::CasMismatch => {
                f.write_str("compare-and-set failed: expected payload hash did not match")
            }
            StoreOpError::Quarantined => f.write_str("credential is quarantined (corrupt)"),
            StoreOpError::NeedsReauth => f.write_str("credential needs re-authentication"),
            StoreOpError::Decrypt(e) => write!(f, "envelope decrypt failed: {e}"),
            StoreOpError::Corrupt(m) => write!(f, "record body corrupt: {m}"),
            StoreOpError::Fenced {
                holder_epoch,
                db_epoch,
            } => write!(
                f,
                "fenced write rejected: holder epoch {holder_epoch} < database epoch {db_epoch}"
            ),
            StoreOpError::Encode(m) => write!(f, "record encode failed: {m}"),
            StoreOpError::CorruptVault(m) => write!(f, "vault corrupt: {m}"),
            StoreOpError::Store(m) => write!(f, "storage error: {m}"),
        }
    }
}

impl std::error::Error for StoreOpError {}

impl From<StoreError> for StoreOpError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Fenced {
                holder_epoch,
                db_epoch,
            } => StoreOpError::Fenced {
                holder_epoch,
                db_epoch,
            },
            other => StoreOpError::Store(other.to_string()),
        }
    }
}

fn normalize_and_validate_record_identity(
    mut record: VaultRecord,
) -> Result<VaultRecord, StoreOpError> {
    let identity = record.identity.clone();
    record = record.with_identity(identity);
    record.identity.validate().map_err(StoreOpError::Encode)?;
    Ok(record)
}

/// SHA-256 of a record's opaque payload — the value an overwrite CAS compares
/// against. Computed over the payload bytes only (not the whole record), so a
/// caller can prove "I am overwriting the payload I last saw" without holding the
/// rest of the record.
pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(payload);
    h.finalize().into()
}

/// The encrypted credential store over a lease-guarded sqlite database.
///
/// Holds the master key (in its zeroizing newtype) for the store's lifetime so
/// every read/write can seal/open records. The underlying [`SqliteStore`] holds
/// the single-writer lease and carries the fence epoch.
pub struct EncryptedStore {
    store: SqliteStore,
    key: MasterKey,
    key_id: KeyId,
    // The audit-chain HMAC key, held in a zeroizing buffer so it is scrubbed from memory
    // on drop rather than lingering for the process lifetime like a plain `[u8; 32]`.
    // Each per-op copy is also a `Zeroizing` clone (scrubbed when the op returns), so the
    // key material never sits in an un-zeroized local either. Deref-coerces to `&[u8; 32]`
    // at the HMAC call sites, so the callees are unchanged.
    audit_key: Zeroizing<[u8; 32]>,
    // Latched true the first time a fenced write is rejected because a newer writer
    // took the lease. This is PERMANENT for a store instance by construction: the
    // fence epoch only ever rises, so a superseded writer can never win a later
    // fenced write. It gives the health probe a precise "fenced out by a newer
    // writer" signal that an unfenced read scan cannot detect on its own (a
    // superseded daemon still reads its stale rows fine — it has only lost WRITE
    // authority), distinguishing "find the other writer" from a generic read error.
    //
    // THE PERMANENCE IS INHERITED, NOT LOCAL. Nothing here keeps the latch set; it
    // stays set only because the lease epoch underneath it is monotonic and never
    // reused or reset. If `cortexkit-lease` ever permitted an epoch to be reused, a
    // superseded writer could win a later fenced write, this latch would be
    // clearable, and two writers would hold the same store without either observing
    // the other. Epoch monotonicity is therefore load-bearing for write custody here
    // and is not enforced by this crate, so it must be preserved by any change to
    // the lease — which will not be apparent from that crate's own tests.
    //
    // AND NOTHING ON THIS SIDE WOULD CATCH IT EITHER, which is the part worth
    // stating rather than leaving as an exercise. The latch's own test rolls the
    // epoch BACK by hand to make a later write succeed — i.e. it simulates the very
    // reuse this comment forbids, precisely to prove the latch does not clear. So it
    // asserts the local property while deliberately violating the inherited one, and
    // cannot detect its loss.
    //
    // NOR DOES THE E2E, checked rather than assumed: the real-daemon suite proves
    // MUTUAL EXCLUSION (the offline CLI is refused, exit 3, while the daemon holds
    // the lease) and never reads the epoch, so a reused epoch would still exclude
    // correctly and pass. Verifying monotonicity means observing the value rise
    // across a real handover, and nothing in either crate does that today.
    //
    // Stated because a limitation named in prose reads as one that was handled. It
    // was not: this is a dependency on another crate's invariant with no automated
    // test on either side of the boundary. What exists is operational: the runbook's
    // deploy acceptance reads the fence epoch across a restart, so a reused epoch
    // would show up as a value that failed to rise — caught by a human comparing two
    // numbers, if they compare them.
    fenced_out: AtomicBool,
}

impl EncryptedStore {
    /// Wrap an already-open, migrated [`SqliteStore`] with a master key, loading (or
    /// creating, on a brand-new vault) the sealed audit-chain key.
    ///
    /// The audit key is a CSPRNG secret created ONCE — when the vault is brand-new
    /// (no credentials, no audit entries, no existing audit_key row) — and SEALED
    /// under the master key. On every later open it is LOADED and decrypted; a wrong
    /// master key fails that decrypt the same way it fails a record decrypt
    /// (fail-closed, not a panic). It is NEVER regenerated for an existing vault: a
    /// missing audit_key row on a non-empty vault is [`StoreOpError::CorruptVault`]
    /// (regenerating would silently make every existing audit entry unverifiable).
    /// The store must have had [`EncryptedStore::migrate`] applied first.
    pub fn open(store: SqliteStore, key: MasterKey) -> Result<Self, StoreOpError> {
        let key_id = key.key_id();
        let audit_key = load_or_create_audit_key(&store, &key)?;
        Ok(EncryptedStore {
            store,
            key,
            key_id,
            audit_key,
            fenced_out: AtomicBool::new(false),
        })
    }

    /// Whether a fenced write has ever been rejected on this store instance because
    /// a newer writer holds the lease. Once true it stays true (the fence epoch only
    /// rises). The health probe reads it to report a precise fenced-out state.
    pub fn is_fenced_out(&self) -> bool {
        self.fenced_out.load(Ordering::Relaxed)
    }

    /// Run a fenced write, latching [`Self::is_fenced_out`] if it is rejected by a
    /// newer lease holder. The single choke point every durable mutation routes
    /// through, so the fenced-out signal is set exactly once, at the source, rather
    /// than at each call site. Returns `Result<_, StoreError>` exactly like the
    /// underlying `with_conn_fenced`, so it is a drop-in at every call site (the
    /// existing `?`/`map_err` error tails are unchanged).
    ///
    /// THE LATCH IS ONE-WAY ON PURPOSE, AND NOTHING CLEARS IT SHORT OF A RESTART.
    /// That is normally the signature of a broken gauge — a status that cannot return
    /// to ok is a boot-scoped incident log rather than a health signal, and every
    /// other field of [`crate::health::VaultHealth`] is recomputed from a fresh scan
    /// for exactly that reason. This one is different because THE CONDITION ITSELF
    /// IS IRREVERSIBLE: losing the epoch fence means another writer holds the lease,
    /// and this process cannot take it back. A later write appearing to succeed would
    /// mean the OTHER holder had gone, not that this instance regained authority.
    /// Clearing the latch on such a write would resume serving as the authority on
    /// the strength of a race.
    /// So the honest recovery sequence is: this process exits, and a new one acquires
    /// the lease from scratch. Fail-closed until then. Do not "fix" this by clearing
    /// the flag on a subsequent successful write.
    fn fenced_write<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction) -> rusqlite::Result<T>,
    ) -> Result<T, StoreError> {
        let out = self.store.with_conn_fenced(f);
        if matches!(out, Err(StoreError::Fenced { .. })) {
            self.fenced_out.store(true, Ordering::Relaxed);
        }
        out
    }

    /// Apply the vault schema migrations to a freshly opened store and set the
    /// vault's durability level. Idempotent. Call once, right after opening, before
    /// any credential write.
    ///
    /// Sets `PRAGMA synchronous=FULL` on the store's connection: the vault's SQLite
    /// IS its own source of truth, so it must fsync every commit.
    ///
    /// The consequence rather than the adjective, because a severity word travels
    /// unchecked while an observable does not: a provider that ROTATES its refresh token
    /// hands back a new one and kills the old in the same exchange. If the commit
    /// recording the new token is lost to power failure, the vault holds a token the
    /// provider has already retired and there is no second copy anywhere -- the
    /// credential is dead until an operator re-authenticates it interactively. This is stronger than WAL's default
    /// `synchronous=NORMAL` (which can lose the last transaction on power loss) and
    /// is set vault-locally rather than in `cortexkit-store`, because the other
    /// consumers hold rebuildable projections that are correct at NORMAL and should
    /// not pay FULL's fsync-per-commit. `SqliteStore` is one connection behind a
    /// mutex, so setting it once here covers every later `with_conn`/
    /// `with_conn_fenced` call.
    /// Read the database's recorded master-key fingerprint WITHOUT the master key:
    /// the plaintext `key_id` of the sealed audit-key row (which always exists from
    /// vault-init). This is the crash-safe-resolve anchor — the resolver compares it
    /// to each key-store slot's fingerprint to pick the slot the database is actually
    /// sealed under (see [`resolver::resolve_for_db`]). `None` on a brand-new vault
    /// whose audit-key row does not exist yet (then `Current` is the only candidate).
    pub fn read_db_key_id(store: &SqliteStore) -> Result<Option<KeyId>, StoreError> {
        let hex: Option<String> = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT key_id FROM vault_secrets WHERE name = ?1",
                    rusqlite::params![AUDIT_KEY_SECRET_NAME],
                    |r| r.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        // Distinguish "no row" (a brand-new vault, resolve against `Current`) from "row
        // present but its fingerprint is unparseable" (a corrupt anchor). The old code
        // collapsed both to `None`, which would silently downgrade a corrupt anchor into
        // the bootstrap path and could open a mismatched key. A present-but-invalid
        // fingerprint fails closed as a corrupt store instead.
        match hex {
            None => Ok(None),
            Some(h) => KeyId::from_hex(&h).map(Some).ok_or_else(|| {
                StoreError::Backend(format!(
                    "vault_secrets audit-key row has an invalid key_id fingerprint '{h}' \
                     (corrupt anchor)"
                ))
            }),
        }
    }

    pub fn migrate(store: &SqliteStore) -> Result<(), StoreError> {
        store.migrate(SCHEMA_NAMESPACE, MIGRATIONS)?;
        store
            .with_conn(|c| c.pragma_update(None, "synchronous", "FULL"))
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    /// The fingerprint of the master key this store seals under.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Run a closure against the raw underlying connection. Test-only: the
    /// conformance tests set up lease-handover (a fence-epoch bump) and inspect raw
    /// rows that the public API deliberately does not expose. Not part of the
    /// production surface.
    #[cfg(test)]
    pub(crate) fn with_raw_conn<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StoreOpError> {
        self.store.with_conn(f).map_err(StoreOpError::from)
    }

    /// Read non-secret metadata for an id WITHOUT decrypting (plaintext columns).
    pub fn meta(&self, credential_id: &str) -> Result<RecordMeta, StoreOpError> {
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT record_version, key_id, state, stale_pending FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |row| {
                        let version: i64 = row.get(0)?;
                        let key_id_hex: String = row.get(1)?;
                        let state: String = row.get(2)?;
                        let stale_pending: i64 = row.get(3)?;
                        Ok((version, key_id_hex, state, stale_pending))
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?
            .map(|(version, key_id_hex, state, stale_pending)| RecordMeta {
                record_version: version as u64,
                key_id_hex,
                state: RecordState::from_str(&state),
                stale_pending: stale_pending != 0,
            })
            .ok_or(StoreOpError::NotFound)
    }

    /// List every record's id + non-secret metadata, WITHOUT decrypting. Used by
    /// rotation scans and status.
    pub fn list_meta(&self) -> Result<Vec<(String, RecordMeta)>, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(
                    "SELECT credential_id, record_version, key_id, state, stale_pending FROM credentials \
                     ORDER BY credential_id",
                )?;
                let rows = stmt.query_map([], |row| {
                    let id: String = row.get(0)?;
                    let version: i64 = row.get(1)?;
                    let key_id_hex: String = row.get(2)?;
                    let state: String = row.get(3)?;
                    let stale_pending: i64 = row.get(4)?;
                    Ok((
                        id,
                        RecordMeta {
                            record_version: version as u64,
                            key_id_hex,
                            state: RecordState::from_str(&state),
                            stale_pending: stale_pending != 0,
                        },
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(StoreOpError::from)
    }

    // ---- principal-scoped operation grants ------------------------------

    /// Create one reserved-principal operation grant and append its audit transition
    /// in the same fenced transaction. A duplicate names an existing authority and is
    /// refused rather than silently accepted as a fresh reviewable change.
    pub fn create_read_grant_audited(
        &self,
        principal_kind: &str,
        principal_id: &str,
        credential_prefix: &str,
        operation: GrantOperation,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        if principal_kind != "reserved" || principal_id.is_empty() || credential_prefix.is_empty() {
            return Err(StoreOpError::Encode(
                "grants require a reserved principal and non-empty prefix".into(),
            ));
        }
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        // The HMAC transcript has no grant-specific columns (adding one would break
        // verification of historical entries), so preserve the full authority target
        // in its existing non-secret target field.
        let audit_target = format!(
            "grant:{}:{principal_kind}:{principal_id}:{credential_prefix}",
            operation.as_str()
        );
        let changed = self.fenced_write(|tx| {
            let changed = tx.execute(
                "INSERT INTO read_grants \
                 (principal_kind, principal_id, credential_prefix, operation, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
                rusqlite::params![
                    principal_kind,
                    principal_id,
                    credential_prefix,
                    operation.as_str(),
                    now
                ],
            )?;
            if changed > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(audit_target.clone()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(changed)
        })?;
        if changed == 0 {
            return Err(StoreOpError::AlreadyExists);
        }
        Ok(())
    }

    /// Revoke one reserved-principal operation grant and append the revocation in the
    /// same fenced transaction. An absent row is not a transition, so it is refused rather
    /// than producing an audit entry that claims access changed when it did not.
    pub fn revoke_read_grant_audited(
        &self,
        principal_kind: &str,
        principal_id: &str,
        credential_prefix: &str,
        operation: GrantOperation,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        if principal_kind != "reserved" || principal_id.is_empty() || credential_prefix.is_empty() {
            return Err(StoreOpError::Encode(
                "grants require a reserved principal and non-empty prefix".into(),
            ));
        }
        let audit_key = self.audit_key.clone();
        // See creation: the historical HMAC transcript cannot gain grant columns, so
        // this stable target string makes a later revocation attributable.
        let audit_target = format!(
            "grant:{}:{principal_kind}:{principal_id}:{credential_prefix}",
            operation.as_str()
        );
        let changed = self.fenced_write(|tx| {
            let changed = tx.execute(
                "DELETE FROM read_grants \
                 WHERE principal_kind = ?1 AND principal_id = ?2 \
                   AND credential_prefix = ?3 AND operation = ?4",
                rusqlite::params![
                    principal_kind,
                    principal_id,
                    credential_prefix,
                    operation.as_str()
                ],
            )?;
            if changed > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(audit_target.clone()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(changed)
        })?;
        if changed == 0 {
            return Err(StoreOpError::NotFound);
        }
        Ok(())
    }

    /// Whether an operation-specific literal credential-id prefix grant covers this
    /// request. Prefixes are compared in Rust rather than SQL `LIKE`, whose `%` and `_`
    /// metacharacters would silently widen a grant stored as ordinary text.
    pub fn read_grant_covers(
        &self,
        principal_kind: &str,
        principal_id: &str,
        credential_id: &str,
        operation: GrantOperation,
    ) -> Result<bool, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(
                    "SELECT credential_prefix FROM read_grants \
                     WHERE principal_kind = ?1 AND principal_id = ?2 AND operation = ?3",
                )?;
                let mut prefixes = stmt.query_map(
                    rusqlite::params![principal_kind, principal_id, operation.as_str()],
                    |row| row.get::<_, String>(0),
                )?;
                prefixes.try_fold(false, |covered, prefix| {
                    Ok(covered || credential_id.starts_with(&prefix?))
                })
            })
            .map_err(StoreOpError::from)
    }

    /// List every grant in deterministic principal/prefix/operation order for admin status.
    pub fn list_read_grants(&self) -> Result<Vec<ReadGrant>, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(
                    "SELECT principal_kind, principal_id, credential_prefix, operation, created_at_ms \
                     FROM read_grants \
                     ORDER BY principal_kind, principal_id, credential_prefix, operation",
                )?;
                let rows = stmt.query_map([], |row| {
                    let operation = row.get::<_, String>(3)?.parse().map_err(|message: String| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, message)),
                        )
                    })?;
                    Ok(ReadGrant {
                        principal_kind: row.get(0)?,
                        principal_id: row.get(1)?,
                        credential_prefix: row.get(2)?,
                        operation,
                        created_at_ms: row.get(4)?,
                    })
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(StoreOpError::from)
    }

    /// Create a record (CREATE-ONLY) with an explicit audit context: fails
    /// [`StoreOpError::AlreadyExists`] if the id is already present. The record is
    /// sealed at `record_version = 1`, the row is written through the epoch-fenced
    /// path, any dangling refresh intent is cleared, AND an audit entry is appended
    /// — all in ONE transaction, so the mutation and its audit record commit
    /// atomically (the audit chain accounts for the new version, tamper-evidently).
    pub fn create_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let mut record = normalize_and_validate_record_identity(record.clone())?;
        record.record_version = 1;
        let blob = self.seal_record(credential_id, &record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&payload_hash(&record.payload));

        // Create-only via INSERT ... ON CONFLICT DO NOTHING inside the fenced
        // transaction: an existing id leaves zero rows changed (atomic, no separate
        // existence query, no error-string matching). Zero changed => AlreadyExists.
        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                "INSERT INTO credentials \
                 (credential_id, record_version, key_id, state, envelope, updated_at_ms) \
                 VALUES (?1, ?2, ?3, 'active', ?4, ?5) \
                 ON CONFLICT(credential_id) DO NOTHING",
                rusqlite::params![
                    credential_id,
                    record.record_version as i64,
                    key_id_hex,
                    blob,
                    now
                ],
            )?;
            // An admin write clears any dangling refresh intent for this id in the
            // SAME transaction: a fresh credential must never inherit a stale intent
            // from a prior id reuse (and on overwrite this is what stops a boot
            // reconciliation from undoing a legitimate re-login).
            //
            // THIS TAIL REPEATS IN THE REPLACE AND OVERWRITE PATHS AND IS NOT WORTH
            // EXTRACTING. A duplicate scan reports the three as one group, which is why
            // the reason is here rather than in a commit message nobody reads at the
            // moment they are tidying.
            //
            // The three sit under different write contracts -- unconditional insert,
            // version-guarded replace, unconditional overwrite -- each with its own SQL
            // and its own definition of what `n > 0` means. A shared helper would have
            // to decide, on its callers' behalf, when the intent may be cleared and
            // which audit op to append. That is the shape that has bitten twice in this
            // codebase and once in a sibling: a helper enforcing an invariant on the way
            // in while some caller writes around it, and a fix constraining a type no
            // reachable writer goes through. Three visible copies under three contracts
            // beat one helper hiding which contract it is serving.
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::AlreadyExists);
        }
        Ok(())
    }

    /// Create a record (CREATE-ONLY), auditing it as a vault-owned `Put`. Convenience
    /// wrapper over [`create_audited`] for callers (and tests) that do not need to
    /// specify the op/actor; production admin writes use `create_audited` with an
    /// admin context.
    pub fn create(&self, credential_id: &str, record: &VaultRecord) -> Result<(), StoreOpError> {
        self.create_audited(credential_id, record, AuditCtx::vault(AuditOp::Put))
    }

    /// Overwrite an existing record under a compare-and-set on its current payload
    /// hash, with an explicit audit context. Fails [`StoreOpError::NotFound`] if
    /// absent, [`StoreOpError::CasMismatch`] if `expected_payload_hash` does not
    /// match. On success the new record is sealed at `current_version + 1`, the
    /// dangling intent is cleared, and the audit entry is appended — all in ONE
    /// transaction.
    pub fn overwrite_cas_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        expected_payload_hash: &[u8; 32],
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        // Read + decrypt the current record to verify the CAS precondition. A
        // decrypt failure here quarantines the id (handled by `get`).
        let current = self.get(credential_id)?;
        if &payload_hash(&current.payload) != expected_payload_hash {
            return Err(StoreOpError::CasMismatch);
        }
        let next_version = current.record_version.saturating_add(1);
        let mut record = normalize_and_validate_record_identity(record.clone())?;
        record.record_version = next_version;
        let blob = self.seal_record(credential_id, &record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&payload_hash(&record.payload));

        // The version in the WHERE makes the UPDATE itself a compare-and-set on the
        // version we read, so a concurrent writer that already bumped it leaves zero
        // rows changed (no error-string matching). Zero changed => CasMismatch.
        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE credentials \
                  SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, \
                      envelope = ?4, updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    current.record_version as i64
                ],
            )?;
            // Clear any dangling intent in the same txn (see `create`): an admin
            // overwrite with fresh valid tokens must clear the old intent, or boot
            // reconciliation's hash-mismatch check would later undo this re-login.
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::CasMismatch);
        }
        Ok(())
    }

    /// Overwrite an existing record UNCONDITIONALLY (no CAS), re-sealing it at
    /// `current_version + 1` and resetting its state to `active`, while preserving an
    /// existing identity when the replacement does not provide one. This is the normal
    /// token-rotation path; callers that intentionally clear identity use
    /// [`Self::overwrite_unconditional_with_identity_policy_audited`].
    pub fn overwrite_unconditional_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        self.overwrite_unconditional_with_identity_policy_audited(credential_id, record, true, ctx)
    }

    /// Overwrite an existing record UNCONDITIONALLY (no CAS), re-sealing it at
    /// `current_version + 1` and resetting its state to `active`, with an explicit
    /// audit context. Fails [`StoreOpError::NotFound`] if the id is absent.
    ///
    /// When `preserve_existing_identity` is true and `record` has no identity, carries
    /// the existing identity into the replacement. Identity describes the account rather
    /// than the token, so re-importing rotated tokens must not erase account labelling.
    /// An undecryptable existing envelope is treated as no identity so repair still
    /// replaces corrupted material. Passing false makes an empty incoming identity an
    /// explicit clear.
    ///
    /// Unlike [`overwrite_cas_audited`], this reads the current version via `meta`
    /// (plaintext columns, NO decrypt) rather than `get`, so it works even when the
    /// current record is `needs_reauth` or quarantined — which is exactly the
    /// re-import case: an operator imported a credential from the wrong source (its
    /// refresh token is dead → `needs_reauth`) and is replacing it with the correct
    /// one. The handles table is untouched, so existing handles keep resolving to this
    /// id (no re-mint). The version bump + state reset + intent clear + audit entry all
    /// commit in ONE fenced transaction.
    pub fn overwrite_unconditional_with_identity_policy_audited(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        preserve_existing_identity: bool,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let incoming = normalize_and_validate_record_identity(record.clone())?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&payload_hash(&record.payload));

        // Read the current version, seal at version+1, and update — ALL inside the
        // one fenced transaction, gated on `WHERE record_version = <the version we
        // just read>`. On the single writer connection this is atomic: nothing can
        // move the version between the read and the guarded update, so the "+1" can
        // never alias a concurrent refresh's own +1 (the lost-update bug a
        // read-outside-the-txn version + unguarded update would allow). "State-
        // unconditional" (works on needs_reauth/quarantined via the plaintext
        // version read, no decrypt) is preserved; only lost-update tolerance is
        // removed. A CasMismatch here would mean the row vanished mid-txn (a
        // concurrent delete), which cannot happen under the single writer, so the
        // guard is belt-and-suspenders that also documents the invariant.
        let outcome = self.fenced_write(|tx| {
            let existing: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((current_version, existing_envelope)) = existing else {
                return Ok(None); // NotFound: signalled to the caller below.
            };
            let next_version = (current_version as u64).saturating_add(1);

            let mut sealed = incoming.clone();
            if preserve_existing_identity && sealed.identity.is_empty() {
                let existing_identity = envelope::open(
                    &self.key,
                    &existing_envelope,
                    &RecordBinding {
                        credential_id,
                        record_version: current_version as u64,
                    },
                )
                .ok()
                .and_then(|plaintext| VaultRecord::decode(&plaintext).ok())
                .map(|existing| existing.identity);
                if let Some(identity) =
                    existing_identity.filter(|identity| identity.validate().is_ok())
                {
                    sealed.identity = identity;
                }
            }
            sealed.record_version = next_version;
            // seal_record is pure crypto (no DB), safe to call inside the txn.
            let blob = self
                .seal_record(credential_id, &sealed)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            let n = tx.execute(
                "UPDATE credentials \
                  SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, \
                      envelope = ?4, updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    current_version
                ],
            )?;
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(Some(n))
        })?;
        match outcome {
            None => Err(StoreOpError::NotFound),
            Some(0) => Err(StoreOpError::CasMismatch),
            Some(_) => Ok(()),
        }
    }

    /// Replace only non-secret account identity, preserving every secret field and the
    /// record's lifecycle state. The envelope must be re-sealed, so `record_version`
    /// advances and lets consumers treat the identity update as fresh record metadata.
    /// This opens the envelope without the normal serving-state gate: identity is safe
    /// to correct on `needs_reauth` or `retired` records, but an undecryptable record
    /// cannot be labelled because there is no trustworthy material to preserve.
    pub fn set_identity_audited(
        &self,
        credential_id: &str,
        identity: crate::record::RecordIdentity,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let identity = identity.normalized();
        identity.validate().map_err(StoreOpError::Encode)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let outcome = self.fenced_write(|tx| {
            let existing: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT record_version, envelope FROM credentials WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((current_version, envelope)) = existing else {
                return Ok(None);
            };
            let plaintext = envelope::open(
                &self.key,
                &envelope,
                &RecordBinding {
                    credential_id,
                    record_version: current_version as u64,
                },
            )
            .map_err(|error| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(StoreOpError::Decrypt(error)))
            })?;
            let record = VaultRecord::decode(&plaintext).map_err(|error| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(StoreOpError::Corrupt(
                    error.to_string(),
                )))
            })?;
            let next_version = (current_version as u64).saturating_add(1);
            let mut updated = record.with_identity(identity.clone());
            updated.record_version = next_version;
            let payload_hash_hex = hex32(&payload_hash(&updated.payload));
            let blob = self
                .seal_record(credential_id, &updated)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            let changed = tx.execute(
                "UPDATE credentials SET record_version = ?2, key_id = ?3, envelope = ?4, \
                     updated_at_ms = ?5 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    current_version,
                ],
            )?;
            if changed > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::SetIdentity,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(Some(changed))
        })?;
        match outcome {
            None => Err(StoreOpError::NotFound),
            Some(0) => Err(StoreOpError::CasMismatch),
            Some(_) => Ok(()),
        }
    }

    /// Overwrite under CAS, auditing as a vault-owned `Overwrite`. Convenience
    /// wrapper for callers/tests that do not specify an audit context.
    pub fn overwrite_cas(
        &self,
        credential_id: &str,
        record: &VaultRecord,
        expected_payload_hash: &[u8; 32],
    ) -> Result<(), StoreOpError> {
        self.overwrite_cas_audited(
            credential_id,
            record,
            expected_payload_hash,
            AuditCtx::vault(AuditOp::Overwrite),
        )
    }

    /// Read and decrypt a record. Fails closed: a quarantined (`corrupt`) row is
    /// [`StoreOpError::Quarantined`]; `needs_reauth` and `retired` rows are both
    /// [`StoreOpError::NeedsReauth`] so consumers need no new recovery branch; a row
    /// that fails to decrypt or parse is
    /// QUARANTINED (its state flipped to `corrupt`) and returned as a typed error.
    /// Never panics, never returns plaintext on failure.
    pub fn get(&self, credential_id: &str) -> Result<VaultRecord, StoreOpError> {
        self.get_with_stale_pending(credential_id)
            .map(|(record, _)| record)
    }

    /// Read a record with the local stale marker that was observed beside its state.
    ///
    /// This stays crate-private because `stale_pending` is a refresh instruction for
    /// the engine, not credential metadata for callers to interpret.
    pub(crate) fn get_with_stale_pending(
        &self,
        credential_id: &str,
    ) -> Result<(VaultRecord, bool), StoreOpError> {
        let row = self
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT record_version, state, stale_pending, envelope FROM credentials \
                     WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    |r| {
                        let version: i64 = r.get(0)?;
                        let state: String = r.get(1)?;
                        let stale_pending: i64 = r.get(2)?;
                        let blob: Vec<u8> = r.get(3)?;
                        Ok((version, state, stale_pending, blob))
                    },
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?;

        let (version, state, stale_pending, blob) = row.ok_or(StoreOpError::NotFound)?;
        match RecordState::from_str(&state) {
            RecordState::Corrupt => return Err(StoreOpError::Quarantined),
            RecordState::NeedsReauth | RecordState::Retired => {
                return Err(StoreOpError::NeedsReauth)
            }
            RecordState::Active => {}
        }

        let binding = RecordBinding {
            credential_id,
            record_version: version as u64,
        };
        let plaintext = match envelope::open(&self.key, &blob, &binding) {
            Ok(pt) => pt,
            Err(e) => {
                // Per-record quarantine: a single undecryptable row is isolated so
                // the rest of the vault keeps serving. Best-effort state flip — a
                // failure to mark must not itself panic the read path.
                let _ = self.quarantine(credential_id);
                return Err(StoreOpError::Decrypt(e));
            }
        };
        match VaultRecord::decode(&plaintext) {
            Ok(record) => Ok((record, stale_pending != 0)),
            Err(e) => {
                let _ = self.quarantine(credential_id);
                Err(StoreOpError::Corrupt(e.to_string()))
            }
        }
    }

    /// Mark a record `needs_reauth` (authoritative revoke / reported auth failure)
    /// and clear any dangling refresh intent for it, with an explicit audit context —
    /// the state flip, the intent clear, and the audit entry all commit atomically.
    /// A no-op (Ok) if the id is absent.
    ///
    /// Clears the intent because an authoritative revoke supersedes any in-flight
    /// refresh: leaving a stale intent would let boot reconciliation reason about a
    /// credential the operator has already invalidated.
    pub fn invalidate_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth, true, Some(ctx))
    }

    /// Version-gated invalidate for a consumer-reported auth failure: mark the
    /// credential `needs_reauth` (and clear any dangling intent) ONLY if its current
    /// `record_version` still equals `expected_version` — the version the consumer was
    /// actually served. Returns `true` if it invalidated, `false` (a silent, successful
    /// no-op) if the version has since moved on.
    ///
    /// This closes a false-invalidation race: a consumer reports a 401 for the token it
    /// held at version N, but the vault has meanwhile refreshed to N+1 (a fresh, working
    /// token); the stale report must NOT kill the healthy N+1 credential. Because every
    /// durable mutation is serialized through the store's single writer connection, this
    /// CAS and a concurrent `commit_refresh` can never interleave: report-first flips
    /// state at version N and the refresh's `WHERE record_version = N` still overwrites it
    /// back to active N+1; refresh-first bumps to N+1 and this CAS matches 0 rows → no-op.
    /// Either ordering converges on the fresh token. It also neuters malicious
    /// invalidation: a consumer can only ever kill the exact version it was served.
    ///
    /// A no-op (Ok(false)) if the id is absent.
    pub fn invalidate_if_version_audited(
        &self,
        credential_id: &str,
        expected_version: u64,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        self.invalidate_if_version_reported(credential_id, expected_version, ctx, None)
    }

    /// As [`Self::invalidate_if_version_audited`], additionally recording WHY.
    ///
    /// `observation` describes what the caller saw, and is written to `auth_events`
    /// in the same transaction WHETHER OR NOT the version matched. That is the point:
    /// a report naming a superseded version is deliberately a no-op on the credential,
    /// and previously left nothing behind, so the case where a consumer is acting on
    /// stale state -- the one worth investigating -- was the one with no record. The
    /// row's `applied` column distinguishes the two outcomes.
    pub fn invalidate_if_version_reported(
        &self,
        credential_id: &str,
        expected_version: u64,
        ctx: AuditCtx<'_>,
        observation: Option<AuthObservation<'_>>,
    ) -> Result<bool, StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let changed = self
            .fenced_write(|tx| {
                // `state <> needs_reauth` makes this a STATE TRANSITION rather than a
                // repeatable write, and that is what bounds the audit chain here.
                //
                // The version guard alone does not: invalidating does not bump
                // record_version, so a consumer reporting the same version twice
                // matched twice, and every match appends to a chain that is
                // append-only by design and must never be trimmed. Measured before
                // this guard existed: eight identical reports produced eight
                // `report_auth_failure` entries, seven of which changed nothing --
                // the credential was already `needs_reauth` after the first.
                //
                // With the clause, a repeat matches zero rows and audits nothing,
                // while the FIRST report still audits exactly as before. The
                // diagnostic record of the repeats is not lost: `auth_events` records
                // every report either way, which is what that table is for, and it is
                // bounded per credential where the chain cannot be.
                let n = tx.execute(
                    "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND record_version = ?4 AND state <> ?2",
                    rusqlite::params![
                        credential_id,
                        RecordState::NeedsReauth.as_str(),
                        now,
                        expected_version as i64
                    ],
                )?;
                if let Some(obs) = observation {
                    append_auth_event_tx(tx, credential_id, &obs, Some(expected_version), n > 0)?;
                }
                if n > 0 {
                    // Same version still current: this is an authoritative revoke, so clear
                    // any dangling intent and audit it, exactly like invalidate_audited.
                    clear_intent_tx(tx, credential_id)?;
                    append_audit_tx(
                        tx,
                        &audit_key,
                        &AuditRecord {
                            op: ctx.op,
                            credential_id: Some(credential_id.to_string()),
                            payload_hash: None,
                            actor: ctx.actor.to_string(),
                            alarm: ctx.alarm,
                        },
                    )?;
                }
                Ok(n)
            })
            .map_err(StoreOpError::from)?;
        Ok(changed > 0)
    }

    /// Mark only the current token stale after a consumer reports it refused.
    ///
    /// The version fence protects a token freshly replaced by a concurrent refresh:
    /// a report for version N cannot set the local marker on version N+1. The marker
    /// deliberately stays outside the envelope and does not advance `record_version`,
    /// because it is a local refresh instruction rather than a changed provider fact.
    pub fn mark_stale_if_version_reported(
        &self,
        credential_id: &str,
        expected_version: u64,
        ctx: AuditCtx<'_>,
        observation: AuthObservation<'_>,
    ) -> Result<bool, StoreOpError> {
        let audit_key = self.audit_key.clone();
        let changed = self
            .fenced_write(|tx| {
                // A repeated report for the same version has already instructed the
                // next read to refresh. Treat it as no new state transition so the
                // append-only audit chain remains bounded; auth_events still records it.
                let n = tx.execute(
                    "UPDATE credentials SET stale_pending = 1 \
                     WHERE credential_id = ?1 AND record_version = ?2 AND stale_pending = 0",
                    rusqlite::params![credential_id, expected_version as i64],
                )?;
                append_auth_event_tx(
                    tx,
                    credential_id,
                    &observation,
                    Some(expected_version),
                    n > 0,
                )?;
                if n > 0 {
                    append_audit_tx(
                        tx,
                        &audit_key,
                        &AuditRecord {
                            op: ctx.op,
                            credential_id: Some(credential_id.to_string()),
                            payload_hash: None,
                            actor: ctx.actor.to_string(),
                            alarm: ctx.alarm,
                        },
                    )?;
                }
                Ok(n)
            })
            .map_err(StoreOpError::from)?;
        Ok(changed > 0)
    }

    /// Record an authentication observation WITHOUT changing the credential.
    ///
    /// For events that explain a credential's health but authorise no state change --
    /// chiefly a refresh that failed transiently, which clears its intent and leaves
    /// the record active. Nothing durable said the provider had been called and
    /// refused, so a credential could fail repeatedly and look untouched.
    ///
    /// Diagnostics only, and this write deliberately skips the fence that guards every
    /// credential mutation. That fence rejects a write from an instance whose lease has
    /// been taken over, which is right for anything carrying authority and wrong here:
    /// an explanatory row would then fail exactly when a handover is making the system
    /// hardest to explain.
    pub fn record_auth_event(
        &self,
        credential_id: &str,
        observation: AuthObservation<'_>,
        record_version: Option<u64>,
    ) -> Result<(), StoreOpError> {
        self.store
            .with_conn(|c| {
                let tx = c.unchecked_transaction()?;
                append_auth_event_tx(&tx, credential_id, &observation, record_version, false)?;
                tx.commit()
            })
            .map_err(StoreOpError::from)
    }

    /// Record why a principal-scoped read was refused. This is a trimmable diagnostic
    /// observation, not an authority transition, so it deliberately does not take the
    /// writer fence or append to the untrimmable audit chain.
    pub fn record_scoped_read_refusal(
        &self,
        credential_id: &str,
        principal_kind: &str,
        principal_id: Option<&str>,
        refusal: ScopedReadRefusal,
    ) -> Result<(), StoreOpError> {
        self.store
            .with_conn(|c| {
                let tx = c.unchecked_transaction()?;
                tx.execute(
                    "INSERT INTO auth_events \
                     (ts_ms, credential_id, kind, provider_status, detail, record_version, applied, principal_kind, principal_id) \
                     VALUES (?1, ?2, ?3, NULL, ?4, NULL, 0, ?5, ?6)",
                     rusqlite::params![
                         now_ms(),
                         credential_id,
                         AuthEventKind::ScopedReadRefusal.as_str(),
                         refusal.as_str(),
                        principal_kind,
                        principal_id,
                    ],
                )?;
                trim_auth_events_tx(&tx, credential_id)?;
                tx.commit()
            })
            .map_err(StoreOpError::from)
    }

    /// Read recent authentication events, newest first. Diagnostics for an operator
    /// asking why a credential stopped working; never an authority for what happened.
    pub fn recent_auth_events(&self, limit: u32) -> Result<Vec<AuthEvent>, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(auth_events_select(c)?)?;
                let rows = stmt.query_map(rusqlite::params![limit], auth_event_from_row)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(StoreOpError::from)
    }

    /// Invalidate, auditing as a vault-owned `Invalidate`. Convenience wrapper for
    /// callers/tests that do not specify an audit context.
    pub fn invalidate(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.invalidate_audited(credential_id, AuditCtx::vault(AuditOp::Invalidate))
    }

    /// Retire a credential only from the operator's logout path: mark an `active` or
    /// `needs_reauth` record `retired`, clear any dangling refresh intent, and revoke
    /// every live handle in one fenced transaction.
    ///
    /// A retirement is an operator acknowledgement, not a discovery of bad material.
    /// `Corrupt` is therefore deliberately excluded: clearing its health contribution
    /// would hide a vault-observed integrity failure. `Retired` is likewise a no-op so
    /// repeated logout requests do not grow the untrimmable audit chain.
    pub fn retire_and_revoke_all_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<InvalidateOutcome, StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let state_changed = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND state IN (?4, ?5)",
                rusqlite::params![
                    credential_id,
                    RecordState::Retired.as_str(),
                    now,
                    RecordState::Active.as_str(),
                    RecordState::NeedsReauth.as_str(),
                ],
            )? > 0;
            let intent_cleared = clear_intent_tx(tx, credential_id)? > 0;
            let revoked = tx.execute(
                "UPDATE handles SET revoked = 1 \
                 WHERE credential_id = ?1 AND revoked = 0",
                rusqlite::params![credential_id],
            )?;
            if state_changed || intent_cleared {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            if revoked > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::RevokeHandle,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(InvalidateOutcome {
                state_changed,
                intent_cleared,
                handles_revoked: revoked,
            })
        })
        .map_err(StoreOpError::from)
    }

    /// The COMPOUND authoritative invalidate: mark `needs_reauth`, clear any
    /// dangling refresh intent, AND revoke every live handle for the credential —
    /// all in ONE fenced transaction, with both audit entries (`Invalidate` and,
    /// when any handles were live, `RevokeHandle`) inside it.
    ///
    /// This exists because invalidate-then-revoke as two calls is crash-partial: a
    /// crash between them leaves a dead credential still resolvable by handle. The
    /// offline CLI performs the same pair; the online admin surface additionally
    /// must not let a relay reorder or split the two halves, so the compound op is
    /// the only online shape.
    ///
    /// REPORTS WHAT IT ACTUALLY CHANGED, and the state flip is guarded so a repeat
    /// is a true no-op. Without the guard this always "succeeded": running it on an
    /// already-invalidated credential rewrote the same state, revoked nothing, and
    /// appended an `Invalidate` audit entry recording that nothing happened. An
    /// operator seeing an unchanged listing after a success message reasonably
    /// concludes the command is broken — observed live, three consecutive invalidations
    /// against one already-dead credential, three identical successes.
    ///
    /// Suppressing the no-op audit entry matters on its own: the chain is
    /// tamper-evident and therefore UNTRIMMABLE, so an operator (or a script)
    /// repeating an invalidation would grow it without bound with entries that record
    /// no mutation. The same guard was added to the consumer-driven path for the same
    /// reason; this is the operator-driven half of it.
    pub fn invalidate_and_revoke_all_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<InvalidateOutcome, StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            // `AND state <> ?2` makes this a TRANSITION rather than a write: the
            // rows-changed count is then the answer to "did this do anything",
            // which is what both the audit decision and the operator message need.
            let state_changed = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND state <> ?2",
                rusqlite::params![credential_id, RecordState::NeedsReauth.as_str(), now],
            )? > 0;
            let intent_cleared = clear_intent_tx(tx, credential_id)? > 0;
            let revoked = tx.execute(
                "UPDATE handles SET revoked = 1 \
                 WHERE credential_id = ?1 AND revoked = 0",
                rusqlite::params![credential_id],
            )?;
            // Audit the mutation, not the request. An invalidation that finds the
            // credential already dead with no live handles mutated nothing, and an audit
            // entry claiming otherwise is a false record in a chain whose
            // whole value is that its entries are true.
            if state_changed || intent_cleared {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            if revoked > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::RevokeHandle,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(InvalidateOutcome {
                state_changed,
                intent_cleared,
                handles_revoked: revoked,
            })
        })
        .map_err(StoreOpError::from)
    }

    /// PERMANENTLY remove a credential: delete the row, its refresh intent, and its
    /// handle rows, appending a `Remove` audit entry — all in ONE fenced transaction.
    /// The audit chain keeps the credential's full history (append-only; removal is
    /// itself an entry), so this deletes serving state, never forensics. For retiring
    /// an account or cleaning up a mistaken id; a temporary stop is `logout`
    /// (retire + revoke, reversible). Returns [`StoreOpError::NotFound`] when the
    /// id has no row, so a typo'd remove is loud instead of a silent no-op.
    /// Returns how many handle rows were deleted, because a consumer holding one
    /// cannot be told by the vault. Handles are bearer capabilities: nothing records
    /// WHO holds one, so removal cannot notify anybody, and a consumer's next fetch
    /// gets `not_found` with no explanation of why. Reporting the count gives the
    /// operator the one fact that says "go check your consumers" at the moment they
    /// can still act on it -- observed live, a removed credential left a stale entry
    /// in a consumer's handle file and blinded its sibling accounts until noticed.
    /// THERE IS NO UN-REMOVE, AND UNLIKE `reactivate` THAT IS IMPOSSIBLE RATHER THAN
    /// DECLINED. The distinction matters to a reader deciding whether to add one.
    ///
    /// `reactivate` exists because `needs_reauth` and `retired` only change a VERDICT
    /// while the sealed material stays on disk, so the verdict can be contradicted. This DELETEs the
    /// credentials row, and the sealed envelope is the only copy of the secret the vault
    /// ever had -- for a `github_app` key, the only copy anywhere, since the PEM is
    /// shredded after deposit by custody rule. After this commits there is nothing left
    /// to restore: the audit chain retains the HISTORY of the credential, never its bytes.
    ///
    /// So the repair for a mistaken `remove` is a fresh deposit of fresh material, which
    /// for a platform-issued key means an operator ceremony. That is the cost of the verb
    /// and it is why `logout` or `invalidate` is the reversible sibling an operator
    /// should reach for first -- stated here because now that ONE inverse exists in this file,
    /// an absent one stops looking deliberate.
    pub fn remove_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<usize, StoreOpError> {
        let audit_key = self.audit_key.clone();
        let (removed, handles) = self.fenced_write(|tx| {
            let n = tx.execute(
                "DELETE FROM credentials WHERE credential_id = ?1",
                rusqlite::params![credential_id],
            )?;
            let mut handles = 0usize;
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                // Handle rows are deleted outright (not just revoked): the credential
                // is gone, so retaining hash rows would only grow an unusable table.
                // The mint/revoke history stays in the audit chain.
                handles = tx.execute(
                    "DELETE FROM handles WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                )?;
                // Diagnostic events go WITH the credential, and this is the one
                // place they can go.
                //
                // `auth_events` is capped per credential, but the trim runs on
                // insert -- and a removed credential never gets another insert, so
                // without this its rows would be the one thing in the store nothing
                // can ever reclaim. Small per removal and driven by an operator
                // rather than by traffic, so this is tidiness rather than a bound,
                // but it is also the difference between `ck auth events` showing a
                // live vault and showing a graveyard.
                //
                // Nothing forensic is lost: the chain holds this credential's whole
                // history including the removal itself, and it is the chain that is
                // evidence -- these rows are explanation, and there is nothing left
                // to explain once the credential is gone. A removal ordered BECAUSE
                // a credential was failing is the case to think about, and there the
                // events were read before the removal, not after.
                tx.execute(
                    "DELETE FROM auth_events WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                )?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok((n, handles))
        })?;
        if removed == 0 {
            return Err(StoreOpError::NotFound);
        }
        Ok(handles)
    }

    /// Quarantine a record (`corrupt`). Used by the read path on a decrypt/parse
    /// failure; idempotent. Does NOT clear a refresh intent or audit — quarantine is
    /// an internal integrity flip, not a recorded mutation, and a corrupt record's
    /// intent (if any) is for reconciliation to resolve, not for this path to discard.
    /// ITS INVERSE EXISTS UNDER A DIFFERENT NAME, which is worth saying because a reader
    /// counting absences will otherwise reach the wrong conclusion in one of two ways.
    ///
    /// There is no un-quarantine, and `reactivate_audited` refuses `Corrupt` on purpose:
    /// this state means the sealed bytes failed their own integrity check, and no
    /// assertion makes an undecryptable envelope decrypt. But the record is NOT lost --
    /// `put --replace` (overwrite-unconditional) writes fresh material into the same id,
    /// clearing the state as a side effect and keeping the credential's audit lineage and
    /// its handles.
    ///
    /// THE EXPENSIVE MISREADING IS THE QUIET ONE. A reader who concludes a corrupt record
    /// is unrecoverable reaches for `remove`, which DELETEs the row and its handles -- so
    /// every consumer holding a handle loses it, and for a platform-issued key the repair
    /// becomes a fresh operator ceremony rather than one command. Replace repairs in
    /// place; remove escalates a fixable state into a ceremony.
    ///
    /// So the three shapes of a missing inverse each need their own note: DECLINED (handle
    /// revocation -- implementable, refused, arguable), IMPOSSIBLE (`remove` -- the bytes
    /// are gone), and RENAMED (this one -- it exists, under a name that does not look like
    /// an inverse).
    pub fn quarantine(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::Corrupt, false, None)
    }

    /// Quarantine only the exact record version the reader inspected. A concurrent
    /// refresh or admin replacement must not let a stale integrity decision poison the
    /// newly-written credential.
    pub fn quarantine_if_version(
        &self,
        credential_id: &str,
        expected_version: u64,
    ) -> Result<bool, StoreOpError> {
        let now = now_ms();
        let changed = self.fenced_write(|tx| {
            tx.execute(
                "UPDATE credentials SET state = 'corrupt', updated_at_ms = ?1
                 WHERE credential_id = ?2 AND record_version = ?3",
                rusqlite::params![now, credential_id, expected_version],
            )
        })?;
        Ok(changed == 1)
    }

    /// Mark a record `needs_reauth` but RETAIN its refresh intent. Used by
    /// reconciliation when a non-mutating validity check could not be run (transient
    /// network): the record fails closed now, but the surviving intent lets a later
    /// retry re-check and restore the credential without a forced re-login.
    pub fn mark_needs_reauth_retaining_intent(
        &self,
        credential_id: &str,
    ) -> Result<(), StoreOpError> {
        self.set_state(credential_id, RecordState::NeedsReauth, false, None)
    }

    /// Clear `needs_reauth` or `retired` back to active WITHOUT touching the stored
    /// material.
    ///
    /// THE REPAIR PATH FOR A VERDICT THAT WAS WRONG. `needs_reauth` is a claim about the
    /// OUTSIDE WORLD -- a provider rejected us, or a consumer said one did -- and the
    /// outside world can be misreported. On 2026-08-17 a consumer relayed GitHub's 403
    /// ("this token is valid and lacks one permission") as an auth failure, and a
    /// seconds-old, perfectly good App credential went dead.
    ///
    /// Without this verb that state was UNRECOVERABLE for the class it hit hardest.
    /// GitHub App keys are shredded after deposit by the vault's own custody rule, so
    /// the vault holds the only copy: `put --replace` needs a PEM nobody has, and no
    /// login flow exists to re-mint one. Repairing material the vault already held
    /// intact would have required a fresh key from GitHub and an operator at a browser.
    /// A consumer's mistaken report could force a human ceremony.
    ///
    /// ONLY FROM `NeedsReauth` OR `Retired`, never from `Corrupt`, and the distinction is
    /// the whole safety argument. Both allowed states are verdicts about serving, while
    /// Corrupt is a claim about OUR OWN BYTES -- they failed to decrypt,
    /// or the payload was empty -- which this vault verified itself and which clearing
    /// cannot fix; it would only put known-broken bytes back into service. Reactivating a
    /// corrupt record is refused rather than silently ignored.
    ///
    /// SELF-CORRECTING BY CONSTRUCTION, which is why it is safe to expose. The operator
    /// asserts the material is good; the vault verifies on next use. If the credential
    /// really is dead, a refreshable record's next `get` gets `InvalidGrant` from the
    /// provider and returns to `needs_reauth` on its own, and a static record's consumer
    /// reports again. The cost of a wrong assertion is one failed call, not a bad state
    /// that persists.
    ///
    /// Guarded as a TRANSITION: reactivating an already-active credential changes nothing
    /// and writes nothing, so a retry loop cannot append to the untrimmable audit chain.
    pub fn reactivate_audited(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<bool, StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            // The state predicate is IN the UPDATE, so the guard cannot be defeated by a
            // concurrent writer between a read and a write.
            let n = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1 AND state IN (?4, ?5)",
                rusqlite::params![
                    credential_id,
                    RecordState::Active.as_str(),
                    now,
                    RecordState::NeedsReauth.as_str(),
                    RecordState::Retired.as_str(),
                ],
            )?;
            if n > 0 {
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: ctx.op,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: None,
                        actor: ctx.actor.to_string(),
                        alarm: ctx.alarm,
                    },
                )?;
            }
            Ok(n > 0)
        })
        .map_err(StoreOpError::from)
    }

    fn set_state(
        &self,
        credential_id: &str,
        state: RecordState,
        clear_intent: bool,
        ctx: Option<AuditCtx<'_>>,
    ) -> Result<(), StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE credentials SET state = ?2, updated_at_ms = ?3 \
                 WHERE credential_id = ?1",
                rusqlite::params![credential_id, state.as_str(), now],
            )?;
            if clear_intent {
                clear_intent_tx(tx, credential_id)?;
            }
            // Audit the state change only when it actually hit a row and a
            // context was supplied (quarantine/retain are internal, unaudited).
            if n > 0 {
                if let Some(ctx) = ctx {
                    append_audit_tx(
                        tx,
                        &audit_key,
                        &AuditRecord {
                            op: ctx.op,
                            credential_id: Some(credential_id.to_string()),
                            payload_hash: None,
                            actor: ctx.actor.to_string(),
                            alarm: ctx.alarm,
                        },
                    )?;
                }
            }
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    // ---- refresh intent log (crash-safe rotation) -----------------------

    /// Durably open a refresh intent (txn1 of the refresh state machine): the
    /// fsynced marker written BEFORE the provider's rotating endpoint is called.
    ///
    /// Goes through the fenced path so a superseded writer cannot open an intent,
    /// and (with `synchronous=FULL`) the row is on disk before this returns —
    /// guaranteeing a crash during the subsequent network call leaves a recoverable
    /// intent. `record_version` is the version being refreshed from (the commit's
    /// CAS guard); `old_refresh_hash` is [`refresh_token_hash`] of the current
    /// refresh token. Replaces any existing intent for the id (single-flight means
    /// there is at most one, but a re-open after a transient failure is idempotent).
    pub fn open_intent(
        &self,
        credential_id: &str,
        record_version: u64,
        old_refresh_hash: &str,
    ) -> Result<(), StoreOpError> {
        let epoch = self.store.epoch();
        let now = now_ms();
        self.fenced_write(|tx| {
            tx.execute(
                "INSERT INTO refresh_intent \
                 (credential_id, record_version, old_refresh_hash, lease_epoch, started_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(credential_id) DO UPDATE SET \
                   record_version = excluded.record_version, \
                   old_refresh_hash = excluded.old_refresh_hash, \
                   lease_epoch = excluded.lease_epoch, \
                   started_at_ms = excluded.started_at_ms",
                rusqlite::params![
                    credential_id,
                    record_version as i64,
                    old_refresh_hash,
                    epoch as i64,
                    now
                ],
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    /// Commit a completed refresh (txn2): seal the new record at
    /// `expected_version + 1`, write it, and clear the intent — in ONE fenced,
    /// fsynced transaction, so the new tokens become visible AND the intent clears
    /// atomically, or neither does.
    ///
    /// Fails [`StoreOpError::CasMismatch`] if the stored version is no longer
    /// `expected_version` (a concurrent write moved it), and
    /// [`StoreOpError::Fenced`] if a newer instance took the lease mid-commit (the
    /// lease-handover race) — in which case NOTHING is applied and the caller must
    /// discard the staged tokens and not retry (reconciliation on the new owner
    /// resolves the still-dangling intent). The new `record_version` is returned.
    pub fn commit_refresh(
        &self,
        credential_id: &str,
        expected_version: u64,
        new_record: &VaultRecord,
    ) -> Result<u64, StoreOpError> {
        let next_version = expected_version.saturating_add(1);
        let mut new_record = new_record.clone();
        new_record.record_version = next_version;
        let blob = self.seal_record(credential_id, &new_record)?;
        let key_id_hex = self.key_id.to_hex();
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        let payload_hash_hex = hex32(&payload_hash(&new_record.payload));

        let changed = self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE credentials \
                  SET record_version = ?2, key_id = ?3, state = 'active', stale_pending = 0, \
                      envelope = ?4, updated_at_ms = ?5 \
                 WHERE credential_id = ?1 AND record_version = ?6",
                rusqlite::params![
                    credential_id,
                    next_version as i64,
                    key_id_hex,
                    blob,
                    now,
                    expected_version as i64
                ],
            )?;
            // The new tokens, the intent-clear, and the audit entry commit together
            // or not at all — so the refresh's version bump is accounted for in the
            // chain (a vault-owned RefreshCommit).
            if n > 0 {
                clear_intent_tx(tx, credential_id)?;
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::RefreshCommit,
                        credential_id: Some(credential_id.to_string()),
                        payload_hash: Some(payload_hash_hex),
                        actor: "vault".to_string(),
                        alarm: None,
                    },
                )?;
            }
            Ok(n)
        })?;
        if changed == 0 {
            return Err(StoreOpError::CasMismatch);
        }
        Ok(next_version)
    }

    /// Persist the last observed GitHub App installation grant after its token commit.
    ///
    /// This is deliberately best-effort inside the store rather than an error returned
    /// to the refresh engine: permission history explains a successful mint, but can
    /// never make that token unavailable. The post-commit version guard prevents an
    /// older owner from replacing a newer mint's observation after a lease handover.
    pub(crate) fn observe_github_app_permissions(
        &self,
        credential_id: &str,
        record_version: u64,
        permissions: &BTreeMap<String, String>,
    ) {
        let Ok(current_json) = serde_json::to_string(permissions) else {
            return;
        };
        let _ = self.store.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            let previous_json: Option<Option<String>> = tx
                .query_row(
                    "SELECT last_github_app_permissions FROM credentials \
                     WHERE credential_id = ?1 AND record_version = ?2",
                    rusqlite::params![credential_id, record_version as i64],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(previous_json) = previous_json else {
                tx.commit()?;
                return Ok(());
            };

            let updated = tx.execute(
                "UPDATE credentials SET last_github_app_permissions = ?3 \
                 WHERE credential_id = ?1 AND record_version = ?2",
                rusqlite::params![credential_id, record_version as i64, current_json],
            )?;
            if updated > 0 {
                if let Some(previous) = previous_json
                    .as_deref()
                    .and_then(|json| serde_json::from_str::<BTreeMap<String, String>>(json).ok())
                    .filter(|previous| previous != permissions)
                {
                    let detail = github_app_permissions_change_detail(&previous, permissions);
                    append_auth_event_tx(
                        &tx,
                        credential_id,
                        &AuthObservation {
                            kind: AuthEventKind::GithubAppPermissionsChanged.as_str(),
                            provider_status: None,
                            detail: Some(&detail),
                            reporter_source: None,
                        },
                        Some(record_version),
                        true,
                    )?;
                }
            }
            tx.commit()
        });
    }

    /// Read the dangling intent for one credential, if any (reconciliation + the
    /// boot gate's never-serve-dangling check).
    pub fn read_intent(&self, credential_id: &str) -> Result<Option<RefreshIntent>, StoreOpError> {
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT credential_id, record_version, old_refresh_hash, lease_epoch, \
                            started_at_ms FROM refresh_intent WHERE credential_id = ?1",
                    rusqlite::params![credential_id],
                    row_to_intent,
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)
    }

    /// List every dangling intent (the boot reconciliation scan).
    pub fn list_intents(&self) -> Result<Vec<RefreshIntent>, StoreOpError> {
        self.store
            .with_conn(|c| {
                let mut stmt = c.prepare(
                    "SELECT credential_id, record_version, old_refresh_hash, lease_epoch, \
                            started_at_ms FROM refresh_intent ORDER BY credential_id",
                )?;
                let rows = stmt.query_map([], row_to_intent)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(StoreOpError::from)
    }

    /// Clear a dangling intent (reconciliation resolved it). Fenced.
    pub fn clear_intent(&self, credential_id: &str) -> Result<(), StoreOpError> {
        self.fenced_write(|tx| clear_intent_tx(tx, credential_id).map(|_| ()))
            .map_err(StoreOpError::from)
    }

    /// The current refresh token hash stored for a credential, read by decrypting
    /// the record. Used by reconciliation to compare against an intent's
    /// `old_refresh_hash`. `None` for a non-OAuth or absent record.
    pub fn stored_refresh_hash(&self, credential_id: &str) -> Result<Option<String>, StoreOpError> {
        match self.get(credential_id) {
            Ok(record) => Ok(record
                .oauth
                .as_ref()
                .map(|o| refresh_token_hash(&o.refresh_token))),
            Err(StoreOpError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // ---- capability handles ---------------------------------------------

    /// Resolve a raw capability handle to its credential id. Hashes the presented
    /// handle and looks up a NON-revoked row; returns [`StoreOpError::NotFound`]
    /// when the handle is unknown or revoked (the read surface maps that to a
    /// uniform not-found so a probe cannot tell "wrong handle" from "revoked").
    pub fn resolve_handle(&self, raw_handle: &str) -> Result<String, StoreOpError> {
        let h = handle_hash(raw_handle);
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT credential_id FROM handles \
                     WHERE handle_hash = ?1 AND revoked = 0",
                    rusqlite::params![h],
                    |r| r.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
            })
            .map_err(StoreOpError::from)?
            .ok_or(StoreOpError::NotFound)
    }

    /// Record a freshly minted handle for a credential, storing only its hash, AND
    /// append a `MintHandle` audit entry — both in ONE fenced transaction, so a handle
    /// can never be minted without a tamper-evident audit record (the same atomicity
    /// every other durable mutation uses). Mint is admin-only; the caller's audit
    /// context records WHICH admin origin performed it (offline CLI vs the module's
    /// authenticated route admin surface) so the trail is truthful provenance.
    ///
    /// DELIBERATELY INDIFFERENT TO THE CREDENTIAL'S STATE: a handle is a grant to a
    /// credential, not an assertion that it currently works, so minting for a
    /// `needs_reauth` record succeeds. That is the shape production reaches on its own
    /// — a live consumer holds a handle across a credential dying and being repaired,
    /// and the same handle serves afterwards.
    ///
    /// Adding a state check here would look like a safety improvement and would break
    /// that: it would make a handle un-mintable exactly when an operator is repairing
    /// a dead credential.
    pub fn put_handle_hash(
        &self,
        handle_hash_hex: &str,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<(), StoreOpError> {
        let now = now_ms();
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            tx.execute(
                "INSERT INTO handles (handle_hash, credential_id, created_at_ms, revoked) \
                 VALUES (?1, ?2, ?3, 0)",
                rusqlite::params![handle_hash_hex, credential_id, now],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::MintHandle,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    /// Revoke a single handle by its raw value (idempotent — revoking an unknown or
    /// already-revoked handle is a no-op success). The update AND a `RevokeHandle`
    /// audit entry commit in ONE fenced transaction, so a revocation — the most
    /// security-relevant handle action — is always tamper-evidently recorded. The
    /// audit entry is keyed by the handle hash (the raw handle is never stored) AND, when
    /// the handle resolves, by the credential that lost a door.
    ///
    /// THAT SECOND HALF WAS MISSING AND THE COMMENT HERE DEFENDED THE GAP. It said
    /// revoke-by-handle "does not name the credential" -- true of the CALLER'S INPUT and
    /// false about the transaction, which looks the row up by hash and therefore knows
    /// the owner. A limitation of an argument was written down as a limitation of the
    /// operation, and it read as a decision for two months.
    ///
    /// The cost was measured by an external contributor on 2026-08-25: a five-credential
    /// rotation produced revocations that the chain could not attribute, two of them
    /// sharing a timestamp to the second and therefore indistinguishable. The chain
    /// answered "a handle was revoked" and could not answer the question an incident
    /// actually asks -- WHICH CREDENTIALS LOST ACCESS, AND WHEN. Recovery by correlating
    /// against the `handles` table works only while the row survives and only if exactly
    /// one revocation landed in that second.
    ///
    /// No secrecy cost: `mint_handle` already records `credential_id`, and both values
    /// are non-secret by construction (the handle is hashed server-side, so neither is a
    /// bearer token). A census across the whole op vocabulary on a live chain found this
    /// was the ONLY genuine gap -- `fetch_anomaly` is also credential-less and that is
    /// correct, since an enumeration sweep is about the connection and its probed handles
    /// may match no credential at all.
    ///
    /// A NULL HERE NOW MEANS SOMETHING, which partly answers the note below: for entries
    /// written after this change, an absent credential id means the handle did not
    /// resolve, so the revocation moved no rows. A populated one means a real door
    /// closed. That does not fully separate attempt from effect -- an already-revoked
    /// handle still resolves -- but it distinguishes the case that changed nothing at all
    /// from the case that did.
    ///
    /// THERE IS DELIBERATELY NO UN-REVOKE, AND THE ABSENCE IS THE POINT. Written down
    /// because an absent mechanism cannot be found by reading code: there is no symbol,
    /// no failing test, and nothing to grep, so the gap is invisible until someone adds
    /// the "missing" verb.
    ///
    /// `reactivate_audited` makes that MORE tempting rather than less, which is why this
    /// note exists. Shipping a counterpart to `invalidate` establishes a pattern, and
    /// un-revoke looks like the same shape one level down. It is not:
    ///
    /// - `reactivate` restores THE VAULT'S OWN trust in material the vault still holds.
    ///   The secret never left; only a verdict about it was wrong.
    /// - un-revoke would restore A THIRD PARTY'S access to a bearer token that has
    ///   already left the building. A handle is revoked because it may have leaked, and
    ///   the vault has no record of who holds a copy — un-revoking hands access back to
    ///   whoever kept the string, including the reason it was revoked.
    ///
    /// The repair for a wrongly-revoked handle is to MINT A NEW ONE and distribute it,
    /// which is cheap and leaves the leaked value dead. If a consumer needs continuity,
    /// mint before revoking.
    ///
    /// UNRELATED AND UNFIXED, noted so it is not lost: this appends an audit entry
    /// unconditionally, so a script revoking defensively in a loop grows the untrimmable
    /// chain with entries that changed nothing — the defect
    /// `invalidate_and_revoke_all_audited` was fixed for. Not changed here tonight
    /// because it is a genuine design question rather than an oversight: a revocation
    /// ATTEMPT may be worth recording even when it moved no rows, and the chain has no
    /// field to say which happened. Admin-gated, so no unauthenticated caller can drive
    /// it.
    pub fn revoke_handle(&self, raw_handle: &str, ctx: AuditCtx<'_>) -> Result<(), StoreOpError> {
        let h = handle_hash(raw_handle);
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            // Read the owner INSIDE the same transaction, before the update. One indexed
            // lookup on an admin-gated path, and it is what makes the entry attributable.
            let owner: Option<String> = tx
                .query_row(
                    "SELECT credential_id FROM handles WHERE handle_hash = ?1",
                    rusqlite::params![h],
                    |row| row.get(0),
                )
                .optional()?;
            tx.execute(
                "UPDATE handles SET revoked = 1 WHERE handle_hash = ?1",
                rusqlite::params![h],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RevokeHandle,
                    credential_id: owner,
                    payload_hash: Some(h.clone()),
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)
    }

    /// Revoke ALL handles for a credential (e.g. on invalidate / suspected leak).
    /// Returns the number revoked. The update AND a `RevokeHandle` audit entry (naming
    /// the credential) commit in ONE fenced transaction.
    pub fn revoke_all_handles(
        &self,
        credential_id: &str,
        ctx: AuditCtx<'_>,
    ) -> Result<usize, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| {
            let n = tx.execute(
                "UPDATE handles SET revoked = 1 \
                 WHERE credential_id = ?1 AND revoked = 0",
                rusqlite::params![credential_id],
            )?;
            append_audit_tx(
                tx,
                &audit_key,
                &AuditRecord {
                    op: AuditOp::RevokeHandle,
                    credential_id: Some(credential_id.to_string()),
                    payload_hash: None,
                    actor: ctx.actor.to_string(),
                    alarm: ctx.alarm,
                },
            )?;
            Ok(n)
        })
        .map_err(StoreOpError::from)
    }

    // ---- audit chain ----------------------------------------------------

    /// Append one entry to the tamper-evident audit chain, computing its HMAC over
    /// the previous entry's mac, in a fenced write. Standalone variant; mutation
    /// paths that must audit atomically use [`append_audit_tx`] inside their own
    /// transaction.
    pub fn append_audit(&self, record: &AuditRecord) -> Result<AuditEntry, StoreOpError> {
        let audit_key = self.audit_key.clone();
        self.fenced_write(|tx| append_audit_tx(tx, &audit_key, record))
            .map_err(StoreOpError::from)
    }

    /// Read the current audit-chain tip without scanning the chain.
    ///
    /// The sequence and entry MAC are returned together because the MAC binds the row at
    /// that sequence. A witness that records only the sequence cannot detect a truncated
    /// tail followed by fresh legitimate appends that reuse the same sequence number.
    /// Returns `None` when the audit chain is empty.
    pub fn audit_tip(&self) -> Result<Option<(i64, String)>, StoreOpError> {
        self.store
            .with_conn(|c| {
                c.query_row(
                    "SELECT seq, entry_mac FROM audit_log ORDER BY seq DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
            })
            .map_err(StoreOpError::from)
    }

    /// Read the audit chain (oldest first), capped at `limit` most-recent entries
    /// when `limit` is `Some`. Used by status/monitoring to surface alarms and by
    /// the integrity check.
    pub fn read_audit(&self, limit: Option<usize>) -> Result<Vec<AuditEntry>, StoreOpError> {
        self.store
            .with_conn(|c| {
                // Fetch newest-first with the cap, then reverse to chain order.
                let cap: i64 = limit.map(|n| n as i64).unwrap_or(-1); // -1 = no limit
                let mut stmt = c.prepare(
                    "SELECT seq, ts_ms, op, credential_id, payload_hash, actor, alarm, \
                            alarm_reason, prev_mac, entry_mac \
                     FROM audit_log ORDER BY seq DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map(rusqlite::params![cap], row_to_audit)?;
                let mut v = rows.collect::<rusqlite::Result<Vec<_>>>()?;
                v.reverse();
                Ok(v)
            })
            .map_err(StoreOpError::from)
    }

    /// Verify the full audit chain against the master-key-derived audit key.
    /// Returns the seq of the first broken entry, or `None` if it verifies.
    pub fn verify_audit_chain(&self) -> Result<Option<i64>, StoreOpError> {
        let entries = self.read_audit(None)?;
        Ok(audit::verify_chain(&self.audit_key, &entries))
    }

    // ---- master-key rotation --------------------------------------------

    /// Rotate the master key: re-wrap every record and the sealed audit key under
    /// `new_key`, swap every `key_id` column to the new fingerprint, and append a
    /// `RotateMasterKey` audit entry — ALL in ONE fenced transaction, so it is
    /// atomic (all-or-nothing). A `Fenced`/failed transaction leaves the OLD key
    /// opening everything (fail-closed); only post-commit is the old key dead.
    ///
    /// The caller MUST persist `new_key` to the key store BEFORE calling this, so a
    /// crash right after commit leaves the vault openable by the persisted new key.
    /// The audit_key VALUE is unchanged (only re-sealed), so the chain stays one
    /// continuously-verifiable sequence across the rotation; the `RotateMasterKey`
    /// entry is MAC'd with that stable audit key and chains cleanly.
    ///
    /// A record that fails to decrypt under the OLD key is already corrupt; it cannot be
    /// re-wrapped under the new key, so it is QUARANTINED (state flipped to `corrupt`)
    /// in the same transaction and its id is collected, rather than silently skipped
    /// while the rotation still reports success. Dropping the old key loses nothing
    /// further (the row was already unreadable), but marking it `corrupt` means the
    /// post-rotation health scan and the returned id list SURFACE it instead of leaving a
    /// still-old-key-sealed row behind a "success". The returned `Vec` is the quarantined
    /// ids (empty on a clean rotation) so the CLI can warn the operator.
    ///
    /// On success the store's in-memory key + key_id are swapped to the new key.
    pub fn rotate_master_key(&mut self, new_key: MasterKey) -> Result<Vec<String>, StoreOpError> {
        let old_key = &self.key;
        let new_key_id_hex = new_key.key_id().to_hex();
        let audit_key = self.audit_key.clone();

        // Re-seal the audit-key secret under the new key (value unchanged).
        let audit_binding = RecordBinding {
            credential_id: AUDIT_KEY_SECRET_NAME,
            record_version: AUDIT_KEY_RECORD_VERSION,
        };
        let new_audit_envelope =
            envelope::seal(&new_key, &*audit_key, &audit_binding).map_err(StoreOpError::Decrypt)?;

        let quarantined = self
            .fenced_write(|tx| {
                // Snapshot every record id + version + current envelope.
                let rows: Vec<(String, i64, Vec<u8>)> = {
                    let mut stmt = tx.prepare(
                        "SELECT credential_id, record_version, envelope FROM credentials",
                    )?;
                    let mapped = stmt.query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, Vec<u8>>(2)?,
                        ))
                    })?;
                    mapped.collect::<rusqlite::Result<Vec<_>>>()?
                };

                let mut quarantined: Vec<String> = Vec::new();
                for (id, version, old_blob) in rows {
                    let binding = RecordBinding {
                        credential_id: &id,
                        record_version: version as u64,
                    };
                    // Decrypt with the old key; a record that does not decrypt is already
                    // corrupt. It cannot be re-wrapped, so QUARANTINE it (flip to `corrupt`)
                    // in this same transaction and record its id — never leave a still-old-
                    // key row behind a reported success.
                    let plaintext = match envelope::open(old_key, &old_blob, &binding) {
                        Ok(pt) => pt,
                        Err(_) => {
                            tx.execute(
                                "UPDATE credentials SET state = ?2 WHERE credential_id = ?1",
                                rusqlite::params![id, RecordState::Corrupt.as_str()],
                            )?;
                            quarantined.push(id);
                            continue;
                        }
                    };
                    // Re-seal under the new key (same id + version => same AAD).
                    let new_blob = envelope::seal(&new_key, &plaintext, &binding)
                        .map_err(|_| rusqlite_err("re-seal under new key failed"))?;
                    tx.execute(
                        "UPDATE credentials SET envelope = ?2, key_id = ?3 \
                     WHERE credential_id = ?1",
                        rusqlite::params![id, new_blob, new_key_id_hex],
                    )?;
                }

                // Re-seal the audit-key secret row under the new key.
                tx.execute(
                    "UPDATE vault_secrets SET envelope = ?2, key_id = ?3 WHERE name = ?1",
                    rusqlite::params![AUDIT_KEY_SECRET_NAME, new_audit_envelope, new_key_id_hex],
                )?;

                // Append the vault-global RotateMasterKey entry (no credential_id),
                // MAC'd with the stable audit key so the chain stays continuous.
                append_audit_tx(
                    tx,
                    &audit_key,
                    &AuditRecord {
                        op: AuditOp::RotateMasterKey,
                        credential_id: None,
                        payload_hash: None,
                        actor: "offline-cli".to_string(),
                        alarm: Some(AlarmReason::AdminWrite),
                    },
                )?;
                Ok(quarantined)
            })
            .map_err(StoreOpError::from)?;

        // Commit succeeded: the new key now opens everything. Swap in-memory state.
        self.key_id = new_key.key_id();
        self.key = new_key;
        Ok(quarantined)
    }

    /// Seal a record into a cipher envelope bound to its id + version.
    fn seal_record(
        &self,
        credential_id: &str,
        record: &VaultRecord,
    ) -> Result<Vec<u8>, StoreOpError> {
        // An OAuth record may intentionally contain no access token while retaining a
        // refresh token; first use then refreshes it. Every non-OAuth credential is the
        // served payload itself, so sealing zero bytes would create a successful read
        // that downstreams can misdiagnose as an authentication failure.
        if record.kind != CredentialKind::Oauth && record.payload.is_empty() {
            return Err(StoreOpError::Encode(
                "non-OAuth credential payload must not be empty".into(),
            ));
        }
        // `Cookie` is a request header captured after the browser consumed Set-Cookie
        // attributes. It cannot disclose an expiry, so accepting a supplied timestamp
        // would persist an invented lifetime rather than an observed fact.
        //
        // IF YOU ARE HERE TO RELAX THIS REFUSAL, READ THE NEXT PARAGRAPH FIRST. There is
        // one capture path that makes a cookie expiry real -- a browser extension, where
        // `chrome.cookies.getAll` returns `expirationDate` uniformly on every platform
        // instead of being refused by App-Bound Encryption on Windows. If the desktop
        // surface adopts it, deleting this check is correct.
        //
        // WHAT MUST NOT FOLLOW: the field reaching a fetch or serve decision. A browser
        // `expirationDate` is an UPPER BOUND -- a session can be revoked server-side long
        // before it, and can outlive a conservative value -- so refusing on a passed
        // declaration takes a possibly-working session dark on the strength of metadata,
        // manufacturing an outage from a hint. The authoritative test is the request and
        // the authoritative answer is the provider's 401.
        //
        // A passed bound is strong evidence of death; a future bound rules re-capture out
        // as the likely fix; NEITHER proves the session is alive. That asymmetry is the
        // whole value, and it is diagnostic value: it sharpens what an operator is told
        // after a 401, and gates nothing. insula holds the mirror of this rule at its
        // consumption site (agreed with QTA 2026-08-28).
        //
        // The drift is a WELL-MEANING one, which is why it is written here rather than
        // left as an understanding between two seats: an implementer sees a stored expiry
        // and a request about to go out with an apparently-dead cookie, and adds the check
        // as an obvious improvement. Nothing fails. The operator quietly loses sessions
        // that were still working.
        if record.kind == CredentialKind::Cookie && record.expires_at_ms.is_some() {
            return Err(StoreOpError::Encode(
                "cookie credentials must not declare an expiry".into(),
            ));
        }
        let body = record
            .encode()
            .map_err(|e| StoreOpError::Encode(e.to_string()))?;
        let binding = RecordBinding {
            credential_id,
            record_version: record.record_version,
        };
        envelope::seal(&self.key, &body, &binding).map_err(StoreOpError::Decrypt)
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Delete a credential's refresh intent within an open transaction. Returns the
/// number of rows removed (0 if there was no intent). Used both standalone and as
/// the intent-clearing step folded into admin writes and the refresh commit.
fn clear_intent_tx(tx: &rusqlite::Transaction, credential_id: &str) -> rusqlite::Result<usize> {
    tx.execute(
        "DELETE FROM refresh_intent WHERE credential_id = ?1",
        rusqlite::params![credential_id],
    )
}

/// Load the vault's sealed audit key, or create it on a brand-new vault.
///
/// The audit key lives in `vault_secrets` under [`AUDIT_KEY_SECRET_NAME`], sealed
/// with the master key (AAD bound to that pseudo-id + version 0). On an existing
/// row: decrypt it (a wrong master key fails closed here). On no row: only create a
/// fresh CSPRNG key if the vault is genuinely EMPTY (no credentials, no audit
/// entries); otherwise the row's absence is corruption and we fail closed rather
/// than regenerate (which would orphan every existing audit entry).
fn load_or_create_audit_key(
    store: &SqliteStore,
    key: &MasterKey,
) -> Result<Zeroizing<[u8; 32]>, StoreOpError> {
    let binding = RecordBinding {
        credential_id: AUDIT_KEY_SECRET_NAME,
        record_version: AUDIT_KEY_RECORD_VERSION,
    };

    // Read the existing sealed audit-key envelope, if any.
    let existing: Option<Vec<u8>> = store
        .with_conn(|c| {
            c.query_row(
                "SELECT envelope FROM vault_secrets WHERE name = ?1",
                rusqlite::params![AUDIT_KEY_SECRET_NAME],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
        })
        .map_err(StoreOpError::from)?;

    if let Some(blob) = existing {
        // Decrypt with the master key — fail-closed on a wrong key (KeyMismatch) or
        // tampering, never a panic.
        let plaintext = envelope::open(key, &blob, &binding).map_err(StoreOpError::Decrypt)?;
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| StoreOpError::CorruptVault("audit key is not 32 bytes".to_string()))?;
        return Ok(Zeroizing::new(bytes));
    }

    // No audit-key row. Only a brand-new (empty) vault may create one.
    let non_empty: bool = store
        .with_conn(|c| {
            c.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials) OR EXISTS(SELECT 1 FROM audit_log)",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v != 0)
        })
        .map_err(StoreOpError::from)?;
    if non_empty {
        return Err(StoreOpError::CorruptVault(
            "audit key missing on a non-empty vault (refusing to regenerate)".to_string(),
        ));
    }

    // Brand-new vault: mint a fresh audit key and seal it under the master key.
    let audit_key = Zeroizing::new(
        crate::audit::generate_audit_key()
            .map_err(|_| StoreOpError::Store("csprng".to_string()))?,
    );
    let blob = envelope::seal(key, &*audit_key, &binding).map_err(StoreOpError::Decrypt)?;
    let key_id_hex = key.key_id().to_hex();
    store
        .with_conn_fenced(|tx| {
            tx.execute(
                "INSERT INTO vault_secrets (name, key_id, envelope) VALUES (?1, ?2, ?3)",
                rusqlite::params![AUDIT_KEY_SECRET_NAME, key_id_hex, blob],
            )?;
            Ok(())
        })
        .map_err(StoreOpError::from)?;
    Ok(audit_key)
}

/// Wrap a message as a rusqlite error so a non-sql failure inside a transaction
/// closure (e.g. an envelope seal failure during rotation) rolls the txn back.
fn rusqlite_err(msg: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
        Some(msg.to_string()),
    )
}

/// Lowercase-hex render of a 32-byte hash (the payload hash, for the audit entry).
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Hex SHA-256 of a raw capability handle — the only form of a handle the store
/// persists (a database leak yields no usable handle).
pub fn handle_hash(raw_handle: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"cortexkit-credentials/handle/v1");
    h.update(raw_handle.as_bytes());
    let digest = h.finalize();
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub(crate) fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        }
    }
    out
}

pub struct MintedHandle {
    pub raw: String,
    pub hash: String,
}

/// Mint a fresh capability handle: 256 CSPRNG bits as a `ckh_`-prefixed base64url
/// string. The raw value is returned once; only its hash is ever persisted.
pub fn mint_handle() -> Result<MintedHandle, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    let value = format!("ckh_{}", base64url(&bytes));
    let hash = handle_hash(&value);
    Ok(MintedHandle { raw: value, hash })
}

/// Append an audit entry within an open transaction: read the current tip mac,
/// compute this entry's mac over it, insert it. Used both standalone and folded
/// into a mutation's own transaction so the audit entry and the mutation commit
/// together. The single-writer lease guarantees no concurrent appender, so reading
/// the tip and inserting the next seq is race-free.
/// Verify the audit chain from a store file WITHOUT taking the single-writer lease.
///
/// Separate from [`EncryptedStore::verify_audit_chain`] for the reason that method
/// could never be used in production: opening an `EncryptedStore` acquires the lease,
/// so the tamper-evidence check required stopping the daemon. Nobody stops a vault to
/// run an integrity check, which means THE CHECK THAT JUSTIFIES THE HMAC CHAIN HAD
/// NEVER RUN ON THE LIVE STORE -- and a tamper-evidence mechanism nobody can afford to
/// invoke provides evidence of nothing.
///
/// The verification itself is a pure read: fetch the entries, recompute each MAC over
/// its predecessor. It needs the master key only to unseal the stored audit key, never
/// to write. `mode=ro` rather than `immutable=1`, so the newest entries -- still in the
/// WAL on a live store, and the ones an operator is usually asking about -- are seen.
///
/// Returns the seq of the first broken entry, or `None` when the chain verifies.
pub fn verify_audit_chain_read_only(
    store_path: &std::path::Path,
    key: &MasterKey,
) -> Result<Option<i64>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        format!("file:{}?mode=ro", store_path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map)?;

    // Unseal the audit key. Its absence is NOT an empty chain: it means this store was
    // never opened by a build that provisions one, and reporting "verified" for a store
    // whose key cannot be found would be the exact false green the chain exists to
    // prevent.
    let sealed: Vec<u8> = conn
        .query_row(
            "SELECT envelope FROM vault_secrets WHERE name = ?1",
            rusqlite::params![AUDIT_KEY_SECRET_NAME],
            |r| r.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreOpError::NotFound,
            other => map(other),
        })?;
    let binding = RecordBinding {
        credential_id: AUDIT_KEY_SECRET_NAME,
        record_version: AUDIT_KEY_RECORD_VERSION,
    };
    // A decrypt failure here is the WRONG KEY, not a broken chain: say so, because
    // "verification failed" would send an operator hunting tampering when the real
    // answer is that the vault is sealed under a different master key.
    let plain = envelope::open(key, &sealed, &binding).map_err(|e| {
        StoreOpError::from(StoreError::Backend(format!(
            "the audit key does not open under this master key ({e:?}) -- wrong key, \
             not a broken chain"
        )))
    })?;
    let audit_key: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| StoreOpError::from(StoreError::Backend("audit key length".into())))?;
    let audit_key = Zeroizing::new(audit_key);

    let mut stmt = conn
        .prepare(
            "SELECT seq, ts_ms, op, credential_id, payload_hash, actor, alarm, \
                    alarm_reason, prev_mac, entry_mac \
             FROM audit_log ORDER BY seq ASC",
        )
        .map_err(map)?;
    let entries = stmt
        .query_map([], row_to_audit)
        .map_err(map)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map)?;

    Ok(audit::verify_chain(&audit_key, &entries))
}

/// Credential ids whose diagnostic history is AT the retention cap, and has therefore
/// almost certainly been trimmed.
///
/// `auth_events` is capped per credential and the trim is a silent DELETE. That is the
/// right behaviour -- an unbounded diagnostic table on a path a hostile consumer can
/// drive is a disk-exhaustion lever -- but it leaves a reader unable to tell "this is
/// everything that happened" from "this is what survived". Those need different
/// responses: the first closes an investigation, the second says the evidence is gone
/// and the window has to be reconstructed another way.
///
/// At-cap is a heuristic and deliberately so: a credential sitting at exactly the cap
/// might never have been trimmed. Reporting a possible loss that did not happen costs
/// an operator one sentence; concealing one that did costs them the wrong conclusion.
pub fn auth_events_at_cap_read_only(
    store_path: &std::path::Path,
) -> Result<Vec<String>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        format!("file:{}?mode=ro", store_path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map)?;

    let mut stmt = conn
        .prepare(
            "SELECT credential_id FROM auth_events \
             GROUP BY credential_id HAVING COUNT(*) >= ?1 ORDER BY credential_id",
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(_, Some(ref m)) if m.contains("no such table") => {
                StoreOpError::NotFound
            }
            other => map(other),
        })?;
    let ids = stmt
        .query_map(rusqlite::params![AUTH_EVENTS_PER_CREDENTIAL as i64], |r| {
            r.get::<_, String>(0)
        })
        .map_err(map)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map)?;
    Ok(ids)
}

/// Read the audit chain from a store file WITHOUT a lease or a master key.
///
/// Every column here is plaintext -- seq, op, credential id, actor, alarm -- so unlike
/// [`verify_audit_chain_read_only`] this needs no key at all, only a read-only
/// connection.
///
/// Separate from [`EncryptedStore::read_audit`] for the same reason as the other
/// lease-free readers: the moment an operator asks what happened is the moment the
/// vault is running, and a forensic log that requires an outage to read is unavailable
/// exactly when it is wanted.
///
/// `limit` caps to the most recent N entries; `None` reads the whole chain. Returned
/// oldest-first, matching chain order.
pub fn read_audit_read_only(
    store_path: &std::path::Path,
    limit: Option<usize>,
) -> Result<Vec<AuditEntry>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        format!("file:{}?mode=ro", store_path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map)?;

    // Newest-first with the cap, then reversed into chain order -- the same shape as
    // the leased reader, so a capped read returns the RECENT entries rather than the
    // oldest ones.
    let cap: i64 = limit.map(|n| n as i64).unwrap_or(-1);
    let mut stmt = conn
        .prepare(
            "SELECT seq, ts_ms, op, credential_id, payload_hash, actor, alarm, \
                    alarm_reason, prev_mac, entry_mac \
             FROM audit_log ORDER BY seq DESC LIMIT ?1",
        )
        .map_err(map)?;
    let mut entries = stmt
        .query_map(rusqlite::params![cap], row_to_audit)
        .map_err(map)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map)?;
    entries.reverse();
    Ok(entries)
}

/// Read recent authentication events from a store file WITHOUT a lease or a key.
///
/// Separate from [`EncryptedStore::recent_auth_events`] because opening an
/// `EncryptedStore` acquires the single-writer lease, which requires the daemon
/// stopped. The moment an operator wants these rows is the moment a credential just
/// failed, i.e. while the vault is running -- a diagnostic that needs an outage to
/// read is useless exactly when it is needed.
///
/// Safe against a live vault: every column is plaintext (no envelope, so no master
/// key), and the connection is read-only, which also leaves the WAL untouched -- a
/// read-write open would checkpoint on close and rewrite the file being inspected.
///
/// `mode=ro` rather than `immutable=1`: immutable skips the write-ahead log, and
/// against a live store the newest events -- the ones being asked about -- are exactly
/// what is still in the WAL.
pub fn read_auth_events_read_only(
    store_path: &std::path::Path,
    limit: u32,
) -> Result<Vec<AuthEvent>, StoreOpError> {
    let map = |e: rusqlite::Error| StoreOpError::from(StoreError::Backend(e.to_string()));
    let conn = rusqlite::Connection::open_with_flags(
        format!("file:{}?mode=ro", store_path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map)?;

    // A MISSING TABLE IS NOT AN EMPTY ONE, and the caller has to be able to tell them
    // apart. The table arrived in a later migration, so a store written by an older
    // build has no `auth_events` at all -- and a running daemon does not migrate until
    // it restarts. Reported as its own outcome, because the raw sqlite "no such table"
    // reads like a broken install, and "no events" would be a lie: this vault cannot
    // record one yet.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'auth_events'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map_err(map)?
        != 0;
    if !table_exists {
        return Err(StoreOpError::NotFound);
    }

    let mut stmt = conn
        .prepare(auth_events_select(&conn).map_err(map)?)
        .map_err(map)?;
    let rows = stmt
        .query_map(rusqlite::params![limit], auth_event_from_row)
        .map_err(map)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(map)
}

/// The `auth_events` read, shared by both readers.
///
/// Kept beside [`auth_event_from_row`] because the two must agree on COLUMN ORDER:
/// the mapper addresses columns positionally, so reordering this list without
/// reordering the mapper compiles cleanly and returns wrong values silently. There
/// are two readers (leased and lease-free), and duplicating the pair would mean two
/// places that have to be changed together with nothing to catch a miss.
const AUTH_EVENTS_SELECT: &str =
    "SELECT ts_ms, credential_id, kind, provider_status, detail, reporter_source, record_version, applied, \
            principal_kind, principal_id \
     FROM auth_events ORDER BY seq DESC LIMIT ?1";

// A read-only CLI can run before the daemon has restarted to apply migration 4. Keep
// its existing diagnostics readable by projecting absent principal fields as NULL.
const AUTH_EVENTS_SELECT_PRE_PRINCIPAL: &str =
    "SELECT ts_ms, credential_id, kind, provider_status, detail, NULL AS reporter_source, record_version, applied, \
            NULL AS principal_kind, NULL AS principal_id \
     FROM auth_events ORDER BY seq DESC LIMIT ?1";

const AUTH_EVENTS_SELECT_PRE_REPORTER_SOURCE: &str =
    "SELECT ts_ms, credential_id, kind, provider_status, detail, NULL AS reporter_source, record_version, applied, \
            principal_kind, principal_id \
     FROM auth_events ORDER BY seq DESC LIMIT ?1";

fn auth_events_select(conn: &rusqlite::Connection) -> rusqlite::Result<&'static str> {
    let mut stmt = conn.prepare("PRAGMA table_info(auth_events)")?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_principal = columns.iter().any(|column| column == "principal_kind")
        && columns.iter().any(|column| column == "principal_id");
    let has_reporter_source = columns.iter().any(|column| column == "reporter_source");
    if has_principal && has_reporter_source {
        Ok(AUTH_EVENTS_SELECT)
    } else if has_principal {
        Ok(AUTH_EVENTS_SELECT_PRE_REPORTER_SOURCE)
    } else {
        Ok(AUTH_EVENTS_SELECT_PRE_PRINCIPAL)
    }
}

/// Decode one `auth_events` row. Positional, so it is bound to the column order in
/// [`AUTH_EVENTS_SELECT`] and [`AUTH_EVENTS_SELECT_PRE_PRINCIPAL`].
fn auth_event_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuthEvent> {
    Ok(AuthEvent {
        ts_ms: r.get(0)?,
        credential_id: r.get(1)?,
        kind: r.get(2)?,
        provider_status: r.get::<_, Option<i64>>(3)?.map(|s| s as u16),
        detail: r.get(4)?,
        reporter_source: r.get(5)?,
        record_version: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
        applied: r.get::<_, i64>(7)? != 0,
        principal_kind: r.get(8)?,
        principal_id: r.get(9)?,
    })
}

/// What a compound lifecycle transition and handle revocation actually changed.
///
/// Three separate facts rather than one boolean, because they drive different
/// operator advice: a credential that was already dead needs a DIFFERENT next step
/// (`remove`, or a re-login) from one this call just killed, and "handles revoked"
/// alone cannot distinguish them -- a credential with no handles reports zero in
/// both cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidateOutcome {
    /// The lifecycle state moved. False when it was already at the target or the
    /// transition deliberately refuses its current state.
    pub state_changed: bool,
    /// A dangling refresh intent was cleared.
    pub intent_cleared: bool,
    /// How many live handles were revoked.
    pub handles_revoked: usize,
}

impl InvalidateOutcome {
    /// Whether anything at all changed. A false answer is the one worth surfacing:
    /// it means the command reports success while the vault is exactly as it was.
    pub fn changed_anything(&self) -> bool {
        self.state_changed || self.intent_cleared || self.handles_revoked > 0
    }
}

/// One recorded authentication observation, as read back for diagnostics.
#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub ts_ms: i64,
    pub credential_id: String,
    pub kind: String,
    pub provider_status: Option<u16>,
    pub detail: Option<String>,
    /// Consumer-asserted, unverified; from `ReporterSource::as_str`, never raw consumer input.
    pub reporter_source: Option<String>,
    pub record_version: Option<u64>,
    /// Whether this observation actually changed the credential. False for a report
    /// against a superseded version, and for events that authorise no change.
    pub applied: bool,
    /// The caller's resolved principal kind for a scoped-read refusal. Older events
    /// and anonymous observations have no principal and remain `None`.
    pub principal_kind: Option<String>,
    /// The module id for a reserved principal. Unit principals such as `Direct` carry
    /// their full identity in `principal_kind`, so this remains `None` for them.
    pub principal_id: Option<String>,
}

/// The distinct internal reasons a principal-scoped read was refused. These values
/// are diagnostics only; the wire response remains uniformly `not_found`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedReadRefusal {
    NoGrant,
    NotFound,
    WrongKind,
    StoreError,
}

impl ScopedReadRefusal {
    fn as_str(self) -> &'static str {
        match self {
            ScopedReadRefusal::NoGrant => "no_grant",
            ScopedReadRefusal::NotFound => "not_found",
            ScopedReadRefusal::WrongKind => "wrong_kind",
            ScopedReadRefusal::StoreError => "store_error",
        }
    }
}

/// How many `auth_events` rows are kept per credential.
///
/// Sized for reading a single incident rather than a history: enough to show a
/// sequence of failures and what preceded them, small enough that a consumer stuck in
/// a retry loop cannot grow the store without bound. Older rows for that credential
/// are dropped as newer ones arrive.
///
/// SO THIS TABLE CANNOT ANSWER "HOW OFTEN DOES THIS CREDENTIAL FAIL", and that is a
/// consequence rather than a decision. The cap bounds ROWS, not TIME, so the window
/// it covers is a function of the failure rate itself: a credential that fails twice
/// a month retains a year, while one in a retry loop retains minutes. Any rate
/// computed from these rows is therefore biased toward whatever was failing most, and
/// a credential whose rows all survive is indistinguishable from one whose earlier
/// rows were evicted.
///
/// The audit chain is the place to ask about frequency: it is append-only, never
/// trimmed, and records every invalidation that actually changed a credential. This
/// table explains an incident; the chain counts them.
pub const AUTH_EVENTS_PER_CREDENTIAL: u32 = 64;

/// Render a changed GitHub installation grant as two ordered entitlement sets. A scope
/// whose level changed appears in both sets, so the direction is visible without asking
/// an operator to reconstruct it from whole JSON blobs.
fn github_app_permissions_change_detail(
    previous: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> String {
    let removed: BTreeSet<String> = previous
        .iter()
        .filter(|(scope, level)| current.get(*scope) != Some(*level))
        .map(|(scope, level)| format!("{scope}:{level}"))
        .collect();
    let added: BTreeSet<String> = current
        .iter()
        .filter(|(scope, level)| previous.get(*scope) != Some(*level))
        .map(|(scope, level)| format!("{scope}:{level}"))
        .collect();
    format!(
        "added=[{}]; removed=[{}]",
        added.into_iter().collect::<Vec<_>>().join(","),
        removed.into_iter().collect::<Vec<_>>().join(",")
    )
}

/// What a caller observed about a credential's authentication, for `auth_events`.
///
/// `detail` is either a typed variant name (`invalid_grant`, `transport`, `status`)
/// or a locally rendered diagnostic such as a GitHub grant diff. It must never be
/// provider response text: adapters carry raw bodies in their error values, and an OAuth
/// error body can echo submitted parameters, so writing one here would risk putting token
/// material in a plaintext column.
#[derive(Debug, Clone, Copy)]
pub struct AuthObservation<'a> {
    /// What kind of event this was, normally from [`AuthEventKind::as_str`]. Test
    /// fixtures may use a raw value to model legacy or unknown rows.
    pub kind: &'a str,
    /// The provider's HTTP status, when there was one.
    pub provider_status: Option<u16>,
    /// A typed variant or locally rendered safe metadata. Never response text.
    pub detail: Option<&'a str>,
    /// Consumer-asserted, unverified; raw consumer input is unrepresentable here.
    pub reporter_source: Option<ReporterSource>,
}

/// Append one `auth_events` row. Diagnostics only: not MAC-chained, prunable, and
/// nothing may depend on it being complete.
///
/// `applied` records whether the observation actually changed the credential, which is
/// what separates "a consumer reported a dead token and we marked it" from "a consumer
/// reported against a version we had already replaced".
pub(crate) fn append_auth_event_tx(
    tx: &rusqlite::Transaction,
    credential_id: &str,
    obs: &AuthObservation<'_>,
    record_version: Option<u64>,
    applied: bool,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO auth_events \
             (ts_ms, credential_id, kind, provider_status, detail, reporter_source, record_version, applied) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            now_ms(),
            credential_id,
            obs.kind,
            obs.provider_status.map(|s| s as i64),
            obs.detail,
            obs.reporter_source.map(ReporterSource::as_str),
            record_version.map(|v| v as i64),
            applied as i64,
        ],
    )?;
    trim_auth_events_tx(tx, credential_id)
}

// Every auth-event writer calls this in the insert transaction, so a repeated scoped
// read refusal cannot turn diagnostics into an unbounded durable write path.
fn trim_auth_events_tx(tx: &rusqlite::Transaction, credential_id: &str) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM auth_events \
         WHERE credential_id = ?1 AND seq NOT IN (\
             SELECT seq FROM auth_events WHERE credential_id = ?1 \
             ORDER BY seq DESC LIMIT ?2\
         )",
        rusqlite::params![credential_id, AUTH_EVENTS_PER_CREDENTIAL as i64],
    )?;
    Ok(())
}

pub(crate) fn append_audit_tx(
    tx: &rusqlite::Transaction,
    audit_key: &[u8; 32],
    record: &AuditRecord,
) -> rusqlite::Result<AuditEntry> {
    // An EMPTY audit table is the only reason to start from genesis (QueryReturnedNoRows
    // on the tip read). ANY OTHER query error (a broken/locked/damaged audit_log) must
    // propagate and fail the whole mutation's transaction — silently substituting genesis
    // would let a mutation commit against an unreadable chain, forking it. The
    // COALESCE(MAX(seq),0)+1 query returns a row even on an empty table, so it never hits
    // NoRows; only a real error surfaces there, and that too must propagate.
    let prev_mac: String = match tx.query_row(
        "SELECT entry_mac FROM audit_log ORDER BY seq DESC LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    ) {
        Ok(mac) => mac,
        Err(rusqlite::Error::QueryReturnedNoRows) => audit::GENESIS_MAC.to_string(),
        Err(e) => return Err(e),
    };

    let next_seq: i64 =
        tx.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log", [], |r| {
            r.get(0)
        })?;

    let ts_ms = now_ms();
    let op = record.op.as_str();
    let alarm = record.alarm.is_some();
    let alarm_reason = record.alarm.map(AlarmReason::as_str);
    let entry_mac = audit::compute_entry_mac(
        audit_key,
        &prev_mac,
        &audit::MacFields {
            seq: next_seq,
            ts_ms,
            op,
            credential_id: record.credential_id.as_deref(),
            payload_hash: record.payload_hash.as_deref(),
            actor: &record.actor,
            alarm,
            alarm_reason,
        },
    );

    tx.execute(
        "INSERT INTO audit_log \
         (seq, ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            next_seq,
            ts_ms,
            op,
            record.credential_id,
            record.payload_hash,
            record.actor,
            alarm as i64,
            alarm_reason,
            prev_mac,
            entry_mac,
        ],
    )?;

    Ok(AuditEntry {
        seq: next_seq,
        ts_ms,
        op: op.to_string(),
        credential_id: record.credential_id.clone(),
        payload_hash: record.payload_hash.clone(),
        actor: record.actor.clone(),
        alarm,
        alarm_reason: alarm_reason.map(String::from),
        prev_mac,
        entry_mac,
    })
}

fn row_to_audit(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        seq: row.get(0)?,
        ts_ms: row.get(1)?,
        op: row.get(2)?,
        credential_id: row.get(3)?,
        payload_hash: row.get(4)?,
        actor: row.get(5)?,
        alarm: row.get::<_, i64>(6)? != 0,
        alarm_reason: row.get(7)?,
        prev_mac: row.get(8)?,
        entry_mac: row.get(9)?,
    })
}

/// Build a [`RefreshIntent`] from a row of the standard intent column projection.
fn row_to_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<RefreshIntent> {
    Ok(RefreshIntent {
        credential_id: row.get(0)?,
        record_version: row.get::<_, i64>(1)? as u64,
        old_refresh_hash: row.get(2)?,
        lease_epoch: row.get::<_, i64>(3)? as u64,
        started_at_ms: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::MASTER_KEY_LEN;
    use crate::oauth::OAuthCredential;
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

    fn tmp_store(seed: u8) -> (std::path::PathBuf, EncryptedStore) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-cred-store-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let db = root.join("store.db");
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: db.to_string_lossy().into_owned(),
            },
        };
        let store = open_sqlite(&descriptor).expect("open");
        EncryptedStore::migrate(&store).expect("migrate");
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        (root, EncryptedStore::open(store, key).expect("open vault"))
    }

    /// Migration 6 must make old grants explicitly read-only while allowing a new
    /// sign grant for the same principal and prefix. Both facts are needed: a default
    /// can hide the backfill, and the old primary key would otherwise collapse the two
    /// independent authorities into one row.
    #[test]
    fn migration_six_backfills_existing_read_grants_without_blocking_sign_grants() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite");
        conn.execute_batch(
            "CREATE TABLE read_grants (\
                 principal_kind TEXT NOT NULL, \
                 principal_id TEXT NOT NULL, \
                 credential_prefix TEXT NOT NULL, \
                 created_at_ms INTEGER NOT NULL, \
                 PRIMARY KEY (principal_kind, principal_id, credential_prefix)\
             );",
        )
        .expect("create v5 grant table");
        for prefix in ["github_app:", "signing:agent-assertion:"] {
            conn.execute(
                "INSERT INTO read_grants \
                 (principal_kind, principal_id, credential_prefix, created_at_ms) \
                 VALUES ('reserved', 'prefrontal-core', ?1, 1)",
                [prefix],
            )
            .expect("seed legacy read grant");
        }

        let migration = MIGRATIONS
            .iter()
            .find(|migration| migration.version == 6)
            .expect("migration 6 exists");
        conn.execute_batch(migration.statements)
            .expect("apply migration 6");

        let mut statement = conn
            .prepare(
                "SELECT credential_prefix, operation FROM read_grants \
                 ORDER BY credential_prefix",
            )
            .expect("prepare backfill query");
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("query backfill rows")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode backfill rows");
        assert_eq!(
            rows,
            [
                ("github_app:".to_string(), "read".to_string()),
                ("signing:agent-assertion:".to_string(), "read".to_string()),
            ],
            "every legacy grant must remain a read grant after migration"
        );
        conn.execute(
            "INSERT INTO read_grants \
             (principal_kind, principal_id, credential_prefix, operation, created_at_ms) \
             VALUES ('reserved', 'prefrontal-core', 'signing:agent-assertion:', 'sign', 2)",
            [],
        )
        .expect("read and sign grants must coexist for one prefix");
    }

    /// Migration 7 adds only a nullable diagnostic column. In particular, it must not
    /// rewrite any audit transcript: audit MACs cover historical fixed fields and remain
    /// evidence for rows created before permission observations existed.
    #[test]
    fn migration_seven_preserves_existing_rows_and_audit_macs() {
        let conn = rusqlite::Connection::open_in_memory().expect("open sqlite");
        conn.execute_batch(
            "CREATE TABLE credentials (\
                 credential_id TEXT PRIMARY KEY, \
                 record_version INTEGER NOT NULL, \
                 key_id TEXT NOT NULL, \
                 state TEXT NOT NULL, \
                 envelope BLOB NOT NULL, \
                 updated_at_ms INTEGER NOT NULL, \
                 stale_pending INTEGER NOT NULL DEFAULT 0\
             ); \
             CREATE TABLE audit_log (\
                 seq INTEGER PRIMARY KEY AUTOINCREMENT, \
                 ts_ms INTEGER NOT NULL, \
                 op TEXT NOT NULL, \
                 credential_id TEXT, \
                 payload_hash TEXT, \
                 actor TEXT NOT NULL, \
                 alarm INTEGER NOT NULL DEFAULT 0, \
                 alarm_reason TEXT, \
                 prev_mac TEXT NOT NULL, \
                 entry_mac TEXT NOT NULL\
             );",
        )
        .expect("create v6 tables");
        conn.execute(
            "INSERT INTO credentials \
                 (credential_id, record_version, key_id, state, envelope, updated_at_ms, stale_pending) \
             VALUES ('github-app', 4, 'old-key', 'active', X'010203', 99, 1)",
            [],
        )
        .expect("seed legacy credential");
        for (seq, mac) in [(1, "mac-before"), (2, "mac-after")] {
            conn.execute(
                "INSERT INTO audit_log \
                     (seq, ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac) \
                 VALUES (?1, 7, 'put', 'github-app', 'hash', 'vault', 0, NULL, 'previous', ?2)",
                rusqlite::params![seq, mac],
            )
            .expect("seed historical audit entry");
        }
        let credential_before: (i64, String, String, Vec<u8>, i64, i64) = conn
            .query_row(
                "SELECT record_version, key_id, state, envelope, updated_at_ms, stale_pending \
                 FROM credentials WHERE credential_id = 'github-app'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("read legacy credential");
        let macs_before = conn
            .prepare("SELECT entry_mac FROM audit_log ORDER BY seq")
            .expect("prepare audit MAC read")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("read audit MACs")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode audit MACs");

        let migration = MIGRATIONS
            .iter()
            .find(|migration| migration.version == 7)
            .expect("migration 7 exists");
        conn.execute_batch(migration.statements)
            .expect("apply migration 7 to a populated v6 store");

        let credential_after: (i64, String, String, Vec<u8>, i64, i64, Option<String>) = conn
            .query_row(
                "SELECT record_version, key_id, state, envelope, updated_at_ms, stale_pending, \
                        last_github_app_permissions \
                 FROM credentials WHERE credential_id = 'github-app'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .expect("read migrated credential");
        assert_eq!(
            (
                &credential_after.0,
                &credential_after.1,
                &credential_after.2,
                &credential_after.3,
                &credential_after.4,
                &credential_after.5,
            ),
            (
                &credential_before.0,
                &credential_before.1,
                &credential_before.2,
                &credential_before.3,
                &credential_before.4,
                &credential_before.5,
            ),
            "adding diagnostic metadata must not alter an existing credential row"
        );
        assert!(
            credential_after.6.is_none(),
            "a legacy credential has no synthetic first observation"
        );
        let macs_after = conn
            .prepare("SELECT entry_mac FROM audit_log ORDER BY seq")
            .expect("prepare post-migration audit MAC read")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("read post-migration audit MACs")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("decode post-migration audit MACs");
        assert_eq!(
            macs_after, macs_before,
            "migration 7 must leave every historical audit MAC byte-identical"
        );
    }

    /// EVERY write path refuses an empty non-OAuth payload, not merely the one that
    /// happens to be covered elsewhere.
    ///
    /// The guard lives in `seal_record` -- a chokepoint every writer passes through --
    /// rather than in `VaultRecord::new_static`, which only debug_asserts the KIND. That
    /// is the right shape, because a constructor is sidesteppable by a struct literal
    /// and a chokepoint is not. But "every writer passes through it" is a claim about
    /// the call graph, and that is precisely the kind of claim that stops being true
    /// quietly.
    ///
    /// So this enumerates the writers rather than trusting the chokepoint. Prompted by
    /// the sibling defect in a peer's code: an invariant stated explicitly in one arm of
    /// a function and silently inherited in the other, where the CORRECT arm is what
    /// makes the incorrect one invisible to a reader.
    #[test]
    fn every_write_path_refuses_an_empty_non_oauth_payload() {
        let (_root, store) = tmp_store(0x5A);
        let empty = VaultRecord::new_static(CredentialKind::ApiKey, "test", Vec::new(), None);

        assert!(
            store.create("apikey:empty", &empty).is_err(),
            "create must refuse an empty payload"
        );
        assert!(
            store
                .create_audited("apikey:empty", &empty, AuditCtx::admin(AuditOp::Put))
                .is_err(),
            "create_audited must refuse an empty payload"
        );

        // Seed a good record, then try to REPLACE it with an empty one. The replace
        // paths are the dangerous ones: overwriting a working credential with zero bytes
        // reads downstream as an authentication failure rather than as corruption.
        let good = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"real".to_vec(), None);
        store.create("apikey:one", &good).expect("seed");
        assert!(
            store
                .overwrite_unconditional_audited(
                    "apikey:one",
                    &empty,
                    AuditCtx::admin(AuditOp::Put)
                )
                .is_err(),
            "overwrite_unconditional_audited must refuse an empty payload"
        );

        // POSITIVE ARM: the seeded record survives the refused write. A refusal that
        // damaged the row on its way out would satisfy every assertion above.
        let loaded = store.get("apikey:one").expect("reload the seeded record");
        assert_eq!(
            loaded.payload,
            b"real".to_vec(),
            "a refused write must leave the existing record untouched"
        );
    }

    fn oauth_record() -> VaultRecord {
        VaultRecord::new_oauth(
            "opencode",
            "anthropic",
            OAuthCredential {
                access_token: "access".into(),
                refresh_token: "refresh".into(),
                expires_at_ms: Some(9_999),
                token_url: "https://t.test/token".into(),
                client_id: Some("c".into()),
                scopes: vec!["scope-a".into(), "scope-b".into()],
            },
            b"payload-bytes".to_vec(),
        )
    }

    /// The usable-scan reads a REAL sealed store and reaches its stranded arm.
    ///
    /// `is_serviceable` is unit-tested on hand-built credentials, which proves the
    /// predicate and nothing about whether the scan wires it to the bytes on disk. This
    /// seals records through the ordinary write path and reads them back through the
    /// lease-free scan, so a scan that mislabelled every record -- or never called the
    /// predicate -- fails here.
    #[test]
    fn the_usable_scan_reaches_its_stranded_arm_on_a_real_store() {
        use crate::usable::{scan, Usability};

        let (root, store) = tmp_store(41);
        store.create("good:oauth", &oauth_record()).expect("create");

        // An OAuth record with neither token: the state that needs an operator login
        // and that no metadata read can see.
        let mut dead = oauth_record();
        if let Some(o) = dead.oauth.as_mut() {
            o.access_token = String::new();
            o.refresh_token = String::new();
        }
        store.create("dead:oauth", &dead).expect("create stranded");

        // tmp_store derives its key from the seed, so the scan can reconstruct the
        // same one without an accessor that would exist only for tests.
        let key = MasterKey::from_bytes([41u8; MASTER_KEY_LEN]);
        drop(store); // release the single-writer lease before the read-only open

        let conn = crate::usable::open_store_read_only(&root.join("store.db")).expect("open ro");
        let rows = scan(&conn, &key).expect("scan");

        let dead_row = rows
            .iter()
            .find(|r| r.credential_id == "dead:oauth")
            .expect("the stranded record is in the report");
        assert_eq!(
            dead_row.usability,
            Usability::Stranded,
            "an oauth record with neither token is stranded"
        );

        // DISAMBIGUATOR: a scan that marked everything stranded would satisfy the
        // assertion above. The healthy record must come back serviceable.
        let good_row = rows
            .iter()
            .find(|r| r.credential_id == "good:oauth")
            .expect("the healthy record is in the report");
        assert!(
            matches!(good_row.usability, Usability::Serviceable { .. }),
            "a record with both tokens is serviceable, got {:?}",
            good_row.usability
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_then_get_round_trips() {
        let (root, store) = tmp_store(1);
        store
            .create("opencode:anthropic", &oauth_record())
            .expect("create");
        let got = store.get("opencode:anthropic").expect("get");
        assert_eq!(got.payload, b"payload-bytes");
        assert_eq!(got.record_version, 1);
        assert_eq!(got.oauth.unwrap().access_token, "access");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn create_only_rejects_duplicate() {
        let (root, store) = tmp_store(2);
        store.create("id", &oauth_record()).expect("first create");
        match store.create("id", &oauth_record()) {
            Err(StoreOpError::AlreadyExists) => {}
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `retire_and_revoke_all_audited` is the compound behind `ck auth logout`:
    /// mark `retired`, clear any dangling intent, and revoke EVERY live handle, all in
    /// one fenced transaction with both audit entries inside it.
    ///
    /// The compound exists because doing it as two calls is crash-partial: a crash
    /// between them leaves a dead credential still resolvable by handle — a token the
    /// operator believes is withdrawn but which still serves. So the assertions below
    /// pin all four effects TOGETHER, plus the reversibility that distinguishes logout
    /// from `remove`: the row and its audit history survive.
    #[test]
    fn logout_retires_clears_intent_and_revokes_every_handle_atomically() {
        let (root, store) = tmp_store(2);
        store.create("out", &oauth_record()).expect("create out");
        store.create("keep", &oauth_record()).expect("create keep");
        // TWO live handles: "revoke all" is only meaningful past the first, and a loop
        // that stopped after one would otherwise pass.
        let live: Vec<_> = (0..2)
            .map(|_| {
                let h = mint_handle().expect("mint");
                store
                    .put_handle_hash(&h.hash, "out", AuditCtx::vault(AuditOp::MintHandle))
                    .expect("store handle");
                h.raw
            })
            .collect();
        let sibling = mint_handle().expect("mint");
        store
            .put_handle_hash(&sibling.hash, "keep", AuditCtx::vault(AuditOp::MintHandle))
            .expect("store sibling handle");
        store.open_intent("out", 1, "rhash").expect("open intent");

        let outcome = store
            .retire_and_revoke_all_audited("out", AuditCtx::admin(AuditOp::Invalidate))
            .expect("logout");
        assert_eq!(
            outcome.handles_revoked, 2,
            "every live handle must be revoked, not just one"
        );
        assert!(
            outcome.state_changed,
            "a live credential's state must report as changed"
        );

        // All four effects, together.
        assert_eq!(
            store.meta("out").expect("meta").state,
            RecordState::Retired,
            "logout must record an intentional retirement rather than a failure"
        );
        assert!(
            store.read_intent("out").expect("read intent").is_none(),
            "a dangling refresh intent must be cleared in the same transaction"
        );
        for (i, raw) in live.iter().enumerate() {
            assert!(
                matches!(store.resolve_handle(raw), Err(StoreOpError::NotFound)),
                "handle {i} must no longer resolve"
            );
        }
        // The sibling is untouched: logout is scoped to one credential.
        assert_eq!(store.meta("keep").expect("meta").state, RecordState::Active);
        assert_eq!(
            store
                .resolve_handle(&sibling.raw)
                .expect("sibling resolves"),
            "keep"
        );

        // REVERSIBILITY \u2014 what makes this `logout` and not `remove`: the row and its
        // history are still there, so a later replace restores service.
        let entries = store.read_audit(None).expect("read audit");
        assert!(
            entries
                .iter()
                .any(|e| e.op == "invalidate" && e.credential_id.as_deref() == Some("out")),
            "the invalidate must be audited"
        );
        assert!(
            entries
                .iter()
                .any(|e| e.op == "revoke_handle" && e.credential_id.as_deref() == Some("out")),
            "the handle revocation must be audited in the same transaction"
        );
        store
            .verify_audit_chain()
            .expect("chain verifies after logout");
        store
            .overwrite_unconditional_audited("out", &oauth_record(), AuditCtx::admin(AuditOp::Put))
            .expect("a logged-out credential can be restored");
        assert_eq!(
            store.meta("out").expect("meta").state,
            RecordState::Active,
            "logout must be reversible"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Retiring a failed credential is an operator acknowledgement that clears the
    /// health alarm without deleting the stored material.
    #[test]
    fn logout_retires_needs_reauth_and_clears_its_health_alarm() {
        let (root, store) = tmp_store(4);
        store.create("retire-me", &oauth_record()).expect("create");
        store.invalidate("retire-me").expect("invalidate");

        let before = crate::health::VaultHealth::summarize(
            &store.list_meta().expect("list before retirement"),
            0,
            false,
        );
        assert_eq!(before.status, crate::health::VaultHealthStatus::Degraded);

        let outcome = store
            .retire_and_revoke_all_audited("retire-me", AuditCtx::admin(AuditOp::Invalidate))
            .expect("retire needs_reauth");
        assert!(
            outcome.state_changed,
            "needs_reauth must transition to retired"
        );
        assert_eq!(
            store.meta("retire-me").expect("retired meta").state,
            RecordState::Retired
        );

        let after = crate::health::VaultHealth::summarize(
            &store.list_meta().expect("list after retirement"),
            0,
            false,
        );
        assert_eq!(after.status, crate::health::VaultHealthStatus::Ok);
        assert_eq!(after.retired_ids, vec!["retire-me".to_string()]);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `remove_audited` permanently deletes the row + intent + handle rows in one
    /// fenced transaction, appends a `remove` audit entry, and frees the id for a
    /// future create. A missing id is a loud NotFound, and removal must not disturb
    /// other credentials.
    #[test]
    fn remove_deletes_row_handles_and_intent_and_frees_the_id() {
        let (root, store) = tmp_store(2);
        store.create("keep", &oauth_record()).expect("create keep");
        store.create("gone", &oauth_record()).expect("create gone");
        store
            .put_handle_hash("deadbeef", "gone", AuditCtx::vault(AuditOp::MintHandle))
            .expect("mint handle");
        store.open_intent("gone", 1, "rhash").expect("open intent");
        // Diagnostic events for both, so removal can be shown to take one and spare
        // the other. These are the only rows in the store with no other reclaim path:
        // the per-credential cap trims on INSERT, and a removed credential never gets
        // another insert.
        for id in ["gone", "keep"] {
            store
                .record_auth_event(
                    id,
                    AuthObservation {
                        kind: "consumer_report",
                        provider_status: Some(401),
                        detail: None,
                        reporter_source: None,
                    },
                    Some(1),
                )
                .expect("record event");
        }

        // Unknown id: loud NotFound, nothing audited for it.
        match store.remove_audited("nope", AuditCtx::vault(AuditOp::Remove)) {
            Err(StoreOpError::NotFound) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }

        store
            .remove_audited("gone", AuditCtx::vault(AuditOp::Remove))
            .expect("remove");

        // Row gone, intent gone, handle unresolvable; sibling untouched.
        assert!(matches!(store.meta("gone"), Err(StoreOpError::NotFound)));
        assert!(store.read_intent("gone").expect("read intent").is_none());
        assert!(store.meta("keep").is_ok());
        // Diagnostics went with it, and ONLY its own: a removal that swept the table
        // would take the history of every credential still in service.
        let events = store.recent_auth_events(100).expect("read events");
        assert!(
            !events.iter().any(|e| e.credential_id == "gone"),
            "a removed credential's events must go with it -- nothing else can reclaim them"
        );
        assert_eq!(
            events.iter().filter(|e| e.credential_id == "keep").count(),
            1,
            "a sibling credential's events must survive the removal"
        );
        // The audit chain records the removal and still verifies end-to-end.
        let entries = store.read_audit(None).expect("read audit");
        let last = entries.last().expect("has entries");
        assert_eq!(last.op, "remove");
        assert_eq!(last.credential_id.as_deref(), Some("gone"));
        store
            .verify_audit_chain()
            .expect("chain verifies after remove");
        // The id is free for a NEW credential (fresh v1 chain).
        store.create("gone", &oauth_record()).expect("recreate");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unconditional_overwrite_replaces_needs_reauth_record_and_keeps_handle() {
        let (root, store) = tmp_store(20);
        // A credential imported from the wrong source whose refresh token is dead:
        // mark it needs_reauth (as a failed refresh would), and mint a handle for it.
        store.create("opencode:google", &oauth_record()).unwrap();
        let h = mint_handle().unwrap();
        store
            .put_handle_hash(
                &h.hash,
                "opencode:google",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .unwrap();
        store.invalidate("opencode:google").unwrap();
        // A CAS overwrite cannot even read it (get on a needs_reauth row fails closed).
        assert!(matches!(
            store.get("opencode:google"),
            Err(StoreOpError::NeedsReauth)
        ));
        // The unconditional overwrite (the --replace path) replaces it regardless of
        // state, resets it to active, and is immediately gettable again.
        store
            .overwrite_unconditional_audited(
                "opencode:google",
                &oauth_record(),
                AuditCtx::admin(AuditOp::Import),
            )
            .unwrap();
        let rec = store.get("opencode:google").expect("active after replace");
        assert!(rec.record_version >= 2, "version bumped past the original");
        // The pre-existing handle STILL resolves to the same id — no re-mint needed.
        assert_eq!(
            store.resolve_handle(&h.raw).unwrap(),
            "opencode:google",
            "handle survives the replace"
        );
        // Replacing an ABSENT id is NotFound (not a silent create).
        assert!(matches!(
            store.overwrite_unconditional_audited(
                "nope",
                &oauth_record(),
                AuditCtx::admin(AuditOp::Import)
            ),
            Err(StoreOpError::NotFound)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unconditional_overwrite_preserves_existing_identity_when_incoming_has_none() {
        use crate::record::RecordIdentity;

        let (root, store) = tmp_store(24);
        let existing = oauth_record().with_identity(RecordIdentity {
            account_id: Some("acct-original".to_string()),
            email: Some("original@example.com".to_string()),
            org_name: Some("Original Organization".to_string()),
        });
        store.create("oauth:anthropic", &existing).expect("create");

        store
            .overwrite_unconditional_audited(
                "oauth:anthropic",
                &oauth_record(),
                AuditCtx::admin(AuditOp::Import),
            )
            .expect("replace");

        assert_eq!(
            store.get("oauth:anthropic").expect("read").identity,
            existing.identity,
            "a token-only re-import must retain the account identity already attached to the id"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unconditional_overwrite_uses_an_incoming_identity_in_preference_to_existing() {
        use crate::record::RecordIdentity;

        let (root, store) = tmp_store(25);
        let existing = oauth_record().with_identity(RecordIdentity {
            account_id: Some("acct-original".to_string()),
            email: Some("original@example.com".to_string()),
            org_name: None,
        });
        let incoming = oauth_record().with_identity(RecordIdentity {
            account_id: Some("acct-replacement".to_string()),
            email: Some("replacement@example.com".to_string()),
            org_name: Some("Replacement Organization".to_string()),
        });
        store.create("oauth:anthropic", &existing).expect("create");

        store
            .overwrite_unconditional_audited(
                "oauth:anthropic",
                &incoming,
                AuditCtx::admin(AuditOp::Import),
            )
            .expect("replace");

        assert_eq!(
            store.get("oauth:anthropic").expect("read").identity,
            incoming.identity,
            "explicit import identity must replace stale account metadata"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unconditional_overwrite_keeps_an_identity_empty_when_both_records_lack_one() {
        let (root, store) = tmp_store(26);
        store
            .create("oauth:anthropic", &oauth_record())
            .expect("create");

        store
            .overwrite_unconditional_audited(
                "oauth:anthropic",
                &oauth_record(),
                AuditCtx::admin(AuditOp::Import),
            )
            .expect("replace");

        assert!(
            store
                .get("oauth:anthropic")
                .expect("read")
                .identity
                .is_empty(),
            "a replacement cannot synthesize identity where neither record supplied it"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unconditional_overwrite_can_explicitly_clear_existing_identity() {
        use crate::record::RecordIdentity;

        let (root, store) = tmp_store(27);
        let existing = oauth_record().with_identity(RecordIdentity {
            account_id: Some("acct-original".to_string()),
            email: Some("original@example.com".to_string()),
            org_name: None,
        });
        store.create("oauth:anthropic", &existing).expect("create");

        store
            .overwrite_unconditional_with_identity_policy_audited(
                "oauth:anthropic",
                &oauth_record(),
                false,
                AuditCtx::admin(AuditOp::Import),
            )
            .expect("replace with clear");

        assert!(
            store
                .get("oauth:anthropic")
                .expect("read")
                .identity
                .is_empty(),
            "an explicit clear must not be mistaken for token-only replace preservation"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unconditional_overwrite_repairs_a_corrupt_record_without_inventing_identity() {
        use crate::record::RecordIdentity;

        let (root, store) = tmp_store(28);
        let existing = oauth_record().with_identity(RecordIdentity {
            account_id: Some("acct-original".to_string()),
            email: Some("original@example.com".to_string()),
            org_name: None,
        });
        store.create("oauth:anthropic", &existing).expect("create");
        store
            .with_raw_conn(|conn| {
                conn.execute(
                    "UPDATE credentials SET envelope = X'00' WHERE credential_id = 'oauth:anthropic'",
                    [],
                )
            })
            .expect("corrupt envelope");

        store
            .overwrite_unconditional_audited(
                "oauth:anthropic",
                &oauth_record(),
                AuditCtx::admin(AuditOp::Import),
            )
            .expect("repair replace");

        assert!(
            store
                .get("oauth:anthropic")
                .expect("read repaired record")
                .identity
                .is_empty(),
            "a corrupt record cannot supply identity, but it must not block token repair"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn identity_writes_reject_empty_and_control_character_account_ids() {
        use crate::record::RecordIdentity;

        let (root, store) = tmp_store(56);
        store
            .create("oauth:anthropic", &oauth_record())
            .expect("seed record");
        let empty = store
            .set_identity_audited(
                "oauth:anthropic",
                RecordIdentity {
                    account_id: Some(String::new()),
                    email: None,
                    org_name: None,
                },
                AuditCtx::admin(AuditOp::SetIdentity),
            )
            .expect_err("empty account id must be rejected at the store sink");
        assert!(
            matches!(empty, StoreOpError::Encode(ref message) if message.contains("account_id")),
            "the returned error must name the invalid non-secret field: {empty}"
        );

        let control_record = oauth_record().with_identity(RecordIdentity {
            account_id: Some("acct\u{0007}bad".to_string()),
            email: None,
            org_name: None,
        });
        let control = store
            .overwrite_unconditional_audited(
                "oauth:anthropic",
                &control_record,
                AuditCtx::admin(AuditOp::Import),
            )
            .expect_err("control characters must be rejected for replacement identity too");
        assert!(
            matches!(control, StoreOpError::Encode(ref message) if message.contains("account_id")),
            "the returned error must name the invalid non-secret field: {control}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_identity_reseals_same_oauth_material_and_audits_the_metadata_change() {
        use crate::record::RecordIdentity;

        let (root, store) = tmp_store(29);
        let existing = oauth_record();
        let payload_before = existing.payload.clone();
        let oauth_before = existing.oauth.clone();
        store.create("oauth:anthropic", &existing).expect("create");
        let handle = mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:anthropic",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store handle");
        store
            .with_raw_conn(|conn| {
                conn.execute(
                    "UPDATE credentials SET stale_pending = 1 WHERE credential_id = 'oauth:anthropic'",
                    [],
                )
            })
            .expect("seed stale marker");
        let version_before = store.meta("oauth:anthropic").expect("meta").record_version;

        store
            .set_identity_audited(
                "oauth:anthropic",
                RecordIdentity {
                    account_id: Some("acct-set".to_string()),
                    email: Some("set@example.com".to_string()),
                    org_name: Some("Set Organization".to_string()),
                },
                AuditCtx::admin(AuditOp::SetIdentity),
            )
            .expect("set identity");

        let record = store.get("oauth:anthropic").expect("read");
        let meta = store.meta("oauth:anthropic").expect("meta");
        assert_eq!(
            record.payload, payload_before,
            "identity must not rotate payload bytes"
        );
        assert_eq!(
            record.oauth, oauth_before,
            "identity must not replace OAuth material"
        );
        assert_eq!(record.identity.account_id.as_deref(), Some("acct-set"));
        assert_eq!(
            meta.state,
            RecordState::Active,
            "identity must not alter lifecycle state"
        );
        assert_eq!(
            meta.record_version,
            version_before + 1,
            "re-sealing advances version"
        );
        assert!(
            meta.stale_pending,
            "identity-only writes must not clear a consumer's pending refresh verdict"
        );
        assert_eq!(
            store.resolve_handle(&handle.raw).expect("resolve handle"),
            "oauth:anthropic",
            "identity-only writes must retain existing capability handles"
        );
        assert_eq!(
            store
                .read_audit(None)
                .expect("audit")
                .last()
                .expect("entry")
                .op,
            "set_identity"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_identity_allows_a_decryptable_needs_reauth_record() {
        use crate::record::RecordIdentity;

        let (root, store) = tmp_store(30);
        store
            .create("oauth:anthropic", &oauth_record())
            .expect("create");
        store.invalidate("oauth:anthropic").expect("invalidate");

        store
            .set_identity_audited(
                "oauth:anthropic",
                RecordIdentity {
                    account_id: Some("acct-labelled".to_string()),
                    email: None,
                    org_name: None,
                },
                AuditCtx::admin(AuditOp::SetIdentity),
            )
            .expect("set identity while needs reauth");
        assert_eq!(
            store.meta("oauth:anthropic").expect("meta").state,
            RecordState::NeedsReauth,
            "identity metadata must not reactivate the credential"
        );
        store
            .reactivate_audited("oauth:anthropic", AuditCtx::admin(AuditOp::Reactivate))
            .expect("reactivate");
        assert_eq!(
            store
                .get("oauth:anthropic")
                .expect("read after reactivation")
                .identity
                .account_id
                .as_deref(),
            Some("acct-labelled")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_static_payload_is_rejected_before_any_write_or_audit() {
        let (_root, store) = tmp_store(42);
        let empty = VaultRecord::new_static(CredentialKind::ApiKey, "test", Vec::new(), None);

        let audit_before = store.read_audit(None).expect("audit before").len();
        assert!(store.create("apikey:empty", &empty).is_err());
        assert!(matches!(
            store.meta("apikey:empty"),
            Err(StoreOpError::NotFound)
        ));
        assert_eq!(
            store.read_audit(None).expect("audit after create").len(),
            audit_before
        );

        let valid =
            VaultRecord::new_static(CredentialKind::ApiKey, "test", b"non-empty".to_vec(), None);
        store.create("apikey:kept", &valid).expect("seed valid");
        let before = store.get("apikey:kept").expect("read seed");
        let audit_before_overwrites = store.read_audit(None).expect("audit seeded").len();

        assert!(store
            .overwrite_cas("apikey:kept", &empty, &payload_hash(&before.payload),)
            .is_err());
        let after_cas = store.get("apikey:kept").expect("read after CAS refusal");
        assert_eq!(after_cas.record_version, before.record_version);
        assert_eq!(after_cas.payload, before.payload);
        assert_eq!(
            store.read_audit(None).expect("audit after CAS").len(),
            audit_before_overwrites
        );

        assert!(store
            .overwrite_unconditional_audited("apikey:kept", &empty, AuditCtx::admin(AuditOp::Put),)
            .is_err());
        let after_unconditional = store
            .get("apikey:kept")
            .expect("read after unconditional refusal");
        assert_eq!(after_unconditional.record_version, before.record_version);
        assert_eq!(after_unconditional.payload, before.payload);
        assert_eq!(
            store
                .read_audit(None)
                .expect("audit after unconditional")
                .len(),
            audit_before_overwrites
        );
    }

    #[test]
    fn refresh_only_oauth_record_may_be_stored_empty() {
        let (_root, store) = tmp_store(43);
        let record = VaultRecord::new_oauth(
            "import",
            "anthropic",
            OAuthCredential {
                access_token: String::new(),
                refresh_token: "refresh-only".into(),
                expires_at_ms: None,
                token_url: "https://t.test/token".into(),
                client_id: Some("c".into()),
                scopes: vec![],
            },
            Vec::new(),
        );
        assert!(record.payload.is_empty());
        assert!(!record
            .oauth
            .as_ref()
            .expect("oauth")
            .refresh_token
            .is_empty());

        store
            .create("oauth:refresh-only", &record)
            .expect("refresh-only OAuth must remain storable");
        assert!(store
            .get("oauth:refresh-only")
            .expect("read refresh-only")
            .payload
            .is_empty());
    }

    #[test]
    fn version_gated_quarantine_cannot_poison_a_replacement() {
        let (_root, store) = tmp_store(44);
        let original =
            VaultRecord::new_static(CredentialKind::ApiKey, "test", b"original".to_vec(), None);
        store.create("apikey:race", &original).expect("seed");
        let replacement = VaultRecord::new_static(
            CredentialKind::ApiKey,
            "test",
            b"replacement".to_vec(),
            None,
        );
        store
            .overwrite_unconditional_audited(
                "apikey:race",
                &replacement,
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("replace");

        assert!(!store
            .quarantine_if_version("apikey:race", 1)
            .expect("stale quarantine CAS"));
        let kept = store.get("apikey:race").expect("replacement stays active");
        assert_eq!(kept.record_version, 2);
        assert_eq!(kept.payload, b"replacement");
        assert!(store
            .quarantine_if_version("apikey:race", 2)
            .expect("current quarantine CAS"));
        assert_eq!(
            store.meta("apikey:race").expect("meta").state,
            RecordState::Corrupt
        );
    }

    #[test]
    fn get_missing_is_not_found() {
        let (root, store) = tmp_store(3);
        match store.get("absent") {
            Err(StoreOpError::NotFound) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn overwrite_cas_matches_and_bumps_version() {
        let (root, store) = tmp_store(4);
        store.create("id", &oauth_record()).expect("create");
        let cur = store.get("id").expect("get");
        let expect = payload_hash(&cur.payload);
        let mut next = oauth_record();
        next.payload = b"new-payload".to_vec();
        store.overwrite_cas("id", &next, &expect).expect("cas ok");
        let got = store.get("id").expect("get after cas");
        assert_eq!(got.payload, b"new-payload");
        assert_eq!(got.record_version, 2, "version bumped on overwrite");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn overwrite_cas_mismatch_rejected() {
        let (root, store) = tmp_store(5);
        store.create("id", &oauth_record()).expect("create");
        let wrong = payload_hash(b"not the current payload");
        match store.overwrite_cas("id", &oauth_record(), &wrong) {
            Err(StoreOpError::CasMismatch) => {}
            other => panic!("expected CasMismatch, got {other:?}"),
        }
        // The record is unchanged after a rejected CAS.
        assert_eq!(store.get("id").unwrap().record_version, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn invalidate_marks_needs_reauth() {
        let (root, store) = tmp_store(6);
        store.create("id", &oauth_record()).expect("create");
        store.invalidate("id").expect("invalidate");
        match store.get("id") {
            Err(StoreOpError::NeedsReauth) => {}
            other => panic!("expected NeedsReauth, got {other:?}"),
        }
        assert_eq!(store.meta("id").unwrap().state, RecordState::NeedsReauth);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_envelope_quarantines_only_that_record() {
        let (root, store) = tmp_store(7);
        store.create("good", &oauth_record()).expect("create good");
        store.create("bad", &oauth_record()).expect("create bad");
        // Corrupt the 'bad' row's ciphertext directly (simulate at-rest damage).
        store
            .store
            .with_conn(|c| {
                c.execute(
                    "UPDATE credentials SET envelope = X'00010203' WHERE credential_id = 'bad'",
                    [],
                )
            })
            .expect("corrupt bad");
        // 'bad' fails closed and is quarantined; 'good' still serves.
        match store.get("bad") {
            Err(StoreOpError::Decrypt(_)) => {}
            other => panic!("expected Decrypt, got {other:?}"),
        }
        assert_eq!(
            store.meta("bad").unwrap().state,
            RecordState::Corrupt,
            "bad row quarantined"
        );
        // A second get on the now-quarantined row is a clean Quarantined error.
        match store.get("bad") {
            Err(StoreOpError::Quarantined) => {}
            other => panic!("expected Quarantined on re-get, got {other:?}"),
        }
        assert_eq!(
            store.get("good").unwrap().payload,
            b"payload-bytes",
            "good still serves"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_key_fails_closed_at_open() {
        // A vault sealed under one key, then OPENED with a DIFFERENT key: the wrong
        // key fails to decrypt the sealed audit key, so open() itself fails closed
        // (KeyMismatch) — the vault never opens under the wrong key, and nothing
        // panics. This is stronger than the old per-record check: a wrong key is
        // rejected up front, before any credential is touched.
        let (root, store) = tmp_store(8);
        store.create("id", &oauth_record()).expect("create");
        let db_path = root.join("store.db");

        // Release the first store's single-writer lease before re-opening, then
        // re-open the same database under a different master key.
        drop(store);
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: db_path.to_string_lossy().into_owned(),
            },
        };
        let reopened = open_sqlite(&descriptor).expect("reopen");
        let result = EncryptedStore::open(reopened, MasterKey::from_bytes([0xEE; MASTER_KEY_LEN]));
        match result {
            Err(StoreOpError::Decrypt(EnvelopeError::KeyMismatch { .. })) => {}
            Err(other) => panic!("expected KeyMismatch at open under wrong key, got {other:?}"),
            Ok(_) => panic!("expected open to fail closed under the wrong key"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_meta_reports_without_decrypt() {
        let (root, store) = tmp_store(9);
        store.create("a", &oauth_record()).expect("a");
        store.create("b", &oauth_record()).expect("b");
        store.invalidate("b").expect("invalidate b");
        let metas = store.list_meta().expect("list");
        assert_eq!(metas.len(), 2);
        let by_id: std::collections::HashMap<_, _> = metas.into_iter().collect();
        assert_eq!(by_id["a"].state, RecordState::Active);
        assert_eq!(by_id["b"].state, RecordState::NeedsReauth);
        assert_eq!(by_id["a"].key_id_hex, store.key_id().to_hex());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn handle_mint_resolve_revoke() {
        let (root, store) = tmp_store(10);
        store.create("opencode:anthropic", &oauth_record()).unwrap();
        let h = mint_handle().expect("mint");
        assert!(h.raw.starts_with("ckh_"));
        assert_eq!(h.hash, handle_hash(&h.raw));
        store
            .put_handle_hash(
                &h.hash,
                "opencode:anthropic",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .unwrap();
        // Resolve maps the raw handle to its credential id.
        assert_eq!(store.resolve_handle(&h.raw).unwrap(), "opencode:anthropic");
        // Revoke makes it resolve to NotFound (uniform with an unknown handle).
        store
            .revoke_handle(&h.raw, AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap();
        assert!(matches!(
            store.resolve_handle(&h.raw),
            Err(StoreOpError::NotFound)
        ));
        // An unknown handle is also NotFound (no distinction leaked).
        assert!(matches!(
            store.resolve_handle("ckh_bogus"),
            Err(StoreOpError::NotFound)
        ));
        // The mint and the revoke are BOTH recorded in the tamper-evident audit chain
        // (atomically, in their own fenced txns), and the chain still verifies.
        let entries = store.read_audit(None).unwrap();
        let ops: Vec<&str> = entries.iter().map(|e| e.op.as_str()).collect();
        assert!(ops.contains(&"mint_handle"), "mint audited: {ops:?}");
        assert!(ops.contains(&"revoke_handle"), "revoke audited: {ops:?}");
        assert_eq!(
            store.verify_audit_chain().unwrap(),
            None,
            "chain intact after mint+revoke"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn revoke_all_handles_for_credential() {
        let (root, store) = tmp_store(11);
        store.create("id", &oauth_record()).unwrap();
        let h1 = mint_handle().unwrap();
        let h2 = mint_handle().unwrap();
        store
            .put_handle_hash(&h1.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
            .unwrap();
        store
            .put_handle_hash(&h2.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
            .unwrap();
        let n = store
            .revoke_all_handles("id", AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap();
        assert_eq!(n, 2, "both handles revoked");
        assert!(matches!(
            store.resolve_handle(&h1.raw),
            Err(StoreOpError::NotFound)
        ));
        assert!(matches!(
            store.resolve_handle(&h2.raw),
            Err(StoreOpError::NotFound)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn audit_chain_appends_and_verifies() {
        let (root, store) = tmp_store(12);
        let e1 = store
            .append_audit(&AuditRecord {
                op: crate::audit::AuditOp::Put,
                credential_id: Some("id".into()),
                payload_hash: Some("abcd".into()),
                actor: "offline-cli".into(),
                alarm: None,
            })
            .expect("append 1");
        assert_eq!(e1.seq, 1);
        assert_eq!(e1.prev_mac, crate::audit::GENESIS_MAC);
        let e2 = store
            .append_audit(&AuditRecord {
                op: crate::audit::AuditOp::Overwrite,
                credential_id: Some("id".into()),
                payload_hash: Some("ef01".into()),
                actor: "offline-cli".into(),
                alarm: Some(AlarmReason::OverwriteWithoutCas),
            })
            .expect("append 2");
        assert_eq!(e2.seq, 2);
        assert_eq!(e2.prev_mac, e1.entry_mac, "chain links");
        assert!(e2.alarm);
        // The full chain verifies under the store's master-key-derived audit key.
        assert_eq!(store.verify_audit_chain().unwrap(), None);
        // read_audit returns chain order, oldest first.
        let all = store.read_audit(None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[1].seq, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A sequence-only witness cannot see a tail truncation when fresh legitimate
    /// appends reuse the deleted sequence. The tip MAC makes the replacement visible.
    /// A revocation names the credential that lost a door, and names nothing when the
    /// handle does not resolve.
    ///
    /// Both arms are the point. Without the first, the chain answers "a handle was
    /// revoked" and cannot answer the question an incident asks -- WHICH credentials lost
    /// access -- which is exactly what an external contributor measured on a
    /// five-credential rotation where two revocations shared a timestamp to the second.
    ///
    /// Without the second, a NULL would be meaningless and the entry could not
    /// distinguish a revocation that closed a real door from one that found nothing.
    #[test]
    fn a_revocation_names_the_credential_that_lost_a_door() {
        let (_root, store) = tmp_store(41);
        let ctx = AuditCtx::vault(AuditOp::MintHandle);
        store.create("attrib", &oauth_record()).expect("create");
        let h = mint_handle().expect("mint");
        store.put_handle_hash(&h.hash, "attrib", ctx).expect("mint");

        store
            .revoke_handle(&h.raw, AuditCtx::vault(AuditOp::RevokeHandle))
            .expect("revoke");
        let entries = store.read_audit(None).expect("read chain");
        let revoked: Vec<_> = entries.iter().filter(|e| e.op == "revoke_handle").collect();
        assert_eq!(revoked.len(), 1, "one revocation recorded");
        assert_eq!(
            revoked[0].credential_id.as_deref(),
            Some("attrib"),
            "the chain must name which credential lost access; without it a rotation's \
             blast radius is not reconstructable from the chain alone"
        );

        store
            .revoke_handle(
                "ckh_this-handle-never-existed",
                AuditCtx::vault(AuditOp::RevokeHandle),
            )
            .expect("idempotent on an unknown handle");
        let entries = store.read_audit(None).expect("read chain");
        let revoked: Vec<_> = entries.iter().filter(|e| e.op == "revoke_handle").collect();
        assert_eq!(revoked.len(), 2, "the no-op attempt is still recorded");
        assert_eq!(
            revoked[1].credential_id, None,
            "an unresolvable handle must name NO credential, so a NULL means the \
             revocation moved no rows rather than meaning the field was never filled"
        );
    }

    #[test]
    fn audit_tip_pair_exposes_tail_truncation_with_reused_sequence() {
        let (root, store) = tmp_store(21);
        store
            .append_audit(&AuditRecord {
                op: crate::audit::AuditOp::Put,
                credential_id: Some("id".into()),
                payload_hash: Some("first".into()),
                actor: "offline-cli".into(),
                alarm: None,
            })
            .expect("append first");
        let tail = store
            .append_audit(&AuditRecord {
                op: crate::audit::AuditOp::Overwrite,
                credential_id: Some("id".into()),
                payload_hash: Some("original-tail".into()),
                actor: "offline-cli".into(),
                alarm: None,
            })
            .expect("append original tail");
        let observed = (tail.seq, tail.entry_mac.clone());

        let conn = rusqlite::Connection::open(root.join("store.db")).expect("open raw store");
        conn.execute("DELETE FROM audit_log WHERE seq = ?1", [tail.seq])
            .expect("delete tail");
        drop(conn);

        let replacement = store
            .append_audit(&AuditRecord {
                op: crate::audit::AuditOp::Overwrite,
                credential_id: Some("id".into()),
                payload_hash: Some("replacement-tail".into()),
                actor: "fresh-legitimate-writer".into(),
                alarm: None,
            })
            .expect("append replacement tail");

        assert_eq!(
            replacement.seq, observed.0,
            "deletion plus a fresh append can return the sequence to its old value"
        );
        assert_ne!(
            replacement.entry_mac, observed.1,
            "the MAC at a reused sequence must reveal that the row bytes changed"
        );
        assert_eq!(
            store.audit_tip().expect("read tip").expect("tip exists"),
            (replacement.seq, replacement.entry_mac)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rotate_master_key_rewraps_and_chain_stays_verifiable() {
        let (root, mut store) = tmp_store(20);
        store.create("a", &oauth_record()).expect("create a");
        store.create("b", &oauth_record()).expect("create b");
        // The audit chain has two put entries; capture its length.
        let before = store.read_audit(None).unwrap().len();
        assert!(store.verify_audit_chain().unwrap().is_none());

        // Rotate to a new master key.
        let new_key = MasterKey::from_bytes([0x77; MASTER_KEY_LEN]);
        let new_key_id = new_key.key_id();
        store.rotate_master_key(new_key).expect("rotate");

        // Records are still readable (re-wrapped under the new key), unchanged plaintext.
        assert_eq!(store.get("a").unwrap().payload, b"payload-bytes");
        assert_eq!(store.get("b").unwrap().payload, b"payload-bytes");
        // The key_id columns were swapped to the new fingerprint.
        assert_eq!(store.meta("a").unwrap().key_id_hex, new_key_id.to_hex());
        // The chain is STILL one continuously-verifiable sequence (stable audit key)
        // and grew by exactly one RotateMasterKey entry.
        assert_eq!(
            store.verify_audit_chain().unwrap(),
            None,
            "chain spans rotation"
        );
        let after = store.read_audit(None).unwrap();
        assert_eq!(after.len(), before + 1);
        assert_eq!(after.last().unwrap().op, "rotate_master_key");
        assert!(
            after.last().unwrap().credential_id.is_none(),
            "vault-global entry"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rotated_vault_reopens_only_under_new_key() {
        let (root, mut store) = tmp_store(21);
        store.create("a", &oauth_record()).unwrap();
        // Minted BEFORE the rotation: a consumer's live grant, which must survive both
        // the rewrap and the close/reopen below.
        let handle = mint_handle().expect("mint a pre-rotation handle");
        store
            .put_handle_hash(&handle.hash, "a", AuditCtx::admin(AuditOp::MintHandle))
            .expect("record the handle");
        let db_path = root.join("store.db");
        let new_key = MasterKey::from_bytes([0x88; MASTER_KEY_LEN]);
        store
            .rotate_master_key(MasterKey::from_bytes([0x88; MASTER_KEY_LEN]))
            .unwrap();
        drop(store);

        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "vault".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: db_path.to_string_lossy().into_owned(),
            },
        };
        // The OLD key no longer opens the vault (audit-key decrypt fails closed).
        let reopened = open_sqlite(&descriptor).unwrap();
        let old_result =
            EncryptedStore::open(reopened, MasterKey::from_bytes([20u8; MASTER_KEY_LEN]));
        assert!(
            old_result.is_err(),
            "old key must not reopen a rotated vault"
        );
        // The NEW key opens it and the records are intact.
        let reopened = open_sqlite(&descriptor).unwrap();
        let store = EncryptedStore::open(reopened, new_key).expect("new key opens");
        assert_eq!(store.get("a").unwrap().payload, b"payload-bytes");
        assert_eq!(store.verify_audit_chain().unwrap(), None);

        // A ROTATION MUST NOT REVOKE ANYONE'S ACCESS. Handles are hashed, not sealed,
        // so nothing in the rewrap should touch them -- but that is an argument from
        // how the code is written today, and a future rewrap that rebuilt rows
        // wholesale would silently cut off every consumer while every assertion above
        // still passed. Consumers hold these values and cannot tell a revoked handle
        // from an unknown one (both answer NotFound, deliberately), so the failure
        // would surface as an unexplained fleet-wide outage.
        let resolved = store
            .resolve_handle(&handle.raw)
            .expect("the pre-rotation handle still resolves");
        assert_eq!(
            resolved, "a",
            "a handle minted before the rotation must still name its credential"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let (root, store) = tmp_store(13);
        for i in 0..3 {
            store
                .append_audit(&AuditRecord {
                    op: crate::audit::AuditOp::RefreshCommit,
                    credential_id: Some(format!("id{i}")),
                    payload_hash: Some("hh".into()),
                    actor: "conn-1".into(),
                    alarm: None,
                })
                .unwrap();
        }
        assert_eq!(
            store.verify_audit_chain().unwrap(),
            None,
            "clean chain verifies"
        );
        // Tamper with a row's payload_hash directly (a key-less attacker editing the
        // db) — the HMAC no longer matches, so verification flags the broken seq.
        store
            .with_raw_conn(|c| {
                c.execute(
                    "UPDATE audit_log SET payload_hash = 'tampered' WHERE seq = 2",
                    [],
                )
            })
            .unwrap();
        assert_eq!(
            store.verify_audit_chain().unwrap(),
            Some(2),
            "tampered entry detected"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_fenced_write_latches_fenced_out() {
        let (root, store) = tmp_store(21);
        store.create("id", &oauth_record()).expect("create");
        // Not fenced out on a healthy store.
        assert!(!store.is_fenced_out());

        // Simulate a newer writer having claimed the database at a higher epoch, so
        // the next fenced write is rejected — exactly the lease-handover race.
        store
            .with_raw_conn(|c| c.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", []))
            .expect("bump fence epoch above the holder");

        // A real durable mutation now: it must be Fenced AND latch the flag.
        match store.invalidate("id") {
            Err(StoreOpError::Fenced { .. }) => {}
            other => panic!("expected Fenced, got {other:?}"),
        }
        assert!(
            store.is_fenced_out(),
            "a rejected fenced write must latch the fenced-out signal"
        );

        // The signal drives the health snapshot to Failing even though the stale
        // read of the row still succeeds (Active).
        let metas = store.list_meta().expect("list_meta still reads");
        let health = crate::health::VaultHealth::summarize(&metas, 0, store.is_fenced_out());
        assert_eq!(health.status, crate::health::VaultHealthStatus::Failing);
        assert!(health.fenced_out);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A corrupt record is repaired by REPLACE, not by an inverse of quarantine.
    ///
    /// Pins the claim the quarantine doc comment makes, because a comment describing a
    /// repair path is worth less than a test that fails if the path closes. The costly
    /// misreading is quiet: a reader who believes corrupt is unrecoverable reaches for
    /// `remove`, which deletes the row and every handle with it, turning a one-command
    /// fix into an operator ceremony for a platform-issued key.
    #[test]
    fn a_corrupt_record_is_repaired_by_replace_and_keeps_its_handles() {
        let (root, store) = tmp_store(11);
        let rec = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"one".to_vec(), None);
        store.create("id", &rec).expect("create");
        let handle = mint_handle().expect("mint");
        store
            .put_handle_hash(&handle.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
            .expect("put handle");
        store.quarantine("id").expect("quarantine");
        assert!(matches!(
            store.meta("id").expect("meta").state,
            RecordState::Corrupt
        ));

        let fresh = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"two".to_vec(), None);
        store
            .overwrite_unconditional_audited("id", &fresh, AuditCtx::admin(AuditOp::Put))
            .expect("replace");

        let meta = store.meta("id").expect("meta");
        assert!(
            matches!(meta.state, RecordState::Active),
            "replace must clear corrupt, or the doc comment is lying about the repair path"
        );
        assert_eq!(store.get("id").expect("read back").payload, b"two".to_vec());
        // The handle survives -- which is the whole reason replace beats remove here.
        assert_eq!(
            store.resolve_handle(&handle.raw).expect("resolve"),
            "id",
            "the repair must not cost consumers their handles"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Reactivate clears needs_reauth or retired, leaves the SECRET alone, and refuses
    /// corrupt.
    ///
    /// Three properties in one test because they are one guarantee: this verb contradicts
    /// a VERDICT, it never repairs BYTES. Corrupt is excluded precisely because it IS a
    /// claim about our own bytes -- clearing it would return known-broken material to
    /// service, and no operator assertion makes an undecryptable envelope decrypt.
    #[test]
    fn reactivate_clears_needs_reauth_or_retired_without_touching_the_secret_and_refuses_corrupt() {
        let (root, store) = tmp_store(7);
        let rec =
            VaultRecord::new_static(CredentialKind::ApiKey, "test", b"the-secret".to_vec(), None);
        store.create("live", &rec).expect("create");
        store.create("retired", &rec).expect("create retired");
        store.create("broken", &rec).expect("create broken");

        store
            .invalidate_and_revoke_all_audited("live", AuditCtx::admin(AuditOp::Invalidate))
            .expect("invalidate");
        assert!(matches!(
            store.meta("live").expect("meta").state,
            RecordState::NeedsReauth
        ));

        let changed = store
            .reactivate_audited("live", AuditCtx::admin(AuditOp::Reactivate))
            .expect("reactivate");
        assert!(changed, "a needs_reauth credential must reactivate");
        assert!(matches!(
            store.meta("live").expect("meta").state,
            RecordState::Active
        ));
        assert_eq!(
            store.get("live").expect("read back").payload,
            b"the-secret".to_vec(),
            "reactivate must not disturb the stored material"
        );

        store
            .retire_and_revoke_all_audited("retired", AuditCtx::admin(AuditOp::Invalidate))
            .expect("retire");
        let retired_changed = store
            .reactivate_audited("retired", AuditCtx::admin(AuditOp::Reactivate))
            .expect("reactivate retired");
        assert!(retired_changed, "a retired credential must reactivate");
        assert!(matches!(
            store.meta("retired").expect("retired meta").state,
            RecordState::Active
        ));

        // A TRANSITION, not a repeatable write: a retry loop must not append to the
        // untrimmable audit chain.
        let again = store
            .reactivate_audited("live", AuditCtx::admin(AuditOp::Reactivate))
            .expect("second reactivate");
        assert!(!again, "reactivating an active credential must be a no-op");

        // CORRUPT IS REFUSED. The arm that keeps the verb honest.
        store.quarantine("broken").expect("quarantine");
        let corrupt_changed = store
            .reactivate_audited("broken", AuditCtx::admin(AuditOp::Reactivate))
            .expect("reactivate corrupt");
        assert!(
            !corrupt_changed,
            "a corrupt record must NOT reactivate: its own bytes failed"
        );
        assert!(
            matches!(
                store.meta("broken").expect("meta").state,
                RecordState::Corrupt
            ),
            "the corrupt record must still be corrupt"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fenced_out_never_clears_on_a_later_successful_write() {
        // The latch is one-way, and this is the arm that pins it. Every OTHER field of
        // the health snapshot is recomputed from a fresh scan, so a reader could
        // reasonably assume this one recovers too, and "clear the flag when writes work
        // again" is a natural-looking change. It would be wrong: regaining the fence
        // means the OTHER lease holder went away, not that this instance recovered
        // authority, so clearing on a later success resumes serving as the authority on
        // the strength of a race. Recovery is a restart. Without this assertion the
        // one-way property is only a comment.
        let (root, store) = tmp_store(21);
        store.create("id", &oauth_record()).expect("create");

        let held: i64 = store
            .with_raw_conn(|c| {
                c.query_row("SELECT epoch FROM cortexkit_fence WHERE id = 0", [], |r| {
                    r.get(0)
                })
            })
            .expect("read the epoch this store holds");

        // Simulate a competing writer taking the lease: raising the stored fence epoch
        // above the one this store holds makes its next durable write be rejected.
        store
            .with_raw_conn(|c| c.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", []))
            .expect("bump fence epoch above the holder");
        assert!(matches!(
            store.invalidate("id"),
            Err(StoreOpError::Fenced { .. })
        ));
        assert!(store.is_fenced_out(), "precondition: the latch is set");

        // Now make writes succeed again by restoring the epoch this store holds --
        // standing in for the competing holder having exited.
        store
            .with_raw_conn(|c| {
                c.execute("UPDATE cortexkit_fence SET epoch = ?1 WHERE id = 0", [held])
            })
            .expect("restore the held epoch");

        // The write goes through: this is a genuine success, not a second rejection,
        // so the assertion below is about the latch rather than about the write failing.
        store.invalidate("id").expect("the write now succeeds");

        assert!(
            store.is_fenced_out(),
            "a later successful write must NOT clear the fenced-out latch: this process \
             cannot regain lost write authority, only a restart can"
        );
        let metas = store.list_meta().expect("list_meta");
        let health = crate::health::VaultHealth::summarize(&metas, 0, store.is_fenced_out());
        assert_eq!(
            health.status,
            crate::health::VaultHealthStatus::Failing,
            "health must stay Failing until the process is replaced"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn version_gated_invalidate_hits_on_matching_version() {
        let (root, store) = tmp_store(30);
        store.create("id", &oauth_record()).expect("create"); // record_version 1
        let ctx = AuditCtx {
            op: AuditOp::ReportAuthFailure,
            actor: "conn-1",
            alarm: None,
        };
        // Reporting the CURRENT version (1) invalidates and returns true.
        let hit = store
            .invalidate_if_version_audited("id", 1, ctx)
            .expect("version-gated invalidate");
        assert!(hit, "a report for the current version must invalidate");
        assert_eq!(store.meta("id").unwrap().state, RecordState::NeedsReauth);
        // And it audited exactly one ReportAuthFailure entry.
        let reports = store
            .read_audit(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.op == "report_auth_failure")
            .count();
        assert_eq!(reports, 1, "a hitting version-CAS audits the invalidation");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn version_gated_invalidate_is_a_silent_noop_on_stale_version() {
        let (root, store) = tmp_store(31);
        store.create("id", &oauth_record()).expect("create"); // record_version 1
                                                              // Simulate the vault having refreshed to a newer version after the consumer was
                                                              // served v1: overwrite unconditionally so the current version moves to 2.
        store
            .overwrite_unconditional_audited(
                "id",
                &oauth_record(),
                AuditCtx::vault(AuditOp::Overwrite),
            )
            .expect("bump to version 2");
        assert_eq!(store.meta("id").unwrap().record_version, 2);

        let ctx = AuditCtx {
            op: AuditOp::ReportAuthFailure,
            actor: "conn-1",
            alarm: None,
        };
        // A stale report for the SERVED version (1) must be a silent no-op: it does NOT
        // invalidate the fresh v2 credential, returns false, and audits nothing.
        let hit = store
            .invalidate_if_version_audited("id", 1, ctx)
            .expect("stale version-gated invalidate");
        assert!(
            !hit,
            "a report for a superseded version must not invalidate"
        );
        assert_eq!(
            store.meta("id").unwrap().state,
            RecordState::Active,
            "the fresh credential is untouched by a stale report"
        );
        let reports = store
            .read_audit(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.op == "report_auth_failure")
            .count();
        assert_eq!(reports, 0, "a stale version-CAS no-op audits nothing");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A report for the replaced version must not schedule an unnecessary second refresh.
    #[test]
    fn report_for_stale_version_does_not_re_stale_the_fresh_token() {
        let (root, store) = tmp_store(64);
        store.create("id", &oauth_record()).expect("create");
        store
            .overwrite_unconditional_audited(
                "id",
                &oauth_record(),
                AuditCtx::vault(AuditOp::RefreshCommit),
            )
            .expect("replace v1 with fresh v2");

        let changed = store
            .mark_stale_if_version_reported(
                "id",
                1,
                AuditCtx::vault(AuditOp::ReportAuthFailure),
                AuthObservation {
                    kind: "consumer_report_stale",
                    provider_status: Some(401),
                    detail: None,
                    reporter_source: None,
                },
            )
            .expect("stale report is accepted");
        assert!(!changed, "the v1 report must not match the v2 row");
        let meta = store.meta("id").expect("fresh metadata");
        assert_eq!(meta.record_version, 2);
        assert!(matches!(meta.state, RecordState::Active));
        assert!(
            !meta.stale_pending,
            "a stale report must not set the marker on the fresh token"
        );
        let events = store.recent_auth_events(10).expect("events");
        assert_eq!(events[0].kind, "consumer_report_stale");
        assert!(
            !events[0].applied,
            "the stale report must be diagnostic-only"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The no-op case is the one worth explaining, so it must leave a diagnostic row.
    ///
    /// A report naming a superseded version changes nothing and audits nothing -- both
    /// correct. The consequence was that a consumer acting on stale state, which is a
    /// real thing to want to know about, was invisible afterwards. `auth_events` records
    /// the observation either way and marks whether it applied.
    #[test]
    fn a_stale_report_is_still_recorded_as_an_observation_that_did_not_apply() {
        let (root, store) = tmp_store(63);
        store.create("id", &oauth_record()).expect("create");
        store
            .overwrite_unconditional_audited(
                "id",
                &oauth_record(),
                AuditCtx::vault(AuditOp::Overwrite),
            )
            .expect("bump to version 2");

        let ctx = AuditCtx {
            op: AuditOp::ReportAuthFailure,
            actor: "conn-1",
            alarm: None,
        };
        let obs = AuthObservation {
            kind: "consumer_report",
            provider_status: Some(401),
            detail: None,
            reporter_source: None,
        };

        // Stale report against v1 while the store holds v2.
        let hit = store
            .invalidate_if_version_reported("id", 1, ctx, Some(obs))
            .expect("stale report");
        assert!(!hit, "a superseded version must not invalidate");
        assert_eq!(
            store.meta("id").unwrap().state,
            RecordState::Active,
            "the fresh credential is untouched"
        );

        let events = store.recent_auth_events(10).expect("read events");
        assert_eq!(events.len(), 1, "the no-op must still be recorded");
        assert_eq!(events[0].provider_status, Some(401));
        assert_eq!(events[0].record_version, Some(1));
        assert!(
            !events[0].applied,
            "the row must say the observation did NOT change the credential -- that is \
             what separates a stale report from a real one"
        );

        // THE DISAMBIGUATOR: a matching report records `applied = true`. Without this
        // arm, an implementation writing `applied = false` unconditionally passes.
        let hit = store
            .invalidate_if_version_reported("id", 2, ctx, Some(obs))
            .expect("current report");
        assert!(hit, "a report at the served version must invalidate");
        let events = store.recent_auth_events(10).expect("read events");
        assert_eq!(events.len(), 2);
        assert!(
            events[0].applied,
            "a report at the current version must record as applied"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A handle can be minted for a credential that is already `needs_reauth`, and
    /// the compound invalidate revokes only handles that exist WHEN IT RUNS.
    ///
    /// Both halves are load-bearing for a consumer holding a handle across a
    /// credential dying and being repaired — the handle must survive, because the
    /// alternative is re-provisioning every consumer after every provider hiccup.
    ///
    /// So the two orderings are both reachable and mean different things:
    /// invalidate-then-mint leaves a live handle, mint-then-invalidate revokes it.
    /// AFTER EITHER, THE CREDENTIAL READS `needs_reauth` — identical state, opposite
    /// handle state — so anything checking only the credential cannot tell them
    /// apart. That is what makes the second arm worth writing: it pins the handle row
    /// `remove` reports how many handles it deleted, and the count is real.
    ///
    /// A consumer holding a capability handle cannot be told by the vault that its
    /// credential is gone: handles are bearer tokens and nothing records who holds
    /// one, so the holder's next fetch gets a bare `not_found`. The count is the only
    /// warning available and it is only actionable at the moment of removal --
    /// observed live, a removed credential left a stale entry in a consumer's handle
    /// file which blinded three healthy sibling accounts until they noticed
    /// independently.
    ///
    /// Both arms, because a function returning a constant satisfies either one alone:
    /// two handles must report two, and none must report zero so the CLI can stay
    /// silent rather than warning about consumers that cannot exist.
    #[test]
    fn remove_reports_how_many_handles_stopped_resolving() {
        let (root, store) = tmp_store(73);
        let ctx = AuditCtx::vault(AuditOp::MintHandle);

        store
            .create("with-handles", &oauth_record())
            .expect("create");
        for _ in 0..2 {
            let h = mint_handle().expect("mint");
            store
                .put_handle_hash(&h.hash, "with-handles", ctx)
                .expect("store handle");
        }
        store.create("bare", &oauth_record()).expect("create bare");

        let n = store
            .remove_audited("with-handles", AuditCtx::admin(AuditOp::Remove))
            .expect("remove");
        assert_eq!(
            n, 2,
            "the count must be the number of handles that just stopped resolving"
        );

        let none = store
            .remove_audited("bare", AuditCtx::admin(AuditOp::Remove))
            .expect("remove bare");
        assert_eq!(
            none, 0,
            "a credential with no handles must report zero, so the operator is not \
             warned about consumers that cannot exist"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// A REPEAT logout changes nothing, says so, and writes no audit entry.
    ///
    /// The first call is the control: without it, a function that never reports a
    /// change would pass every assertion below.
    ///
    /// Two properties, and they fail differently. The OUTCOME must report no change,
    /// because a CLI that prints plain success on a no-op reads as broken -- observed
    /// live: three consecutive logouts against one already-dead credential, three
    /// identical success messages, an identical listing after each. The AUDIT CHAIN
    /// must not grow, because it is tamper-evident and therefore untrimmable: an
    /// operator repeating a logout would otherwise extend it without bound with
    /// entries recording that nothing happened.
    #[test]
    fn a_repeat_logout_changes_nothing_and_appends_no_audit_entry() {
        let (root, store) = tmp_store(71);
        store.create("dead", &oauth_record()).expect("create");
        let h = mint_handle().expect("mint");
        store
            .put_handle_hash(&h.hash, "dead", AuditCtx::vault(AuditOp::MintHandle))
            .expect("store handle");

        // CONTROL: the first logout genuinely mutates.
        let first = store
            .invalidate_and_revoke_all_audited("dead", AuditCtx::admin(AuditOp::Invalidate))
            .expect("first logout");
        assert!(
            first.state_changed && first.handles_revoked == 1,
            "the first logout must actually invalidate and revoke: {first:?}"
        );
        assert!(
            first.changed_anything(),
            "a logout that killed a live credential must report a change"
        );

        let entries_after_first = store.read_audit(None).expect("read audit").len();

        // The repeat.
        let second = store
            .invalidate_and_revoke_all_audited("dead", AuditCtx::admin(AuditOp::Invalidate))
            .expect("second logout");
        assert!(
            !second.changed_anything(),
            "a logout against an already-dead credential with no live handles must \
             report that nothing changed, or the CLI cannot tell an operator why the \
             listing is identical: {second:?}"
        );
        assert!(
            !second.state_changed && second.handles_revoked == 0,
            "no state flip and no revocation on the repeat: {second:?}"
        );

        let entries_after_second = store.read_audit(None).expect("read audit").len();
        assert_eq!(
            entries_after_first, entries_after_second,
            "the tamper-evident chain must not grow on a no-op -- it cannot be \
             trimmed, so a repeated logout would extend it without bound"
        );

        // The record still exists: logout is reversible, which is exactly why it
        // stays listed and why `remove` is the verb for making it go away.
        assert_eq!(
            store.meta("dead").expect("meta").state,
            RecordState::NeedsReauth,
            "logout keeps the row"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// as the discriminator, and would fail if minting ever started refusing a dead
    /// credential.
    #[test]
    fn a_handle_mints_for_a_dead_credential_and_invalidate_only_revokes_what_exists() {
        let (root, store) = tmp_store(67);
        let ctx = AuditCtx::vault(AuditOp::MintHandle);

        // invalidate -> mint: the compound has nothing to revoke, then the mint lands.
        store.create("id", &oauth_record()).expect("create");
        let revoked = store
            .invalidate_and_revoke_all_audited("id", AuditCtx::vault(AuditOp::Invalidate))
            .expect("invalidate");
        assert_eq!(
            revoked.handles_revoked, 0,
            "nothing to revoke before a handle exists"
        );
        let live = mint_handle().expect("mint");
        store
            .put_handle_hash(&live.hash, "id", ctx)
            .expect("minting for a needs_reauth credential must succeed");
        assert_eq!(
            store.resolve_handle(&live.raw).expect("resolve"),
            "id",
            "the handle must RESOLVE: this is the state production reaches on its own, \
             and resolution selects on revoked = 0"
        );

        // mint -> invalidate: same credential state, opposite handle state.
        store.create("id2", &oauth_record()).expect("create");
        let dead = mint_handle().expect("mint");
        store.put_handle_hash(&dead.hash, "id2", ctx).expect("mint");
        let revoked = store
            .invalidate_and_revoke_all_audited("id2", AuditCtx::vault(AuditOp::Invalidate))
            .expect("invalidate");
        assert_eq!(
            revoked.handles_revoked, 1,
            "an existing handle IS revoked by the operator verb"
        );
        assert!(
            matches!(store.resolve_handle(&dead.raw), Err(StoreOpError::NotFound)),
            "revoked, while the credential reads needs_reauth exactly as above"
        );

        assert_eq!(
            store.meta("id").unwrap().state,
            store.meta("id2").unwrap().state,
            "the credential state cannot discriminate the two orderings -- which is \
             why the handle row is the guard"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A repeated report audits ONCE, because the chain cannot be trimmed.
    ///
    /// The version guard does not bound this on its own: invalidating does not bump
    /// `record_version`, so a consumer reporting the same version twice matches twice,
    /// and every match appends to a log that is append-only by design. Requiring an
    /// actual state transition makes the repeat a no-op.
    ///
    /// The second arm is the disambiguator: a guard that simply refused everything
    /// would satisfy the first assertion alone.
    #[test]
    fn a_repeated_report_audits_once_but_is_recorded_every_time() {
        let (root, store) = tmp_store(65);
        store.create("id", &oauth_record()).expect("create");
        let ctx = AuditCtx {
            op: AuditOp::ReportAuthFailure,
            actor: "conn-1",
            alarm: None,
        };
        let obs = AuthObservation {
            kind: "consumer_report",
            provider_status: Some(401),
            detail: None,
            reporter_source: None,
        };

        // First report at the served version: a real transition.
        let hit = store
            .invalidate_if_version_reported("id", 1, ctx, Some(obs))
            .expect("first report");
        assert!(hit, "the first report must invalidate");

        // Six more identical reports. The credential is already needs_reauth, and the
        // version has not moved, so each still MATCHES the version guard.
        for _ in 0..6 {
            let hit = store
                .invalidate_if_version_reported("id", 1, ctx, Some(obs))
                .expect("repeat report");
            assert!(!hit, "a repeat changes nothing and must report so");
        }

        let audited = store
            .read_audit(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.op == "report_auth_failure")
            .count();
        assert_eq!(
            audited, 1,
            "only the transition may append to the untrimmable chain; got {audited}"
        );

        // THE DISAMBIGUATOR: every report is still recorded as a diagnostic, which is
        // the table that CAN be bounded. A guard that dropped these too would pass the
        // assertion above while destroying the evidence of the loop.
        let events = store.recent_auth_events(100).expect("read events");
        assert_eq!(
            events.len(),
            7,
            "every report must still be recorded as an observation"
        );
        assert_eq!(
            events.iter().filter(|e| e.applied).count(),
            1,
            "exactly one of them applied"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A flood against one credential is bounded, and cannot evict another's history.
    ///
    /// Recording an observation even when it changes nothing is the point of this
    /// table, and the cost is that a formerly silent no-op now always writes. Nothing
    /// upstream refuses one -- the read surface's limiter alarms on a report flood and
    /// lets the call through -- so the bound lives at the insert.
    ///
    /// The per-credential scope is the load-bearing part: under a global cap, one
    /// consumer looping on one credential would evict every other credential's
    /// history -- the rows that explain whatever failure is being diagnosed.
    #[test]
    fn an_event_flood_is_bounded_per_credential_and_spares_other_credentials() {
        let (root, store) = tmp_store(64);
        store
            .create("noisy", &oauth_record())
            .expect("create noisy");
        store
            .create("quiet", &oauth_record())
            .expect("create quiet");

        // One event for the quiet credential, which must survive the flood.
        store
            .record_auth_event(
                "quiet",
                AuthObservation {
                    kind: "refresh_failed",
                    provider_status: Some(503),
                    detail: Some("status"),
                    reporter_source: None,
                },
                Some(1),
            )
            .expect("quiet event");

        // Well past the cap, as a stuck consumer would produce.
        let flood = AUTH_EVENTS_PER_CREDENTIAL + 40;
        for _ in 0..flood {
            store
                .record_auth_event(
                    "noisy",
                    AuthObservation {
                        kind: "consumer_report",
                        provider_status: Some(401),
                        detail: None,
                        reporter_source: None,
                    },
                    Some(1),
                )
                .expect("noisy event");
        }

        let events = store.recent_auth_events(10_000).expect("read events");
        let noisy = events.iter().filter(|e| e.credential_id == "noisy").count();
        let quiet = events.iter().filter(|e| e.credential_id == "quiet").count();

        assert_eq!(
            noisy as u32, AUTH_EVENTS_PER_CREDENTIAL,
            "a flood must be trimmed to the cap, not grow without bound"
        );
        assert_eq!(
            quiet, 1,
            "a flood against one credential must not evict another's history -- those \
             are the rows an operator reads during the incident"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rotate_quarantines_undecryptable_rows_and_reports_them() {
        let (root, mut store) = tmp_store(40);
        store.create("good", &oauth_record()).expect("create good");
        store.create("bad", &oauth_record()).expect("create bad");
        // Corrupt "bad"'s envelope directly (a key-less db edit): it will fail to decrypt
        // under the OLD key during rotation, so it cannot be re-wrapped.
        store
            .with_raw_conn(|c| {
                c.execute(
                    "UPDATE credentials SET envelope = X'00010203' WHERE credential_id = 'bad'",
                    [],
                )
            })
            .expect("corrupt bad envelope");

        let new_key = MasterKey::from_bytes([0x41; MASTER_KEY_LEN]);
        let quarantined = store.rotate_master_key(new_key).expect("rotate");
        // The undecryptable row is surfaced, not silently skipped behind a success.
        assert_eq!(quarantined, vec!["bad".to_string()]);
        assert_eq!(store.meta("bad").unwrap().state, RecordState::Corrupt);
        // The good record re-wrapped under the new key and still reads.
        assert_eq!(
            store.get("good").expect("good readable").payload,
            b"payload-bytes"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_db_key_id_fails_closed_on_a_corrupt_anchor() {
        let (root, store) = tmp_store(50);
        store.create("id", &oauth_record()).expect("create");
        // Corrupt the sealed audit-key row's plaintext key_id fingerprint (the resolve
        // anchor). This must be distinguished from an ABSENT row (a new vault) and fail
        // closed, not silently downgrade to the bootstrap path.
        store
            .with_raw_conn(|c| {
                c.execute(
                    "UPDATE vault_secrets SET key_id = 'not-hex' WHERE name = ?1",
                    rusqlite::params![AUDIT_KEY_SECRET_NAME],
                )
            })
            .expect("corrupt anchor");
        // The test module is inside store.rs, so it can reach the private inner store.
        match EncryptedStore::read_db_key_id(&store.store) {
            Err(StoreError::Backend(m)) => assert!(m.contains("corrupt anchor"), "got: {m}"),
            other => panic!("a corrupt anchor must fail closed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A grant prefix is ordinary text, not a SQL pattern: `%` and `_` in a credential
    /// id family must never authorize unrelated ids by acting as wildcards.
    #[test]
    fn read_grant_prefixes_are_literal_not_like_patterns() {
        let (root, store) = tmp_store(51);
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "github%_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");

        assert!(
            store
                .read_grant_covers(
                    "reserved",
                    "prefrontal-core",
                    "github%_app:agent",
                    GrantOperation::Read,
                )
                .expect("check literal prefix"),
            "the exact literal prefix must cover its family"
        );
        assert!(
            !store
                .read_grant_covers(
                    "reserved",
                    "prefrontal-core",
                    "githubZZapp:agent",
                    GrantOperation::Read,
                )
                .expect("check unrelated id"),
            "percent and underscore in a grant must not widen it as SQL LIKE wildcards"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// PINS THE LITERAL, deliberately, so adding a migration REDDENS rather than
    /// silently changing what this binary declares to the supervisor.
    ///
    /// The manifest publishes this number, so a new migration is a change to a
    /// fleet-visible declaration and not only to the schema. A relationship assertion
    /// (`== MIGRATIONS.iter().max()`) would move with the list and prove nothing about
    /// the value; the literal is what makes the author look at the manifest.
    #[test]
    fn the_newest_migration_version_is_pinned_because_the_manifest_declares_it() {
        assert_eq!(
            newest_migration_version(),
            8,
            "the newest migration changed. This value is DECLARED in the module manifest \
             as store_schema_version, so a supervisor comparing declared-against-actual \
             sees it. Update the literal, and note the manifest consequence."
        );

        // Semantics, not just the value: `newest` must be the MAXIMUM, not the last
        // element. They agree while the list stays sorted, and diverge the first time
        // someone inserts out of order -- which is exactly when a silent wrong answer
        // would be least expected.
        for m in MIGRATIONS {
            assert!(
                m.version <= newest_migration_version(),
                "migration {} exceeds the reported newest -- newest_migration_version is \
                 returning a position rather than a maximum",
                m.version
            );
        }
    }
}
