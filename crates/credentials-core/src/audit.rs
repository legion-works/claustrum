//! The tamper-evident, HMAC-keyed audit chain for vault mutations.
//!
//! Every durable mutation appends one [`AuditEntry`] in the same fenced transaction
//! as the mutation itself. Each entry carries an `entry_mac` computed over the
//! previous entry's mac plus this entry's fields, so the log is a hash chain: any
//! edit to a past entry invalidates every later mac.
//!
//! The chain is HMAC-keyed (not a plain hash) with a key DERIVED from the master
//! key, so the audit log cannot be forged or silently repaired without the master
//! key. A key-less attacker who rewrites the whole `audit_log` table could
//! recompute a plain SHA-256 chain and erase their tracks; they cannot recompute
//! the HMACs without the audit key, so the forensic record's tamper-evidence rests
//! on the SAME trust boundary as the record encryption. (An attacker who HAS the
//! master key would write through the admin CLI anyway, so this is the right
//! boundary.)

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The genesis predecessor mac for the first chain entry (a fixed, non-secret
/// constant — the chain's anchor).
pub const GENESIS_MAC: &str = "genesis";

/// What kind of mutation an audit entry records. Op-typed so the chain accounts for
/// every record-version change and an unexplained bump is a detectable gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOp {
    /// A create-only `put` (a new credential).
    Put,
    /// An import of a credential from a source format.
    Import,
    /// A vault-native first-party OAuth login: the operator minted an INDEPENDENT
    /// grant directly into the vault (distinct from `Import`, which ingests a token
    /// another custodian minted). Kept separate so forensics can tell a native mint
    /// from a foreign import without inference.
    Login,
    /// An overwrite under a compare-and-set.
    Overwrite,
    /// A non-secret account identity update that re-seals the existing credential
    /// material without replacing it.
    SetIdentity,
    /// An authoritative invalidate (revoke).
    Invalidate,
    /// A master-key rotation (rewrap).
    RotateMasterKey,
    /// A vault-owned refresh that committed new tokens.
    RefreshCommit,
    /// A consumer-reported auth failure that marked the credential needs_reauth.
    ReportAuthFailure,
    /// A credential row was permanently removed (its audit history is retained —
    /// removal deletes the row, never the chain).
    Remove,
    /// An operator cleared `needs_reauth` back to active WITHOUT touching the stored
    /// material — the assertion that the credential was marked dead in error.
    ///
    /// Distinct from `Put`/`Overwrite` on purpose: those replace the secret, this one
    /// only contradicts a verdict about it. An incident review asking "was this
    /// credential re-keyed or merely un-marked?" gets different answers, and the chain
    /// has to be able to tell them apart.
    Reactivate,
    /// A capability handle was minted.
    MintHandle,
    /// A capability handle (or all for a credential) was revoked.
    RevokeHandle,
    /// A read-surface fetch anomaly was detected (an enumeration/rate alarm). Not a
    /// mutation, but recorded durably so the anomaly survives the connection.
    FetchAnomaly,
    /// A principal-scoped credential-prefix read grant was created.
    GrantCreate,
    /// A principal-scoped credential-prefix read grant was revoked.
    GrantRevoke,
    /// A named approver approved a specific artifact, identified by the SHA-256 of its
    /// EXACT BYTES, before a signing window was opened for it.
    ///
    /// NOT A MUTATION OF ANY CREDENTIAL, and deliberately in the chain anyway. Signing
    /// itself writes nothing — `credential.sign` is a route operation reachable in a
    /// loop by any handle holder, and a durable write per call would let one grow the
    /// untrimmable chain without bound. So the ordering evidence lives here instead:
    ///
    ///   approval        payload_hash = SHA-256(artifact bytes), actor = approver
    ///   mint_handle     opens the signing window
    ///     ... signatures happen here, unrecorded and unbounded ...
    ///   revoke_handle   closes it
    ///
    /// The approval and the published signature MEET AT THE HASH: the chain proves who
    /// approved bytes H before the key was reachable, and the signature proves the key
    /// signed bytes H. A signature whose hash has no approval entry is then visible as
    /// an ABSENCE rather than merely undocumented.
    ///
    /// What it deliberately does not prove: that exactly one signature happened inside
    /// the window. An unrevoked handle is that gap, which is why a mint with no matching
    /// revoke is an unfinished ceremony rather than a harmless leftover.
    Approval,
}

impl AuditOp {
    /// The stable wire/storage string for this op.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditOp::Put => "put",
            AuditOp::Import => "import",
            AuditOp::Login => "login",
            AuditOp::Overwrite => "overwrite",
            AuditOp::SetIdentity => "set_identity",
            AuditOp::Invalidate => "invalidate",
            AuditOp::RotateMasterKey => "rotate_master_key",
            AuditOp::RefreshCommit => "refresh_commit",
            AuditOp::ReportAuthFailure => "report_auth_failure",
            AuditOp::Remove => "remove",
            AuditOp::Reactivate => "reactivate",
            AuditOp::MintHandle => "mint_handle",
            AuditOp::RevokeHandle => "revoke_handle",
            AuditOp::FetchAnomaly => "fetch_anomaly",
            AuditOp::GrantCreate => "grant_create",
            AuditOp::GrantRevoke => "grant_revoke",
            AuditOp::Approval => "approval",
        }
    }
}

/// The stable diagnostic kind stored in `auth_events.kind`.
///
/// Unlike [`AuditOp`] and [`AlarmReason`], these observations are not part of the
/// tamper-evident audit chain. They explain authentication failures and refusals in a
/// separate, prunable diagnostics table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthEventKind {
    /// A provider refresh attempt failed without producing a committed replacement.
    RefreshFailed,
    /// A stale report on a non-refreshable credential was latched as `needs_reauth`.
    StaleNonrefreshableLatch,
    /// A consumer report marked a refreshable credential stale for its next read.
    ConsumerReportStale,
    /// A consumer report immediately latched a non-refreshable credential.
    ConsumerReportLatch,
    /// A principal-scoped read was refused; the detail names the internal reason.
    ScopedReadRefusal,
    /// Startup reconciliation forced a credential to `needs_reauth`.
    ReconcileNeedsReauth,
    /// A successful GitHub App mint observed changed installation permissions.
    GithubAppPermissionsChanged,
}

/// The consumer-asserted, unverified source of a reported authentication failure.
///
/// This is separate from vault-observed `AuthEventKind` and `detail`: the vault records
/// what the reporter claims about its own path, without vouching for that claim. The
/// closed set ensures consumer input can never become durable plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReporterSource {
    Direct,
    RelayStatusField,
    RelayMessageParse,
    Unrecognised,
}

impl ReporterSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::RelayStatusField => "relay_status_field",
            Self::RelayMessageParse => "relay_message_parse",
            Self::Unrecognised => "unrecognised",
        }
    }

    pub fn from_wire(value: &str) -> Self {
        match value {
            "direct" => Self::Direct,
            "relay_status_field" => Self::RelayStatusField,
            "relay_message_parse" => Self::RelayMessageParse,
            _ => Self::Unrecognised,
        }
    }
}

impl AuthEventKind {
    /// The stable storage string for this authentication diagnostic kind.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthEventKind::RefreshFailed => "refresh_failed",
            AuthEventKind::StaleNonrefreshableLatch => "stale_nonrefreshable_latch",
            AuthEventKind::ConsumerReportStale => "consumer_report_stale",
            AuthEventKind::ConsumerReportLatch => "consumer_report_latch",
            AuthEventKind::ScopedReadRefusal => "scoped_read_refusal",
            AuthEventKind::ReconcileNeedsReauth => "reconcile_needs_reauth",
            AuthEventKind::GithubAppPermissionsChanged => "github_app_permissions_changed",
        }
    }
}

/// Why an audit entry is flagged as an alarm (a detected anomaly). `None` for a
/// normal entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmReason {
    /// An existing credential was overwritten without a compare-and-set guard.
    OverwriteWithoutCas,
    /// A connection's credential-fetch rate/spread crossed the anomaly threshold.
    FetchRateAnomaly,
    /// An administrative write occurred (always flagged so admin activity is loud).
    AdminWrite,
    /// Boot reconciliation found a stored refresh token whose hash did NOT match the
    /// dangling intent's recorded hash — a write landed without clearing the intent
    /// (an interrupted-rotation corruption / rogue-write guard). Alarmed so this tamper
    /// signal is durable and loud in the chain, not a silent generic invalidate.
    ReconcileHashMismatch,
}

impl AlarmReason {
    pub fn as_str(self) -> &'static str {
        match self {
            AlarmReason::OverwriteWithoutCas => "overwrite_without_cas",
            AlarmReason::FetchRateAnomaly => "fetch_rate_anomaly",
            AlarmReason::AdminWrite => "admin_write",
            AlarmReason::ReconcileHashMismatch => "reconcile_hash_mismatch",
        }
    }
}

/// Who is performing a mutation, under what op, and whether it should alarm —
/// threaded into each store mutation so the audit entry it appends (atomically, in
/// the mutation's own transaction) records all three. The credential id and payload
/// hash come from the mutation's own data.
#[derive(Debug, Clone, Copy)]
pub struct AuditCtx<'a> {
    /// The op recorded for this mutation. Distinguishes e.g. a `put` from an
    /// `import` even though both go through the same create path.
    pub op: AuditOp,
    /// The actor: `"conn-N"` for a daemon read-surface action, `"offline-cli"` for an
    /// admin CLI write, `"route-admin"` for an admin write through the running daemon,
    /// or `"vault"` for a vault-owned action (refresh, reconciliation).
    ///
    /// `N` in `"conn-N"` is the ROUTE CHANNEL NUMBER, which is assigned to a route
    /// binding and reused as bindings come and go. It is not a consumer identity and
    /// cannot be read as one: rows sharing a number are not necessarily the same
    /// caller, and one caller across reconnects may appear under several.
    pub actor: &'a str,
    /// An alarm reason when this mutation should be flagged (every admin write is
    /// flagged `AdminWrite`; a blind overwrite is `OverwriteWithoutCas`).
    pub alarm: Option<AlarmReason>,
}

impl AuditCtx<'_> {
    /// A vault-owned action (refresh commit, reconciliation): no alarm.
    pub fn vault(op: AuditOp) -> AuditCtx<'static> {
        AuditCtx {
            op,
            actor: "vault",
            alarm: None,
        }
    }

    /// An admin CLI write: always alarmed so admin activity is loud.
    pub fn admin(op: AuditOp) -> AuditCtx<'static> {
        AuditCtx {
            op,
            actor: "offline-cli",
            alarm: Some(AlarmReason::AdminWrite),
        }
    }

    /// An admin write that arrived over the running module's authenticated route
    /// admin surface (master-key challenge-response), rather than the offline CLI
    /// taking the lease. Always alarmed like any admin write; the actor names the
    /// authenticated origin so the audit trail distinguishes a live module-driven
    /// admin op from an offline-CLI one. The caller passes a stable actor string
    /// (e.g. "route-admin" or "route-admin/gen-N"); it is truthful provenance, not
    /// a caller-chosen free-form label — the module derives it, not the client.
    pub fn route_admin(op: AuditOp, actor: &str) -> AuditCtx<'_> {
        AuditCtx {
            op,
            actor,
            alarm: Some(AlarmReason::AdminWrite),
        }
    }
}

/// The data of one audit entry, BEFORE it is sequenced and chained. The store
/// assigns `seq`/`prev_mac` and computes `entry_mac` at append time.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// The mutation kind.
    pub op: AuditOp,
    /// The credential affected, if the op is credential-scoped.
    pub credential_id: Option<String>,
    /// Hex hash of the affected payload (for substitution detection), if applicable.
    pub payload_hash: Option<String>,
    /// Who performed it: a connection id (daemon read-surface action) or
    /// `"offline-cli"` (an admin CLI write).
    pub actor: String,
    /// An alarm reason when this entry records a detected anomaly.
    pub alarm: Option<AlarmReason>,
}

/// A fully chained audit entry as stored/read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: i64,
    pub ts_ms: i64,
    pub op: String,
    pub credential_id: Option<String>,
    pub payload_hash: Option<String>,
    pub actor: String,
    pub alarm: bool,
    pub alarm_reason: Option<String>,
    pub prev_mac: String,
    pub entry_mac: String,
}

/// Generate a fresh CSPRNG audit-chain HMAC key. Created ONCE at vault init and
/// then SEALED under the master key (see the store's `vault_secrets`); the value is
/// stable across master-key rotations (only its wrapping key changes), so the chain
/// stays continuously verifiable. NEVER regenerated for an existing vault.
pub fn generate_audit_key() -> Result<[u8; 32], getrandom::Error> {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k)?;
    Ok(k)
}

/// The MAC-covered content of one audit entry (everything the chain authenticates
/// except the audit key and the predecessor mac). Grouped so the mac computation
/// takes a single content view rather than a long positional argument list.
#[derive(Debug, Clone, Copy)]
pub struct MacFields<'a> {
    pub seq: i64,
    pub ts_ms: i64,
    pub op: &'a str,
    pub credential_id: Option<&'a str>,
    pub payload_hash: Option<&'a str>,
    pub actor: &'a str,
    pub alarm: bool,
    pub alarm_reason: Option<&'a str>,
}

/// Compute an entry's mac over its predecessor's mac and its own fields. The field
/// order and separators are fixed so the mac is reproducible for verification.
/// Optional fields use a fixed sentinel when absent so a missing value can never be
/// confused with an empty one.
pub fn compute_entry_mac(audit_key: &[u8; 32], prev_mac: &str, fields: &MacFields<'_>) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(audit_key).expect("HMAC accepts a 32-byte key");
    // Length-prefixed, sentinel-tagged field feed so no crafted field value can
    // shift a boundary or alias a missing value.
    feed(&mut mac, prev_mac.as_bytes());
    feed(&mut mac, &fields.seq.to_le_bytes());
    feed(&mut mac, &fields.ts_ms.to_le_bytes());
    feed(&mut mac, fields.op.as_bytes());
    feed_opt(&mut mac, fields.credential_id.map(str::as_bytes));
    feed_opt(&mut mac, fields.payload_hash.map(str::as_bytes));
    feed(&mut mac, fields.actor.as_bytes());
    feed(&mut mac, &[fields.alarm as u8]);
    feed_opt(&mut mac, fields.alarm_reason.map(str::as_bytes));
    let bytes = mac.finalize().into_bytes();
    hex(&bytes)
}

/// Verify a chain segment: each entry's mac recomputes from its predecessor and its
/// fields, and `prev_mac` links to the prior entry's `entry_mac`. The first entry's
/// `prev_mac` must be [`GENESIS_MAC`]. Returns the seq of the first broken entry, or
/// `None` if the whole segment verifies.
///
/// GUARANTEE AND ITS LIMIT: this makes the chain TAMPER-EVIDENT — no one without the
/// audit key can alter, reorder, or insert an interior entry without breaking a mac. It
/// is NOT rollback/truncation-resistant on its own: an attacker with write access to the
/// database (but not the key) can DELETE a suffix of the most recent entries, and the
/// remaining prefix still verifies cleanly (a valid shorter chain), with the next
/// legitimate append continuing from the truncated tip. Detecting suffix truncation
/// requires an EXTERNAL monotonic anchor (e.g. periodically recording `(last_seq,
/// tip_mac)` off-box); that is out of scope for the in-DB chain. Callers relying on the
/// audit log for non-repudiation must pair it with such an anchor.
pub fn verify_chain(audit_key: &[u8; 32], entries: &[AuditEntry]) -> Option<i64> {
    let mut expected_prev = GENESIS_MAC.to_string();
    for e in entries {
        if e.prev_mac != expected_prev {
            return Some(e.seq);
        }
        let recomputed = compute_entry_mac(
            audit_key,
            &e.prev_mac,
            &MacFields {
                seq: e.seq,
                ts_ms: e.ts_ms,
                op: &e.op,
                credential_id: e.credential_id.as_deref(),
                payload_hash: e.payload_hash.as_deref(),
                actor: &e.actor,
                alarm: e.alarm,
                alarm_reason: e.alarm_reason.as_deref(),
            },
        );
        if recomputed != e.entry_mac {
            return Some(e.seq);
        }
        expected_prev = e.entry_mac.clone();
    }
    None
}

fn feed(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&(field.len() as u64).to_le_bytes());
    mac.update(field);
}

/// Feed an optional field: a leading tag byte (0 = absent, 1 = present) so a
/// missing value is distinct from an empty one.
fn feed_opt(mac: &mut HmacSha256, field: Option<&[u8]>) {
    match field {
        Some(bytes) => {
            mac.update(&[1u8]);
            feed(mac, bytes);
        }
        None => mac.update(&[0u8]),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed test audit key (in production this is a CSPRNG secret sealed under
    /// the master key; tests just need a deterministic key).
    fn test_key() -> [u8; 32] {
        [3u8; 32]
    }

    fn entry(seq: i64, prev: &str, ak: &[u8; 32]) -> AuditEntry {
        let op = "put";
        let cid = Some("opencode:anthropic");
        let ph = Some("abcd");
        let actor = "offline-cli";
        let mac = compute_entry_mac(
            ak,
            prev,
            &MacFields {
                seq,
                ts_ms: 1000 + seq,
                op,
                credential_id: cid,
                payload_hash: ph,
                actor,
                alarm: false,
                alarm_reason: None,
            },
        );
        AuditEntry {
            seq,
            ts_ms: 1000 + seq,
            op: op.into(),
            credential_id: cid.map(String::from),
            payload_hash: ph.map(String::from),
            actor: actor.into(),
            alarm: false,
            alarm_reason: None,
            prev_mac: prev.into(),
            entry_mac: mac,
        }
    }

    #[test]
    fn generated_audit_keys_differ() {
        let a = generate_audit_key().expect("csprng");
        let b = generate_audit_key().expect("csprng");
        assert_ne!(a, b, "fresh audit keys are distinct");
    }

    #[test]
    fn valid_chain_verifies() {
        let ak = test_key();
        let e1 = entry(1, GENESIS_MAC, &ak);
        let e2 = entry(2, &e1.entry_mac, &ak);
        let e3 = entry(3, &e2.entry_mac, &ak);
        assert_eq!(verify_chain(&ak, &[e1, e2, e3]), None);
    }

    #[test]
    fn tampered_entry_breaks_chain() {
        let ak = test_key();
        let e1 = entry(1, GENESIS_MAC, &ak);
        let mut e2 = entry(2, &e1.entry_mac, &ak);
        let e3 = entry(3, &e2.entry_mac, &ak);
        // Tamper with e2's payload_hash but keep its (now-stale) mac.
        e2.payload_hash = Some("deadbeef".into());
        assert_eq!(verify_chain(&ak, &[e1, e2, e3]), Some(2), "broken at e2");
    }

    #[test]
    fn reordered_entries_break_chain() {
        let ak = test_key();
        let e1 = entry(1, GENESIS_MAC, &ak);
        let e2 = entry(2, &e1.entry_mac, &ak);
        // e2 before e1: e2.prev_mac (e1's mac) != genesis.
        assert_eq!(verify_chain(&ak, &[e2, e1]), Some(2));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let ak = test_key();
        let e1 = entry(1, GENESIS_MAC, &ak);
        let other = [9u8; 32];
        // A different audit key cannot reproduce the mac.
        assert_eq!(verify_chain(&other, &[e1]), Some(1));
    }

    #[test]
    fn optional_field_presence_changes_mac() {
        let ak = test_key();
        let base = MacFields {
            seq: 1,
            ts_ms: 1,
            op: "put",
            credential_id: None,
            payload_hash: None,
            actor: "a",
            alarm: false,
            alarm_reason: None,
        };
        let with = compute_entry_mac(
            &ak,
            "p",
            &MacFields {
                credential_id: Some(""),
                ..base
            },
        );
        let without = compute_entry_mac(&ak, "p", &base);
        assert_ne!(with, without, "absent != empty-present");
    }
}

#[cfg(test)]
mod vocabulary_documentation_tests {
    use super::{AlarmReason, AuditOp, AuthEventKind, ReporterSource};

    const RUNBOOK: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/operator-runbook.md"
    ));

    // These tests pin membership and spelling only. Finding a value somewhere in its
    // subsection cannot verify that the accompanying one-line meaning is correct.
    fn documented_subsection(heading: &str, positive_control: &str) -> &'static str {
        let start = RUNBOOK
            .find(heading)
            .unwrap_or_else(|| panic!("operator runbook is missing {heading}"));
        let after_heading = &RUNBOOK[start + heading.len()..];
        let end = after_heading
            .find("\n#### ")
            .or_else(|| after_heading.find("\n### "))
            .or_else(|| after_heading.find("\n## "))
            .unwrap_or(after_heading.len());
        let section = &after_heading[..end];
        assert!(
            section.contains(positive_control),
            "positive control {positive_control:?} is absent from {heading}; the doc scan would be vacuous"
        );
        section
    }

    fn assert_documented(section: &str, vocabulary: &str, value: &'static str) {
        assert!(
            section.contains(value),
            "{vocabulary} value {value:?} is missing from its documented runbook section"
        );
    }

    #[test]
    fn audit_op_values_are_documented() {
        let section = documented_subsection("#### `audit_log.op`", "**Table:** `audit_log`");

        fn value(op: AuditOp) -> &'static str {
            match op {
                AuditOp::Put => AuditOp::Put.as_str(),
                AuditOp::Import => AuditOp::Import.as_str(),
                AuditOp::Login => AuditOp::Login.as_str(),
                AuditOp::Overwrite => AuditOp::Overwrite.as_str(),
                AuditOp::SetIdentity => AuditOp::SetIdentity.as_str(),
                AuditOp::Invalidate => AuditOp::Invalidate.as_str(),
                AuditOp::RotateMasterKey => AuditOp::RotateMasterKey.as_str(),
                AuditOp::RefreshCommit => AuditOp::RefreshCommit.as_str(),
                AuditOp::ReportAuthFailure => AuditOp::ReportAuthFailure.as_str(),
                AuditOp::Remove => AuditOp::Remove.as_str(),
                AuditOp::Reactivate => AuditOp::Reactivate.as_str(),
                AuditOp::MintHandle => AuditOp::MintHandle.as_str(),
                AuditOp::RevokeHandle => AuditOp::RevokeHandle.as_str(),
                AuditOp::FetchAnomaly => AuditOp::FetchAnomaly.as_str(),
                AuditOp::GrantCreate => AuditOp::GrantCreate.as_str(),
                AuditOp::GrantRevoke => AuditOp::GrantRevoke.as_str(),
                AuditOp::Approval => AuditOp::Approval.as_str(),
            }
        }

        assert_documented(section, "audit_log.op", value(AuditOp::Put));
        assert_documented(section, "audit_log.op", value(AuditOp::Import));
        assert_documented(section, "audit_log.op", value(AuditOp::Login));
        assert_documented(section, "audit_log.op", value(AuditOp::Overwrite));
        assert_documented(section, "audit_log.op", value(AuditOp::SetIdentity));
        assert_documented(section, "audit_log.op", value(AuditOp::Invalidate));
        assert_documented(section, "audit_log.op", value(AuditOp::RotateMasterKey));
        assert_documented(section, "audit_log.op", value(AuditOp::RefreshCommit));
        assert_documented(section, "audit_log.op", value(AuditOp::ReportAuthFailure));
        assert_documented(section, "audit_log.op", value(AuditOp::Remove));
        assert_documented(section, "audit_log.op", value(AuditOp::Reactivate));
        assert_documented(section, "audit_log.op", value(AuditOp::MintHandle));
        assert_documented(section, "audit_log.op", value(AuditOp::RevokeHandle));
        assert_documented(section, "audit_log.op", value(AuditOp::FetchAnomaly));
        assert_documented(section, "audit_log.op", value(AuditOp::GrantCreate));
        assert_documented(section, "audit_log.op", value(AuditOp::GrantRevoke));
        assert_documented(section, "audit_log.op", value(AuditOp::Approval));
    }

    #[test]
    fn alarm_reason_values_are_documented() {
        let section = documented_subsection("#### `audit_log.alarm`", "**Table:** `audit_log`");

        fn value(reason: AlarmReason) -> &'static str {
            match reason {
                AlarmReason::OverwriteWithoutCas => AlarmReason::OverwriteWithoutCas.as_str(),
                AlarmReason::FetchRateAnomaly => AlarmReason::FetchRateAnomaly.as_str(),
                AlarmReason::AdminWrite => AlarmReason::AdminWrite.as_str(),
                AlarmReason::ReconcileHashMismatch => AlarmReason::ReconcileHashMismatch.as_str(),
            }
        }

        assert_documented(
            section,
            "audit_log.alarm",
            value(AlarmReason::OverwriteWithoutCas),
        );
        assert_documented(
            section,
            "audit_log.alarm",
            value(AlarmReason::FetchRateAnomaly),
        );
        assert_documented(section, "audit_log.alarm", value(AlarmReason::AdminWrite));
        assert_documented(
            section,
            "audit_log.alarm",
            value(AlarmReason::ReconcileHashMismatch),
        );
    }

    #[test]
    fn auth_event_kind_values_are_documented() {
        let section = documented_subsection("#### `auth_events.kind`", "**Table:** `auth_events`");

        fn value(kind: AuthEventKind) -> &'static str {
            match kind {
                AuthEventKind::RefreshFailed => AuthEventKind::RefreshFailed.as_str(),
                AuthEventKind::StaleNonrefreshableLatch => {
                    AuthEventKind::StaleNonrefreshableLatch.as_str()
                }
                AuthEventKind::ConsumerReportStale => AuthEventKind::ConsumerReportStale.as_str(),
                AuthEventKind::ConsumerReportLatch => AuthEventKind::ConsumerReportLatch.as_str(),
                AuthEventKind::ScopedReadRefusal => AuthEventKind::ScopedReadRefusal.as_str(),
                AuthEventKind::ReconcileNeedsReauth => AuthEventKind::ReconcileNeedsReauth.as_str(),
                AuthEventKind::GithubAppPermissionsChanged => {
                    AuthEventKind::GithubAppPermissionsChanged.as_str()
                }
            }
        }

        assert_documented(
            section,
            "auth_events.kind",
            value(AuthEventKind::RefreshFailed),
        );
        assert_documented(
            section,
            "auth_events.kind",
            value(AuthEventKind::StaleNonrefreshableLatch),
        );
        assert_documented(
            section,
            "auth_events.kind",
            value(AuthEventKind::ConsumerReportStale),
        );
        assert_documented(
            section,
            "auth_events.kind",
            value(AuthEventKind::ConsumerReportLatch),
        );
        assert_documented(
            section,
            "auth_events.kind",
            value(AuthEventKind::ScopedReadRefusal),
        );
        assert_documented(
            section,
            "auth_events.kind",
            value(AuthEventKind::ReconcileNeedsReauth),
        );
        assert_documented(
            section,
            "auth_events.kind",
            value(AuthEventKind::GithubAppPermissionsChanged),
        );
    }

    #[test]
    fn reporter_source_rejects_unrecognised_wire_values() {
        assert_eq!(
            ReporterSource::from_wire(&"a".repeat(40)),
            ReporterSource::Unrecognised
        );
    }

    #[test]
    fn reporter_source_values_are_documented() {
        let section = documented_subsection(
            "#### `auth_events.reporter_source`",
            "**Table:** `auth_events`",
        );

        fn value(source: ReporterSource) -> &'static str {
            match source {
                ReporterSource::Direct => ReporterSource::Direct.as_str(),
                ReporterSource::RelayStatusField => ReporterSource::RelayStatusField.as_str(),
                ReporterSource::RelayMessageParse => ReporterSource::RelayMessageParse.as_str(),
                ReporterSource::Unrecognised => ReporterSource::Unrecognised.as_str(),
            }
        }

        for source in [
            ReporterSource::Direct,
            ReporterSource::RelayStatusField,
            ReporterSource::RelayMessageParse,
            ReporterSource::Unrecognised,
        ] {
            assert_documented(section, "auth_events.reporter_source", value(source));
        }
    }
}
