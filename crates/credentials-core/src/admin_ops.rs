//! The shared admin-op wire contract: the exact op-body shapes the CLI/app signs
//! and the module verifies+executes.
//!
//! Both sides use THESE types, so the bytes the caller MACs are byte-identical to
//! what the module parses (the caller serializes an `AdminOpBody`, MACs those exact
//! bytes, and sends them verbatim; the module verifies those bytes, then decodes
//! them back into an `AdminOpBody`). Keeping the contract in one place is why the
//! transcript's op-body binding cannot silently drift between the two binaries — a
//! field rename breaks both at compile time, not at runtime.
//!
//! The body is treated as OPAQUE bytes during authentication (parse-after-verify);
//! these types are only used to BUILD the bytes (caller) and to INTERPRET them
//! (module) once the MAC has proven possession.

use serde::{Deserialize, Serialize};

use crate::audit::AuditRecord;
use crate::audit::{AuditCtx, AuditOp};
use crate::record::{RecordIdentity, VaultRecord};
use crate::store::{mint_handle, EncryptedStore, GrantOperation, StoreOpError};

/// The admin-op schema version. Bumped only on a breaking op-body change; the
/// module refuses any other version rather than best-effort parsing it.
pub const ADMIN_OP_SCHEMA_V1: u32 = 1;

/// One authenticated admin operation. `#[serde(tag = "op")]` so the discriminator
/// is an `op` string inside the same object the transcript covers.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum AdminOpBody {
    #[serde(rename = "admin.store")]
    Store {
        v: u32,
        id: String,
        // Boxed to keep the enum variants' sizes comparable (a VaultRecord carries
        // token strings); serde flattens the box transparently.
        record: Box<VaultRecord>,
        audit_op: AdminAuditOp,
        mode: StoreMode,
    },
    /// Update only the non-secret identity attached to an existing record. The store
    /// re-seals the unchanged credential material and keeps its lifecycle state.
    #[serde(rename = "admin.set_identity")]
    SetIdentity {
        v: u32,
        id: String,
        identity: RecordIdentity,
    },
    #[serde(rename = "admin.invalidate")]
    Invalidate { v: u32, id: String },
    /// Reversibly stop serving a credential because an operator intentionally retired
    /// it. This is the only admin operation that writes `retired`; all discovery paths
    /// continue to use `needs_reauth` or `corrupt`.
    #[serde(rename = "admin.logout")]
    Logout { v: u32, id: String },
    /// Clear `needs_reauth` or `retired` back to active WITHOUT replacing the stored material: the
    /// operator asserting the credential was marked dead in error.
    ///
    /// The counterpart to `Invalidate`, and NOT a substitute for `Store` -- it changes
    /// no secret, only a verdict about one. Exists because a mistaken consumer report
    /// could otherwise strand material the vault holds intact: a GitHub App key is
    /// shredded after deposit by custody rule, so there is no copy to re-put and no
    /// login flow to re-mint, and recovering would need a browser ceremony.
    #[serde(rename = "admin.reactivate")]
    Reactivate { v: u32, id: String },
    /// PERMANENT removal: delete the credential row, its intent, and its handles
    /// (audited; the chain keeps the history). `logout` (invalidate) is the
    /// reversible sibling — remove is for retiring an account or cleaning up a
    /// mistaken id.
    #[serde(rename = "admin.remove")]
    Remove { v: u32, id: String },
    #[serde(rename = "admin.mint_handle")]
    MintHandle { v: u32, id: String },
    #[serde(rename = "admin.revoke_handle")]
    RevokeHandle { v: u32, handle: String },
    #[serde(rename = "admin.revoke_all_handles")]
    RevokeAllHandles { v: u32, id: String },
    /// Grant a reserved module principal one literal-prefix credential operation.
    #[serde(rename = "admin.grant_create")]
    GrantCreate {
        v: u32,
        principal_id: String,
        credential_prefix: String,
        operation: GrantOperation,
    },
    /// Revoke a reserved module principal literal-prefix credential operation grant.
    #[serde(rename = "admin.grant_revoke")]
    GrantRevoke {
        v: u32,
        principal_id: String,
        credential_prefix: String,
        operation: GrantOperation,
    },
    /// Record that a NAMED APPROVER approved a specific artifact, identified by the
    /// SHA-256 of its exact bytes, before a signing window is opened for it.
    ///
    /// Master-key-gated like every other admin op, and that is the point rather than
    /// uniformity: an approval a route caller could forge would prove nothing about who
    /// approved. The signing itself is NOT gated this way — `credential.sign` needs only
    /// a handle — so the gate is deliberately on the record of intent rather than on the
    /// act, which is the asymmetry the ceremony rests on.
    #[serde(rename = "admin.approval")]
    Approval {
        v: u32,
        /// The signing credential the window will open on, so the entry names WHICH key
        /// was approved for use and not merely that something was approved.
        credential_id: String,
        /// Lowercase hex SHA-256 of the exact artifact bytes. Never a rendering, never a
        /// canonicalized form: the verifier verifies received bytes, so the approver
        /// must approve those same bytes or the two meet at nothing.
        artifact_sha256: String,
        /// Who approved. Free text by design — the vault cannot authenticate a human,
        /// and pretending otherwise by constraining the field would imply a check that
        /// does not exist.
        approver: String,
    },
    /// An authenticated READ: the no-decrypt credential inventory + health summary.
    /// A read, but master-key-gated like every other admin op, because the full
    /// per-credential id/state list is not an anonymous enumeration surface (the
    /// anonymous read plane is capability-handle-scoped by design). Serves `ck creds
    /// status` against a RUNNING daemon.
    #[serde(rename = "admin.status")]
    Status { v: u32 },
}

/// Redacted `Debug`, hand-written rather than derived, and NOT only because of the
/// boxed `VaultRecord` -- that one is fixed transitively now that `VaultRecord` redacts
/// its own payload.
///
/// THE VARIANT THAT MADE THIS NECESSARY IS `RevokeHandle`. Its `handle` is the RAW
/// `ckh_...` bearer, not a hash: `apply` passes it straight to `store.revoke_handle`,
/// which hashes it there (`handle_hash(raw_handle)`). A capability handle in a log is
/// strictly worse than an encrypted payload in one -- it needs no key, no decoding, and
/// no vault access to use. Anyone who can read the line can read the credential it
/// grants, until someone notices and revokes it.
///
/// A MANUAL IMPL RATHER THAN A REDACTING NEWTYPE, deliberately: this enum IS the MAC
/// transcript, verified byte-for-byte on the admin route, so nothing that could perturb
/// its serialization belongs anywhere near it. A `Debug` impl cannot; a serde-adjacent
/// type change could.
///
/// The exhaustive match is the forcing function. A new variant carrying a new secret
/// will not compile until someone has decided how it renders, which is the property a
/// derive gives up.
impl std::fmt::Debug for AdminOpBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminOpBody::Store {
                v,
                id,
                record,
                audit_op,
                mode,
            } => f
                .debug_struct("Store")
                .field("v", v)
                .field("id", id)
                // VaultRecord redacts its own payload.
                .field("record", record)
                .field("audit_op", audit_op)
                .field("mode", mode)
                .finish(),
            AdminOpBody::SetIdentity { v, id, identity } => f
                .debug_struct("SetIdentity")
                .field("v", v)
                .field("id", id)
                .field("identity", identity)
                .finish(),
            AdminOpBody::Invalidate { v, id } => f
                .debug_struct("Invalidate")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Logout { v, id } => f
                .debug_struct("Logout")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Reactivate { v, id } => f
                .debug_struct("Reactivate")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::Remove { v, id } => f
                .debug_struct("Remove")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::MintHandle { v, id } => f
                .debug_struct("MintHandle")
                .field("v", v)
                .field("id", id)
                .finish(),
            // The one that matters: a live bearer token.
            AdminOpBody::RevokeHandle { v, .. } => f
                .debug_struct("RevokeHandle")
                .field("v", v)
                .field("handle", &"<redacted>")
                .finish(),
            AdminOpBody::RevokeAllHandles { v, id } => f
                .debug_struct("RevokeAllHandles")
                .field("v", v)
                .field("id", id)
                .finish(),
            AdminOpBody::GrantCreate {
                v,
                principal_id,
                credential_prefix,
                operation,
            } => f
                .debug_struct("GrantCreate")
                .field("v", v)
                .field("principal_id", principal_id)
                .field("credential_prefix", credential_prefix)
                .field("operation", operation)
                .finish(),
            AdminOpBody::GrantRevoke {
                v,
                principal_id,
                credential_prefix,
                operation,
            } => f
                .debug_struct("GrantRevoke")
                .field("v", v)
                .field("principal_id", principal_id)
                .field("credential_prefix", credential_prefix)
                .field("operation", operation)
                .finish(),
            AdminOpBody::Approval {
                v,
                credential_id,
                artifact_sha256,
                approver,
            } => f
                .debug_struct("Approval")
                .field("v", v)
                .field("credential_id", credential_id)
                .field("artifact_sha256", artifact_sha256)
                .field("approver", approver)
                .finish(),
            AdminOpBody::Status { v } => f.debug_struct("Status").field("v", v).finish(),
        }
    }
}

impl AdminOpBody {
    /// The schema version this op declares.
    pub fn schema_version(&self) -> u32 {
        match self {
            AdminOpBody::Store { v, .. }
            | AdminOpBody::SetIdentity { v, .. }
            | AdminOpBody::Invalidate { v, .. }
            | AdminOpBody::Logout { v, .. }
            | AdminOpBody::Reactivate { v, .. }
            | AdminOpBody::Remove { v, .. }
            | AdminOpBody::MintHandle { v, .. }
            | AdminOpBody::RevokeHandle { v, .. }
            | AdminOpBody::RevokeAllHandles { v, .. }
            | AdminOpBody::GrantCreate { v, .. }
            | AdminOpBody::GrantRevoke { v, .. }
            | AdminOpBody::Approval { v, .. }
            | AdminOpBody::Status { v } => *v,
        }
    }

    /// The credential id this op serializes against, for per-credential single-flight
    /// locking. `None` for `revoke_handle` (addressed by handle, not credential id),
    /// which therefore takes no per-id lock.
    pub fn lock_id(&self) -> Option<&str> {
        match self {
            // An approval takes the signing credential's lock: it is the record whose
            // window is about to open, so an approval racing an admin mutation of that
            // same key should serialize rather than interleave.
            AdminOpBody::Approval {
                credential_id: id, ..
            }
            | AdminOpBody::Store { id, .. }
            | AdminOpBody::SetIdentity { id, .. }
            | AdminOpBody::Invalidate { id, .. }
            | AdminOpBody::Logout { id, .. }
            | AdminOpBody::Reactivate { id, .. }
            | AdminOpBody::Remove { id, .. }
            | AdminOpBody::MintHandle { id, .. }
            | AdminOpBody::RevokeAllHandles { id, .. } => Some(id),
            AdminOpBody::RevokeHandle { .. }
            | AdminOpBody::GrantCreate { .. }
            | AdminOpBody::GrantRevoke { .. }
            | AdminOpBody::Status { .. } => None,
        }
    }

    /// Serialize to the exact bytes the caller MACs and the module verifies. The
    /// caller sends THESE bytes verbatim; the module verifies THESE bytes before
    /// decoding — so serialization non-canonicality is irrelevant (the bytes are
    /// the contract, not a re-derived form).
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// The audit op an `admin.store` records: login, import, or put/overwrite. A closed
/// set so a caller cannot inject an arbitrary audit label.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditOp {
    Login,
    Import,
    Put,
    Overwrite,
}

impl AdminAuditOp {
    pub fn to_audit_op(self) -> AuditOp {
        match self {
            AdminAuditOp::Login => AuditOp::Login,
            AdminAuditOp::Import => AuditOp::Import,
            AdminAuditOp::Put => AuditOp::Put,
            AdminAuditOp::Overwrite => AuditOp::Overwrite,
        }
    }
}

/// Apply an admin op to the store, auditing under `actor`. This is the ONE place
/// the mutation is applied — the running module calls it under the engine's
/// per-credential single-flight lock; the offline CLI calls it directly against the
/// leased store. Sharing it means the online and offline admin paths can never drift
/// in what a given op actually does. Returns a small non-secret JSON result (e.g. a
/// freshly minted handle, or a revoked count).
///
/// The schema version is validated by the caller (the module refuses an unknown
/// version before dispatch); this function assumes a v1 body.
pub fn apply(
    store: &EncryptedStore,
    op: AdminOpBody,
    actor: &str,
) -> Result<serde_json::Value, StoreOpError> {
    match op {
        AdminOpBody::Approval {
            credential_id,
            artifact_sha256,
            approver,
            ..
        } => {
            // The approver is recorded as the ACTOR rather than folded into a message,
            // so the chain answers "who approved" with a field instead of prose a later
            // reader has to parse.
            //
            // The route actor (`route-admin`) is deliberately NOT used here: it names the
            // path, and this entry exists to name the person.
            store.append_audit(&AuditRecord {
                op: AuditOp::Approval,
                credential_id: Some(credential_id.clone()),
                payload_hash: Some(artifact_sha256.clone()),
                actor: approver.clone(),
                alarm: None,
            })?;
            Ok(serde_json::json!({
                "approved": artifact_sha256,
                "credential_id": credential_id,
                "approver": approver,
            }))
        }
        AdminOpBody::Store {
            id,
            record,
            audit_op,
            mode,
            ..
        } => {
            let ctx = AuditCtx::route_admin(audit_op.to_audit_op(), actor);
            match mode {
                StoreMode::Create => store.create_audited(&id, &record, ctx)?,
                StoreMode::ReplaceUnconditional { clear_identity } => store
                    .overwrite_unconditional_with_identity_policy_audited(
                        &id,
                        &record,
                        !clear_identity,
                        ctx,
                    )?,
                StoreMode::ReplaceCas { expected_hash_hex } => {
                    let expected = decode_hash32(&expected_hash_hex)
                        .ok_or_else(|| StoreOpError::Encode("bad expected hash hex".into()))?;
                    store.overwrite_cas_audited(&id, &record, &expected, ctx)?
                }
            }
            Ok(serde_json::json!({ "stored": true }))
        }
        AdminOpBody::SetIdentity { id, identity, .. } => {
            store.set_identity_audited(
                &id,
                identity,
                AuditCtx::route_admin(AuditOp::SetIdentity, actor),
            )?;
            Ok(serde_json::json!({ "identity_updated": true }))
        }
        AdminOpBody::Invalidate { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Invalidate, actor);
            let outcome = store.invalidate_and_revoke_all_audited(&id, ctx)?;
            // `state_changed` rides the wire so the CLI can tell an operator whether
            // this call did anything. `handles_revoked` alone cannot: a credential
            // with no handles reports zero whether it was live or already dead.
            Ok(serde_json::json!({
                "handles_revoked": outcome.handles_revoked,
                "state_changed": outcome.state_changed,
                "intent_cleared": outcome.intent_cleared,
            }))
        }
        AdminOpBody::Logout { id, .. } => {
            // Keep the established `invalidate` audit label. Historic rows are
            // intentionally not reclassified, and the current lifecycle state carries
            // the operator's retirement intent without changing that chain vocabulary.
            let ctx = AuditCtx::route_admin(AuditOp::Invalidate, actor);
            let outcome = store.retire_and_revoke_all_audited(&id, ctx)?;
            Ok(serde_json::json!({
                "handles_revoked": outcome.handles_revoked,
                "state_changed": outcome.state_changed,
                "intent_cleared": outcome.intent_cleared,
            }))
        }
        AdminOpBody::Reactivate { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Reactivate, actor);
            let state_changed = store.reactivate_audited(&id, ctx)?;
            // `state_changed` rides the wire for the same reason it does on invalidate:
            // without it, a no-op (already active, or corrupt and refused) is
            // indistinguishable from a real repair, and an operator would read success
            // as "the credential is back" when nothing happened.
            Ok(serde_json::json!({ "state_changed": state_changed }))
        }
        AdminOpBody::Remove { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::Remove, actor);
            let handles_deleted = store.remove_audited(&id, ctx)?;
            // The count rides the wire so the CLI can tell an operator that live
            // capability handles just stopped resolving. Handles are bearer tokens
            // with no record of who holds them, so this is the only warning
            // available and it is only useful at the moment of the removal.
            Ok(serde_json::json!({
                "removed": true,
                "handles_deleted": handles_deleted,
            }))
        }
        AdminOpBody::MintHandle { id, .. } => {
            // The credential must exist before a handle is minted for it (the handles
            // table has no FK, so this guard is the check). meta() is a no-decrypt
            // plaintext read, so it works on any lifecycle state.
            store.meta(&id)?;
            let handle = mint_handle().map_err(|e| StoreOpError::Encode(format!("csprng: {e}")))?;
            let ctx = AuditCtx::route_admin(AuditOp::MintHandle, actor);
            store.put_handle_hash(&handle.hash, &id, ctx)?;
            // The raw handle is returned ONCE here; only its hash is persisted.
            Ok(serde_json::json!({ "handle": handle.raw }))
        }
        AdminOpBody::RevokeHandle { handle, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            store.revoke_handle(&handle, ctx)?;
            Ok(serde_json::json!({ "revoked": true }))
        }
        AdminOpBody::RevokeAllHandles { id, .. } => {
            let ctx = AuditCtx::route_admin(AuditOp::RevokeHandle, actor);
            let n = store.revoke_all_handles(&id, ctx)?;
            Ok(serde_json::json!({ "handles_revoked": n }))
        }
        AdminOpBody::GrantCreate {
            principal_id,
            credential_prefix,
            operation,
            ..
        } => {
            let ctx = AuditCtx::route_admin(AuditOp::GrantCreate, actor);
            store.create_read_grant_audited(
                "reserved",
                &principal_id,
                &credential_prefix,
                operation,
                ctx,
            )?;
            Ok(serde_json::json!({ "grant_created": true }))
        }
        AdminOpBody::GrantRevoke {
            principal_id,
            credential_prefix,
            operation,
            ..
        } => {
            let ctx = AuditCtx::route_admin(AuditOp::GrantRevoke, actor);
            store.revoke_read_grant_audited(
                "reserved",
                &principal_id,
                &credential_prefix,
                operation,
                ctx,
            )?;
            Ok(serde_json::json!({ "grant_revoked": true }))
        }
        AdminOpBody::Status { .. } => {
            // A no-decrypt inventory + the same fail-closed health ladder the L3
            // probe computes, so `ck creds status` answers "why does the health
            // table say degraded" from one authenticated read. No mutation, no audit.
            let metas = store.list_meta()?;
            let grants = store.list_read_grants()?;
            let open_intents = store.list_intents()?.len();
            let health =
                crate::health::VaultHealth::summarize(&metas, open_intents, store.is_fenced_out());
            let credentials: Vec<serde_json::Value> = metas
                .iter()
                .map(|(id, m)| {
                    serde_json::json!({
                        "id": id,
                        "state": m.state.as_str(),
                        "record_version": m.record_version,
                    })
                })
                .collect();
            // Both source lists are SQL-sorted, and the filter retains credential order.
            // Grants are ordered by principal, prefix, then operation so the complete
            // authority set is stable across repeated status reads. Stable covered-set
            // output makes an added credential under an existing prefix
            // visible in a status diff instead of silently widening access.
            let read_grants: Vec<serde_json::Value> = grants
                .iter()
                .map(|grant| {
                    let covered_credential_ids: Vec<&str> = metas
                        .iter()
                        .map(|(id, _)| id.as_str())
                        .filter(|id| id.starts_with(&grant.credential_prefix))
                        .collect();
                    serde_json::json!({
                        "principal_kind": grant.principal_kind,
                        "principal_id": grant.principal_id,
                        "credential_prefix": grant.credential_prefix,
                        "operation": grant.operation.as_str(),
                        "created_at_ms": grant.created_at_ms,
                        "covered_credential_ids": covered_credential_ids,
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "status": health.status.as_str(),
                "credentials_total": health.credentials_total,
                "active": health.active,
                "needs_reauth": health.needs_reauth,
                "retired": health.retired,
                "corrupt": health.corrupt,
                "needs_reauth_ids": health.needs_reauth_ids,
                "retired_ids": health.retired_ids,
                "corrupt_ids": health.corrupt_ids,
                "open_intents": health.open_intents,
                "fenced_out": health.fenced_out,
                "credentials": credentials,
                "read_grants": read_grants,
            }))
        }
    }
}

fn decode_hash32(s: &str) -> Option<[u8; 32]> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect();
    <[u8; 32]>::try_from(bytes?.as_slice()).ok()
}

/// The write mode for `admin.store`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreMode {
    /// Create-only: fails if the id already exists.
    Create,
    /// Unconditional overwrite (version-guarded internally): the re-login / re-import
    /// replace that keeps the handle.
    ReplaceUnconditional {
        /// `import --clear-identity` is the one replacement that must not retain an
        /// identity absent from the incoming record.
        #[serde(default)]
        clear_identity: bool,
    },
    /// CAS overwrite gated on the current payload hash (lowercase hex).
    ReplaceCas { expected_hash_hex: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::CredentialKind;

    /// A capability handle never reaches a `Debug` rendering.
    ///
    /// `RevokeHandle.handle` is the RAW `ckh_...` bearer -- `apply` hands it to
    /// `store.revoke_handle`, which hashes it there. Unlike an encrypted payload, a
    /// handle in a log needs no key and no vault access: whoever reads the line holds
    /// the credential it grants.
    ///
    /// Asserts the marker is present as well as the secret absent, so an impl that
    /// rendered nothing cannot pass.
    #[test]
    fn debug_never_renders_a_capability_handle() {
        let op = AdminOpBody::RevokeHandle {
            v: 1,
            handle: "ckh_LIVEBEARERTOKENVALUE".to_string(),
        };
        let rendered = format!("{op:?}");
        assert!(
            !rendered.contains("ckh_LIVEBEARERTOKENVALUE"),
            "a live capability handle rendered into Debug output: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "the redaction marker must be present, or an empty rendering would pass: \
             {rendered}"
        );
    }

    /// The boxed record inside `Store` is redacted transitively.
    ///
    /// Pins the delegation rather than assuming it: if `VaultRecord` ever went back to a
    /// derived `Debug`, this enum's careful impl would start leaking through a field it
    /// does not itself redact.
    #[test]
    fn debug_of_store_does_not_render_the_boxed_records_payload() {
        let record = VaultRecord::new_static(
            CredentialKind::ApiKey,
            "operator",
            b"sk-INNER".to_vec(),
            None,
        );
        let op = AdminOpBody::Store {
            v: 1,
            id: "apikey:x".to_string(),
            record: Box::new(record),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::Create,
        };
        let rendered = format!("{op:?}");
        assert!(
            !rendered.contains("sk-INNER"),
            "the boxed record's payload rendered as text: {rendered}"
        );
        assert!(
            !rendered.contains("115, 107, 45, 73"),
            "the boxed record's payload rendered as bytes: {rendered}"
        );
    }

    #[test]
    fn round_trips_through_bytes() {
        let record = VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None);
        let op = AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "apikey:x".into(),
            record: Box::new(record),
            audit_op: AdminAuditOp::Put,
            mode: StoreMode::Create,
        };
        let bytes = op.to_bytes().unwrap();
        let back: AdminOpBody = serde_json::from_slice(&bytes).unwrap();
        // Re-serializing the decoded value yields the same bytes (serde is stable
        // for these types), which is what lets the module verify the caller's exact
        // bytes and then decode them.
        assert_eq!(back.to_bytes().unwrap(), bytes);
        assert_eq!(back.schema_version(), ADMIN_OP_SCHEMA_V1);
    }

    #[test]
    fn op_discriminator_is_present_in_bytes() {
        let op = AdminOpBody::Invalidate {
            v: 1,
            id: "apikey:x".into(),
        };
        let s = String::from_utf8(op.to_bytes().unwrap()).unwrap();
        assert!(s.contains("\"op\":\"admin.invalidate\""));
    }
}
