//! The module-driven admin surface: authenticated write ops on the RUNNING module.
//!
//! Design: docs/module-driven-admin-design.md (Oracle-amended). Admin ops ride the
//! same route plane as reads, dual-gated:
//!
//! - Gate 1 (provenance pre-filter): the bind's daemon-stamped principal must be
//!   `direct`. `Reserved`, `Unverified`, and ABSENT all refuse. This removes the
//!   honest/accidental consumer class; it is NOT the adversarial boundary.
//! - Gate 2 (THE authority root): a master-key challenge-response per op. The
//!   caller MACs the exact op-body bytes with a key derived from the master key
//!   (`credentials_core::admin_auth`); the module verifies with the key it already
//!   holds, then — only after verification — parses and executes.
//!
//! Guarantee: at-most-once acceptance of an individually key-authorized operation.
//! A hostile relay can drop/delay/reorder ops and fabricate responses; it cannot
//! create or alter one, and a captured (nonce, tag) cannot authorize a second
//! execution (atomic nonce claim) or a different op (op-body binding).
//!
//! Serialization: every credential-scoped admin mutation runs under the engine's
//! per-credential single-flight lock (`RefreshEngine::with_admin_lock`) — the same
//! lock a refresh holds across its provider call and commit — so an admin write
//! can never interleave with a refresh for the same credential.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credentials_core::admin_auth::{AdminMacKey, TranscriptParts, ADMIN_NONCE_LEN, VAULT_ID_LEN};
use credentials_core::admin_ops::{AdminOpBody, ADMIN_OP_SCHEMA_V1};
use credentials_core::engine::RefreshEngine;
use credentials_core::key::KeyId;
use credentials_core::store::StoreOpError;
use subc_protocol::Principal;

/// Challenge TTL. Long enough for a CLI to resolve the keychain key and MAC the op;
/// short enough that a captured nonce is stale quickly (an attacker also needs the
/// master key, so this is defense-in-depth over the authority boundary).
const NONCE_TTL: Duration = Duration::from_secs(30);

/// Hard cap on outstanding challenges across all binds. Bounds the nonce table so a
/// challenge flood cannot exhaust memory. When full, a new challenge is refused
/// (never evict another bind's live nonce — that would let a flooder cancel a real
/// admin flow). Small: admin is a human-driven, low-rate operation.
const MAX_OUTSTANDING_NONCES: usize = 128;

/// Max authenticated op-body size. Bounds MAC work and decode cost per op.
const MAX_OP_BODY_LEN: usize = 1 << 20; // 1 MiB

/// The outcome the surface hands back to the wire layer. `Refused` carries a
/// non-secret reason string; the wire maps it to a route error.
pub enum AdminOutcome {
    /// A `admin.challenge` reply.
    Challenge {
        nonce_hex: String,
        vault_id_hex: String,
        key_id_hex: String,
    },
    /// A successful op with a JSON result body.
    Ok(serde_json::Value),
    /// A refused op (gate failure, bad MAC, expired/used nonce, oversize, decode).
    Refused(String),
}

/// A single-use challenge nonce with its issue instant (for TTL).
struct Nonce {
    bytes: [u8; ADMIN_NONCE_LEN],
    issued: Instant,
    /// The bind generation this nonce was issued to. The op must arrive on the same
    /// generation — a rebind (new generation on the same channel) invalidates it.
    generation: u64,
}

/// Per-bind admin state, keyed by route channel. Replaced wholesale on rebind so a
/// stale generation cannot reuse a prior bind's principal or nonce.
struct BindState {
    generation: u64,
    principal: Principal,
    /// At most one outstanding nonce per bind (issuing a new challenge replaces it).
    nonce: Option<Nonce>,
}

/// The module admin surface. Holds the engine (for the store + per-id lock), the
/// admin MAC key (derived from the master key), and the vault identity — plus the
/// per-bind registry and a global outstanding-nonce counter.
pub struct AdminSurface {
    engine: Arc<RefreshEngine>,
    mac_key: AdminMacKey,
    vault_id: [u8; VAULT_ID_LEN],
    key_id: KeyId,
    binds: Mutex<HashMap<u16, BindState>>,
    /// Monotonic generation source: every bind (including a rebind of the same
    /// channel) gets a fresh generation, so a stale in-flight op is detectable.
    next_generation: AtomicU64,
    outstanding_nonces: AtomicU64,
}

/// The actor recorded in the audit trail for a route-driven admin write.
const ROUTE_ADMIN_ACTOR: &str = "route-admin";

impl AdminSurface {
    pub fn new(
        engine: Arc<RefreshEngine>,
        mac_key: AdminMacKey,
        vault_id: [u8; VAULT_ID_LEN],
        key_id: KeyId,
    ) -> Self {
        AdminSurface {
            engine,
            mac_key,
            vault_id,
            key_id,
            binds: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            outstanding_nonces: AtomicU64::new(0),
        }
    }

    /// Record a bind's principal, replacing any prior state for the channel with a
    /// FRESH generation (so a lost-Goodbye rebind invalidates the old generation's
    /// outstanding nonce and in-flight ops). Returns the new generation.
    pub fn record_bind(&self, channel: u16, principal: Principal) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(prev) = binds.get(&channel) {
            // Draining the replaced bind's nonce keeps the global counter honest.
            if prev.nonce.is_some() {
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
            }
        }
        binds.insert(
            channel,
            BindState {
                generation,
                principal,
                nonce: None,
            },
        );
        generation
    }

    /// Test seam: backdate this channel's outstanding nonce so the TTL check sees it
    /// as expired, without sleeping through the real window.
    #[cfg(test)]
    fn backdate_nonce_for_test(&self, channel: u16, by: Duration) {
        let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(state) = binds.get_mut(&channel) {
            if let Some(nonce) = state.nonce.as_mut() {
                nonce.issued = Instant::now() - by;
            }
        }
    }

    /// Snapshot the principal that was stamped on a route bind. The route dispatcher
    /// captures this before spawning a request so a later channel rebind cannot change
    /// which caller authorized an already-accepted frame.
    pub fn principal(&self, channel: u16) -> Option<Principal> {
        let binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        binds.get(&channel).map(|state| state.principal.clone())
    }

    /// Forget a channel's admin state on route Goodbye. Idempotent.
    pub fn drop_bind(&self, channel: u16) {
        let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(prev) = binds.remove(&channel) {
            if prev.nonce.is_some() {
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    /// Whether this channel is bound by a `direct` principal (Gate 1). A non-direct
    /// or absent bind can never reach an admin op.
    fn is_direct(&self, channel: u16) -> bool {
        let binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        matches!(
            binds.get(&channel).map(|b| &b.principal),
            Some(Principal::Direct)
        )
    }

    /// Issue a fresh challenge nonce for a bind. Gate 1 enforced. Replaces any prior
    /// nonce on this bind (at most one outstanding per bind). Refused if the global
    /// outstanding cap is reached (never evicts another bind's nonce).
    pub fn challenge(&self, channel: u16) -> AdminOutcome {
        if !self.is_direct(channel) {
            return AdminOutcome::Refused("admin ops require a direct bind".into());
        }
        let nonce_bytes = match credentials_core::admin_auth::generate_admin_nonce() {
            Ok(n) => n,
            Err(e) => return AdminOutcome::Refused(format!("csprng: {e}")),
        };

        let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
        let Some(state) = binds.get_mut(&channel) else {
            return AdminOutcome::Refused("admin ops require a direct bind".into());
        };
        // Reissuing replaces this bind's own nonce (net-zero on the counter); a fresh
        // nonce needs a global slot only when this bind had none.
        if state.nonce.is_none() {
            // Reserve a global slot; refuse if full (never evict a peer's live nonce).
            let prior = self.outstanding_nonces.fetch_add(1, Ordering::SeqCst);
            if prior as usize >= MAX_OUTSTANDING_NONCES {
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
                return AdminOutcome::Refused("admin challenge capacity reached".into());
            }
        }
        state.nonce = Some(Nonce {
            bytes: nonce_bytes,
            issued: Instant::now(),
            generation: state.generation,
        });

        AdminOutcome::Challenge {
            nonce_hex: hex(&nonce_bytes),
            vault_id_hex: hex(&self.vault_id),
            key_id_hex: self.key_id.to_hex(),
        }
    }

    /// Execute an admin op. `op_body` is the EXACT authenticated bytes; `tag_hex` is
    /// the caller's MAC over the transcript. Verify-then-claim-then-parse-then-execute:
    /// the nonce is claimed atomically only after the MAC verifies, and the body is
    /// parsed only after the nonce is claimed.
    pub async fn execute(&self, channel: u16, op_body: &[u8], tag_hex: &str) -> AdminOutcome {
        // Gate 1.
        if !self.is_direct(channel) {
            return AdminOutcome::Refused("admin ops require a direct bind".into());
        }
        if op_body.len() > MAX_OP_BODY_LEN {
            return AdminOutcome::Refused("admin op body too large".into());
        }
        let Some(tag) = decode_hex(tag_hex) else {
            return AdminOutcome::Refused("malformed auth tag".into());
        };

        // Gate 2 + atomic nonce claim. Hold the bind lock across verify+claim so two
        // concurrent replays of the same (nonce, tag) cannot both pass — exactly one
        // claims the nonce; the other sees it already taken.
        let claimed_nonce = {
            let mut binds = self.binds.lock().unwrap_or_else(|p| p.into_inner());
            let Some(state) = binds.get_mut(&channel) else {
                return AdminOutcome::Refused("admin ops require a direct bind".into());
            };
            let Some(nonce) = state.nonce.as_ref() else {
                return AdminOutcome::Refused("no outstanding challenge".into());
            };
            // Same-generation requirement: a rebind (new generation) invalidates a
            // nonce issued to the old one.
            if nonce.generation != state.generation {
                state.nonce = None;
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
                return AdminOutcome::Refused("challenge is from a stale bind".into());
            }
            if nonce.issued.elapsed() > NONCE_TTL {
                state.nonce = None;
                self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
                return AdminOutcome::Refused("challenge expired".into());
            }
            // Verify the MAC over the exact op bytes BEFORE consuming the nonce, so a
            // wrong guess cannot burn a caller's outstanding challenge.
            let parts = TranscriptParts {
                vault_id: &self.vault_id,
                key_id: self.key_id,
                nonce: &nonce.bytes,
                op_body,
            };
            if !self.mac_key.verify(&parts, &tag) {
                return AdminOutcome::Refused("auth failed".into());
            }
            // Verified: claim the nonce (single-use). The next replay finds none.
            let claimed = state.nonce.take().expect("checked Some above");
            self.outstanding_nonces.fetch_sub(1, Ordering::SeqCst);
            claimed.bytes
        };
        let _ = claimed_nonce; // (kept for clarity; the claim is the side effect above)

        // Parse-AFTER-verify: the body is opaque until the MAC proves possession.
        let op: AdminOpBody = match serde_json::from_slice(op_body) {
            Ok(op) => op,
            Err(e) => return AdminOutcome::Refused(format!("admin op body not decodable: {e}")),
        };
        self.dispatch(op).await
    }

    async fn dispatch(&self, op: AdminOpBody) -> AdminOutcome {
        // Every op carries a schema version `v`; this module speaks exactly v1. An
        // unknown version is refused (never best-effort-parsed) so a future field
        // addition can't be silently dropped by an old module — the caller learns
        // the module is too old rather than getting a partial write.
        if op.schema_version() != ADMIN_OP_SCHEMA_V1 {
            return AdminOutcome::Refused(format!(
                "unsupported admin op schema version {} (module speaks {})",
                op.schema_version(),
                ADMIN_OP_SCHEMA_V1
            ));
        }
        // Apply through the SHARED core applier so the online and offline admin paths
        // can never diverge in what an op does. A credential-scoped op runs under the
        // engine's per-credential single-flight lock (same lock a refresh holds), so
        // an admin write and a refresh for one credential are strictly serialized;
        // revoke-by-handle names no credential, so it commits directly.
        let result = match op.lock_id() {
            Some(_) => {
                let lock_id = op.lock_id().expect("Some checked").to_string();
                self.engine
                    .with_admin_lock(&lock_id, move |store| {
                        credentials_core::admin_ops::apply(store, op, ROUTE_ADMIN_ACTOR)
                    })
                    .await
            }
            None => credentials_core::admin_ops::apply(self.engine.store(), op, ROUTE_ADMIN_ACTOR),
        };
        match result {
            Ok(v) => AdminOutcome::Ok(v),
            Err(e) => store_err(e),
        }
    }
}

/// Map a store error to a non-secret refusal. Admin ops are authenticated, so a bit
/// more detail than the anonymous read surface is acceptable (the caller holds the
/// master key), but never secret material.
fn store_err(e: StoreOpError) -> AdminOutcome {
    let reason = match e {
        StoreOpError::NotFound => "credential not found".to_string(),
        StoreOpError::CasMismatch => "version/hash mismatch (concurrent change)".to_string(),
        StoreOpError::AlreadyExists => "credential already exists".to_string(),
        StoreOpError::Fenced { .. } => "fenced out by a newer writer".to_string(),
        other => format!("store error: {other}"),
    };
    AdminOutcome::Refused(reason)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
    use credentials_core::audit::{AuditCtx, AuditOp};
    use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
    use credentials_core::record::{CredentialKind, RecordIdentity, VaultRecord};
    use credentials_core::store::{mint_handle, EncryptedStore};
    use credentials_core::vault_id_for;

    /// A test rig: the AdminSurface plus everything a caller-side signer needs
    /// (the same MAC key derivation the CLI would perform from the keychain key).
    struct Rig {
        admin: AdminSurface,
        store: Arc<EncryptedStore>,
        caller_mac: AdminMacKey,
        vault_id: [u8; VAULT_ID_LEN],
        key_id: KeyId,
    }

    fn rig(seed: u8) -> Rig {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-admin-surface-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("mkdir");
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "default".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: root.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let store = open_sqlite(&descriptor).expect("open");
        EncryptedStore::migrate(&store).expect("migrate");
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        let mac_key = AdminMacKey::derive(&key);
        let caller_mac = AdminMacKey::derive(&MasterKey::from_bytes([seed; MASTER_KEY_LEN]));
        let key_id = key.key_id();
        let vault_id = vault_id_for(&root).expect("vault id");
        let store = Arc::new(EncryptedStore::open(store, key).expect("open vault"));
        let http = Arc::new(crate::test_support::NoHttp);
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
        Rig {
            admin: AdminSurface::new(engine, mac_key, vault_id, key_id),
            store,
            caller_mac,
            vault_id,
            key_id,
        }
    }

    /// Caller side: fetch a challenge and sign the op body exactly as the CLI would.
    fn challenge_and_sign(rig: &Rig, channel: u16, op_body: &str) -> (String, String) {
        let AdminOutcome::Challenge { nonce_hex, .. } = rig.admin.challenge(channel) else {
            panic!("challenge refused");
        };
        let nonce_vec = decode_hex(&nonce_hex).expect("nonce hex");
        let nonce: [u8; ADMIN_NONCE_LEN] = nonce_vec.as_slice().try_into().expect("nonce len");
        let parts = TranscriptParts {
            vault_id: &rig.vault_id,
            key_id: rig.key_id,
            nonce: &nonce,
            op_body: op_body.as_bytes(),
        };
        (hex(&rig.caller_mac.sign(&parts)), nonce_hex)
    }

    fn store_op_body(id: &str) -> String {
        let record =
            VaultRecord::new_static(CredentialKind::ApiKey, "test", b"sk-1".to_vec(), None);
        serde_json::json!({
            "v": 1,
            "op": "admin.store",
            "id": id,
            "record": record,
            "audit_op": "put",
            "mode": { "kind": "create" },
        })
        .to_string()
    }

    #[tokio::test]
    async fn direct_bind_full_round_trip_stores_a_credential() {
        let r = rig(1);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:new");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(out, AdminOutcome::Ok(_)), "store should succeed");
        // The write is REAL: the record is in the store, audited as route-admin.
        let rec = r.store.get("apikey:new").expect("stored");
        assert_eq!(rec.payload, b"sk-1");
        let entries = r.store.read_audit(None).expect("audit");
        let last = entries.last().expect("an entry");
        assert_eq!(last.actor, "route-admin");
        assert_eq!(last.op, "put");
    }

    #[tokio::test]
    async fn direct_bind_set_identity_reseals_an_oauth_record_without_replacing_its_secret() {
        let r = rig(11);
        r.admin.record_bind(5, Principal::Direct);
        let record = VaultRecord::new_oauth(
            "test",
            "anthropic",
            credentials_core::oauth::OAuthCredential {
                access_token: "opaque-access".to_string(),
                refresh_token: "refresh-secret".to_string(),
                expires_at_ms: Some(4_102_444_800_000),
                token_url: "https://example.invalid/token".to_string(),
                client_id: Some("identity-test-client".to_string()),
                scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
            },
            b"opaque-access".to_vec(),
        );
        r.store
            .create("oauth:anthropic", &record)
            .expect("seed OAuth record");
        let before = r.store.get("oauth:anthropic").expect("before");
        let op = AdminOpBody::SetIdentity {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:anthropic".to_string(),
            identity: RecordIdentity {
                account_id: Some("acct-routed".to_string()),
                email: Some("routed@example.com".to_string()),
                org_name: None,
            },
        };
        let body = String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let outcome = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(outcome, AdminOutcome::Ok(_)),
            "set identity must route"
        );
        let after = r.store.get("oauth:anthropic").expect("after");
        assert_eq!(
            after.payload, before.payload,
            "route op must preserve payload bytes"
        );
        assert_eq!(
            after.oauth, before.oauth,
            "route op must preserve OAuth material"
        );
        assert_eq!(after.identity.account_id.as_deref(), Some("acct-routed"));
        assert_eq!(
            r.store
                .read_audit(None)
                .expect("audit")
                .last()
                .expect("entry")
                .op,
            "set_identity"
        );
    }

    #[tokio::test]
    async fn direct_bind_set_identity_refuses_an_empty_account_id_at_the_store_sink() {
        let r = rig(12);
        r.admin.record_bind(5, Principal::Direct);
        r.store
            .create(
                "oauth:anthropic",
                &VaultRecord::new_oauth(
                    "test",
                    "anthropic",
                    credentials_core::oauth::OAuthCredential {
                        access_token: "opaque-access".to_string(),
                        refresh_token: "refresh-secret".to_string(),
                        expires_at_ms: Some(4_102_444_800_000),
                        token_url: "https://example.invalid/token".to_string(),
                        client_id: Some("identity-test-client".to_string()),
                        scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
                    },
                    b"opaque-access".to_vec(),
                ),
            )
            .expect("seed OAuth record");
        let op = AdminOpBody::SetIdentity {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:anthropic".to_string(),
            identity: RecordIdentity {
                account_id: Some(String::new()),
                email: None,
                org_name: None,
            },
        };
        let body = String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let outcome = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(outcome, AdminOutcome::Refused(ref message) if message.contains("account_id")),
            "a MAC-authenticated op must still be refused for invalid identity"
        );
        assert!(
            r.store
                .get("oauth:anthropic")
                .expect("record remains readable")
                .identity
                .is_empty(),
            "the rejected operation must not persist any metadata"
        );
    }

    #[tokio::test]
    async fn direct_bind_store_refuses_an_invalid_import_identity() {
        let r = rig(13);
        r.admin.record_bind(5, Principal::Direct);
        let record = VaultRecord::new_oauth(
            "import",
            "anthropic",
            credentials_core::oauth::OAuthCredential {
                access_token: "opaque-access".to_string(),
                refresh_token: "refresh-secret".to_string(),
                expires_at_ms: Some(4_102_444_800_000),
                token_url: "https://example.invalid/token".to_string(),
                client_id: Some("identity-test-client".to_string()),
                scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
            },
            b"opaque-access".to_vec(),
        )
        .with_identity(RecordIdentity {
            account_id: Some("acct-good".to_string()),
            email: Some("invalid\u{0007}email@example.com".to_string()),
            org_name: None,
        });
        let op = AdminOpBody::Store {
            v: ADMIN_OP_SCHEMA_V1,
            id: "oauth:anthropic".to_string(),
            record: Box::new(record),
            audit_op: credentials_core::admin_ops::AdminAuditOp::Import,
            mode: credentials_core::admin_ops::StoreMode::Create,
        };
        let body = String::from_utf8(op.to_bytes().expect("encode op")).expect("UTF-8 JSON");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let outcome = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(outcome, AdminOutcome::Refused(ref message) if message.contains("email")),
            "authenticated imports must enforce the same store identity boundary"
        );
        assert!(r.store.get("oauth:anthropic").is_err());
    }

    #[tokio::test]
    async fn non_direct_principals_never_reach_admin() {
        let r = rig(2);
        let body = store_op_body("apikey:x");

        // Each arm asserts the refusal REASON, not merely that a refusal happened: a
        // non-direct caller has no outstanding challenge either, so a wildcard match is
        // satisfied by the missing-nonce refusal and would still pass with Gate 1
        // deleted. Naming the reason is what makes these tests about Gate 1.
        const GATE_1: &str = "require a direct bind";

        // Reserved bind: challenge refused.
        r.admin.record_bind(
            3,
            Principal::Reserved {
                module_id: "llm-runner".into(),
            },
        );
        assert!(matches!(r.admin.challenge(3), AdminOutcome::Refused(ref m) if m.contains(GATE_1)));
        // Unverified bind (absent stamp records as this): refused.
        r.admin.record_bind(4, Principal::Unverified);
        assert!(matches!(r.admin.challenge(4), AdminOutcome::Refused(ref m) if m.contains(GATE_1)));
        // Never-bound channel: refused.
        assert!(matches!(r.admin.challenge(9), AdminOutcome::Refused(ref m) if m.contains(GATE_1)));
        // Execute without a direct bind is refused even with a (meaningless) tag.
        let out = r.admin.execute(3, body.as_bytes(), "00").await;
        assert!(
            matches!(out, AdminOutcome::Refused(ref m) if m.contains(GATE_1)),
            "execute must refuse on Gate 1, not on the absent challenge behind it"
        );
        // Nothing was written.
        assert!(r.store.get("apikey:x").is_err());
    }

    #[tokio::test]
    async fn replay_of_a_valid_tag_is_refused_nonce_claimed() {
        let r = rig(3);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:once");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        let first = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(first, AdminOutcome::Ok(_)));
        // The exact same (body, tag) again: the nonce is consumed — refused.
        let replay = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(replay, AdminOutcome::Refused(ref m) if m.contains("challenge")),
            "replay must be refused for lack of an outstanding challenge"
        );
    }

    #[tokio::test]
    async fn a_tag_for_op_a_cannot_authorize_op_b() {
        let r = rig(4);
        r.admin.record_bind(5, Principal::Direct);
        let body_a = store_op_body("apikey:a");
        let body_b = store_op_body("apikey:b");
        let (tag_a, _) = challenge_and_sign(&r, 5, &body_a);

        // Splice: op B with A's tag — MAC covers the exact bytes, so refused, and
        // the failed attempt does NOT burn the outstanding nonce...
        let out = r.admin.execute(5, body_b.as_bytes(), &tag_a).await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("auth failed")));
        assert!(
            r.store.get("apikey:b").is_err(),
            "spliced op must not execute"
        );
        // ...so the legitimate op A still goes through on the same challenge.
        let ok = r.admin.execute(5, body_a.as_bytes(), &tag_a).await;
        assert!(
            matches!(ok, AdminOutcome::Ok(_)),
            "original op survives a failed splice"
        );
    }

    #[tokio::test]
    async fn wrong_master_key_tag_is_refused() {
        let r = rig(5);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:wrongkey");
        // Sign with a DIFFERENT master key's derived MAC.
        let AdminOutcome::Challenge { nonce_hex, .. } = r.admin.challenge(5) else {
            panic!("challenge refused");
        };
        let nonce: [u8; ADMIN_NONCE_LEN] = decode_hex(&nonce_hex)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let wrong = AdminMacKey::derive(&MasterKey::from_bytes([99; MASTER_KEY_LEN]));
        let tag = hex(&wrong.sign(&TranscriptParts {
            vault_id: &r.vault_id,
            key_id: r.key_id,
            nonce: &nonce,
            op_body: body.as_bytes(),
        }));

        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("auth failed")));
        assert!(r.store.get("apikey:wrongkey").is_err());
    }

    #[tokio::test]
    async fn expired_nonce_is_refused() {
        let r = rig(6);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:late");
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        r.admin
            .backdate_nonce_for_test(5, NONCE_TTL + Duration::from_secs(1));

        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("expired")));
        assert!(r.store.get("apikey:late").is_err());
    }

    #[tokio::test]
    async fn rebind_invalidates_an_outstanding_challenge() {
        let r = rig(7);
        r.admin.record_bind(5, Principal::Direct);
        let body = store_op_body("apikey:rebind");
        let (tag, _) = challenge_and_sign(&r, 5, &body);

        // A rebind of the same channel (lost-Goodbye self-heal): fresh generation,
        // no nonce — the old challenge cannot authorize anything.
        r.admin.record_bind(5, Principal::Direct);
        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("challenge")));
        assert!(r.store.get("apikey:rebind").is_err());
    }

    #[tokio::test]
    async fn unsupported_schema_version_is_refused_after_auth() {
        let r = rig(8);
        r.admin.record_bind(5, Principal::Direct);
        let record = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"sk".to_vec(), None);
        let body = serde_json::json!({
            "v": 2,
            "op": "admin.invalidate",
            "id": "apikey:v2",
            "record": record,
        })
        .to_string();
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        assert!(
            matches!(out, AdminOutcome::Refused(ref m) if m.contains("schema version")),
            "v=2 must be refused, not best-effort parsed"
        );
    }

    #[tokio::test]
    async fn oversize_body_is_refused_before_mac_work() {
        let r = rig(9);
        r.admin.record_bind(5, Principal::Direct);
        let body = "x".repeat(MAX_OP_BODY_LEN + 1);
        let out = r.admin.execute(5, body.as_bytes(), "00").await;
        assert!(matches!(out, AdminOutcome::Refused(ref m) if m.contains("too large")));
    }

    #[tokio::test]
    async fn compound_invalidate_revokes_handles_atomically() {
        let r = rig(10);
        r.admin.record_bind(5, Principal::Direct);

        // Seed a credential with two live handles.
        r.store
            .create(
                "apikey:dead",
                &VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None),
            )
            .unwrap();
        let h1 = mint_handle().unwrap();
        let h2 = mint_handle().unwrap();
        let ctx = AuditCtx::admin(AuditOp::MintHandle);
        r.store
            .put_handle_hash(&h1.hash, "apikey:dead", ctx)
            .unwrap();
        r.store
            .put_handle_hash(&h2.hash, "apikey:dead", ctx)
            .unwrap();

        let body = serde_json::json!({
            "v": 1,
            "op": "admin.invalidate",
            "id": "apikey:dead",
        })
        .to_string();
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        let out = r.admin.execute(5, body.as_bytes(), &tag).await;
        let AdminOutcome::Ok(v) = out else {
            panic!("invalidate refused");
        };
        assert_eq!(v["handles_revoked"], 2);
        // The credential is needs_reauth AND both handles are dead.
        assert!(matches!(
            r.store.get("apikey:dead"),
            Err(StoreOpError::NeedsReauth)
        ));
        // resolve_handle returns NotFound for a revoked handle (uniform not-found).
        assert!(matches!(
            r.store.resolve_handle(&h1.raw),
            Err(StoreOpError::NotFound)
        ));
        assert!(matches!(
            r.store.resolve_handle(&h2.raw),
            Err(StoreOpError::NotFound)
        ));
    }

    #[tokio::test]
    async fn mint_handle_returns_a_resolvable_handle() {
        let r = rig(11);
        r.admin.record_bind(5, Principal::Direct);
        r.store
            .create(
                "apikey:h",
                &VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None),
            )
            .unwrap();

        let body =
            serde_json::json!({ "v": 1, "op": "admin.mint_handle", "id": "apikey:h" }).to_string();
        let (tag, _) = challenge_and_sign(&r, 5, &body);
        let AdminOutcome::Ok(v) = r.admin.execute(5, body.as_bytes(), &tag).await else {
            panic!("mint refused");
        };
        let raw = v["handle"].as_str().expect("handle string");
        assert!(raw.starts_with("ckh_"));
        assert_eq!(r.store.resolve_handle(raw).expect("resolve"), "apikey:h");
    }

    #[tokio::test]
    async fn challenge_capacity_is_bounded_and_never_evicts() {
        let r = rig(12);
        // Fill the global nonce table from distinct binds.
        for ch in 0..MAX_OUTSTANDING_NONCES as u16 {
            r.admin.record_bind(ch, Principal::Direct);
            assert!(matches!(
                r.admin.challenge(ch),
                AdminOutcome::Challenge { .. }
            ));
        }
        // The next NEW bind's challenge is refused (no eviction of live nonces).
        let overflow_ch = MAX_OUTSTANDING_NONCES as u16;
        r.admin.record_bind(overflow_ch, Principal::Direct);
        assert!(matches!(
            r.admin.challenge(overflow_ch),
            AdminOutcome::Refused(ref m) if m.contains("capacity")
        ));
        // But an EXISTING bind reissuing its own challenge still works (replace, not add).
        assert!(matches!(
            r.admin.challenge(0),
            AdminOutcome::Challenge { .. }
        ));
        // And dropping a bind frees capacity for the newcomer.
        r.admin.drop_bind(0);
        assert!(matches!(
            r.admin.challenge(overflow_ch),
            AdminOutcome::Challenge { .. }
        ));
    }
}
