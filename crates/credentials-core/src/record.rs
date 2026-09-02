//! The typed vault record.
//!
//! A [`VaultRecord`] is the vault's INTERNAL, typed view of one credential: enough
//! structure for the vault to reason about freshness and refresh. The consumer
//! never sees this type — a `get` returns only the opaque `payload` bytes. The
//! whole record is encrypted at rest as a single unit, so none of the internal
//! fields (the OAuth tokens, the source, the adapter name) leak to a read.
//!
//! ## Plaintext vs encrypted
//!
//! Two fields are kept ALSO as plaintext columns beside the ciphertext, because
//! the store must read them without decrypting:
//! - `record_version` — the monotonic version, bumped on every write/refresh. It
//!   is bound into the cipher envelope's authenticated data (anti-rollback), so the
//!   plaintext column and the ciphertext are always written together in one fenced
//!   transaction; a read uses it to build the decrypt binding and to power the
//!   consumer's `record_version`-keyed cache.
//! - the key fingerprint — so a master-key rotation scan can find records under the
//!   old key without decrypting every row.
//!
//! Everything else here is part of the encrypted plaintext.

use serde::{Deserialize, Serialize};

use crate::oauth::OAuthCredential;

/// The current schema version of the encrypted record body. Bumped only when the
/// record's PLAINTEXT structure changes in a way a decoder must branch on; it is
/// independent of the cipher envelope's `cipher_version`.
pub const RECORD_SCHEMA_VERSION: u32 = 1;

/// What kind of credential a record holds. Drives whether refresh applies and how
/// the payload is interpreted by its consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// An OAuth credential with refreshable tokens (`oauth` is populated).
    Oauth,
    /// A static API key (no refresh).
    ApiKey,
    /// A database connection string.
    Dsn,
    /// A manually captured session-cookie header. The payload remains opaque, has no
    /// declared expiry, and is never refreshable.
    Cookie,
    /// Opaque bytes with no vault-understood structure (no refresh).
    Opaque,
    /// A private signing key the vault EXERCISES on behalf of a caller rather than
    /// serving: see `credential.sign`.
    ///
    /// This kind is the FENCE, not a label. `credential.sign` refuses every other
    /// kind with `kind_not_signable`, so without it a capability handle for an API
    /// key could produce signatures under that key and the vault would be a general
    /// signing oracle over every stored secret.
    ///
    /// Enforced in the type deliberately, and NOT derived from the credential id: a
    /// prefix is not authoritative here (this repo already rejected prefix-parsing
    /// for adapter selection, because the stored adapter can be overridden at write
    /// time, and the same argument applies to anything a writer controls).
    ///
    /// A record of this kind is still served by `credential.get` if a handle
    /// resolves to it -- the kind restricts what the vault will DO, not what it will
    /// disclose. Callers that must never see key material should not hold a get-
    /// capable handle for one.
    SigningKey,
}

/// The non-secret lifecycle state of a stored record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    /// Decryptable and serveable.
    Active,
    /// Authoritatively invalidated (revoke / a static-record report): the credential
    /// is present but must not be served until re-auth.
    NeedsReauth,
    /// Intentionally withdrawn by an operator through `logout`. Retired credentials
    /// remain unreadable to consumers, but are not a health alarm.
    Retired,
    /// Undecryptable / corrupt: quarantined so a `get` fails closed for this id
    /// while the rest of the vault keeps serving.
    Corrupt,
}

impl RecordState {
    /// The stable lowercase wire/display form (also what the `state` column stores).
    pub fn as_str(self) -> &'static str {
        match self {
            RecordState::Active => "active",
            RecordState::NeedsReauth => "needs_reauth",
            RecordState::Retired => "retired",
            RecordState::Corrupt => "corrupt",
        }
    }

    pub(crate) fn from_str(s: &str) -> RecordState {
        match s {
            "active" => RecordState::Active,
            "needs_reauth" => RecordState::NeedsReauth,
            "retired" => RecordState::Retired,
            // `corrupt` and ANY unrecognized value fail closed to Corrupt: an
            // unknown lifecycle string must never be served as if active.
            _ => RecordState::Corrupt,
        }
    }
}

/// NON-SECRET provider account identity, captured once at login from the token
/// exchange response (Anthropic returns it inline; OpenAI carries it in id_token
/// claims). Stored because some providers' access tokens are opaque (Anthropic), so
/// identity cannot be parsed live at serve time the way the OpenAI claim table does.
/// Display/routing metadata only — never part of an authorization decision.
///
/// THE TWO IDENTITY FIELDS ARE NOT INTERCHANGEABLE, and which one a capture site
/// fills decides whether consumers can tell accounts apart. `account_id` is what the
/// read surface serves as identity and what consumers join on; `email` is display
/// metadata. A record carrying only `email` therefore RENDERS a value while
/// resolving no identity, which presents downstream as accounts collapsing into one
/// unlabelled entry -- a symptom that looks like the capture never happened.
///
/// So: never populate `email` alone. When a provider discloses only an email (opaque
/// tokens, no claim to parse), put it in BOTH fields -- consumers treat `account_id`
/// as an opaque stable string, and an email satisfies that. [`Self::is_servable`]
/// states the rule as a predicate.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordIdentity {
    /// The provider's stable account id (Anthropic account uuid, ChatGPT account id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// The account email, when the provider disclosed it at login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Human-readable organization/workspace name (the subscription the token draws
    /// limits from), when disclosed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
}

impl RecordIdentity {
    /// Validate the bounded non-secret labels before a store write. Keeping this at
    /// the record boundary prevents authenticated admin-op bytes from bypassing CLI
    /// validation and making account grouping depend on malformed metadata.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(account_id) = self.account_id.as_deref() {
            if account_id.trim().is_empty() {
                return Err("account_id must not be empty".to_string());
            }
            validate_identity_value("account_id", account_id)?;
        }
        if let Some(email) = self.email.as_deref() {
            validate_identity_value("email", email)?;
        }
        if let Some(org_name) = self.org_name.as_deref() {
            validate_identity_value("org_name", org_name)?;
        }
        Ok(())
    }

    /// Drop email-only identity before validation or persistence; consumers join on
    /// account_id, so keeping its display-only counterpart would advertise a label
    /// that cannot identify an account.
    pub(crate) fn normalized(self) -> Self {
        if self.is_servable() {
            self
        } else {
            RecordIdentity {
                account_id: None,
                email: None,
                org_name: self.org_name,
            }
        }
    }

    /// Whether this identity can be served without collapsing a consumer's labelling.
    ///
    /// False for the one shape that looks captured and behaves as though it was not:
    /// an `email` with no `account_id`. Written as a predicate rather than left in
    /// prose so a capture site can be tested against it, since the failure is silent
    /// at every layer -- it type-checks, it stores, it serves, and it surfaces only as
    /// a consumer that cannot distinguish two accounts.
    pub fn is_servable(&self) -> bool {
        !(self.email.is_some() && self.account_id.is_none())
    }

    /// Whether every field is absent (nothing worth storing).
    pub fn is_empty(&self) -> bool {
        self.account_id.is_none() && self.email.is_none() && self.org_name.is_none()
    }
}

fn validate_identity_value(field: &str, value: &str) -> Result<(), String> {
    if value.len() > 256 {
        return Err(format!("{field} must be at most 256 bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} must not contain control characters"));
    }
    Ok(())
}

/// The vault's typed, at-rest view of one credential. Encrypted as one unit; only
/// `payload` is ever returned to a consumer.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRecord {
    /// Schema version of this record body (see [`RECORD_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// What kind of credential this is.
    pub kind: CredentialKind,
    /// Where the credential was acquired from: `opencode` | `pi` | `antigravity` |
    /// `operator`. Provenance for audit and import reconciliation.
    pub source: String,
    /// Monotonic version, bumped on every write/refresh. Mirrored to a plaintext
    /// column and bound into the cipher AAD (see the module docs).
    pub record_version: u64,
    /// Access-token / credential expiry as a Unix timestamp in milliseconds, when
    /// known. Drives refresh-on-`get`.
    pub expires_at_ms: Option<i64>,
    /// Names the bounded refresh adapter to use (e.g. `anthropic`), when this
    /// credential is refreshable. `None` for non-refreshable kinds.
    pub refresh_adapter: Option<String>,
    /// The canonical OAuth credential, present when `kind == Oauth`.
    pub oauth: Option<OAuthCredential>,
    /// The opaque bytes returned to a consumer verbatim by a `get`. For an OAuth
    /// credential this is typically the serialized form the consumer expects (e.g.
    /// the access token / an auth header value); the vault does not interpret it.
    pub payload: Vec<u8>,
    /// Non-secret account identity captured at login. `default` so records sealed
    /// before this field existed decode with an empty identity (additive schema
    /// evolution under the same `schema_version`, like any other optional field).
    #[serde(default, skip_serializing_if = "RecordIdentity::is_empty")]
    pub identity: RecordIdentity,
}

/// Redacted `Debug`, because the derived one printed the secret this struct exists to
/// protect -- and printed it NEXT TO the same secret already redacted.
///
/// Measured on the derived impl before this replaced it, one record, one line:
///
/// ```text
/// oauth: Some(OAuthCredential { access_token: "<redacted>", refresh_token: "<redacted>" })
/// payload: [115, 107, 45, 83, 69, 67, 82, 69, 84, 45, 65, 67, 67, 69, 83, 83]
/// ```
///
/// Those bytes are `sk-SECRET-ACCESS`: for an OAuth record the payload IS typically the
/// access token, so `OAuthCredential`'s careful redaction was defeated by the field
/// beside it. Two disclosure policies inside one struct, and the weaker one wins for any
/// reader who formats the whole record.
///
/// A byte array is the worst possible shape for this. A reader skimming a log sees
/// numeric noise rather than something secret-shaped, so it does not trigger the alarm a
/// quoted token would -- while being trivially decodable by anyone who wants to.
///
/// No current call site formats a `VaultRecord`, so this is a latent hazard rather than a
/// live leak. It is worth closing anyway: the whole value of a redaction convention is
/// that a future `{:?}` added in a hurry is safe by default, and a convention with a hole
/// in it teaches the wrong lesson to whoever reads it next.
impl std::fmt::Debug for VaultRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultRecord")
            .field("schema_version", &self.schema_version)
            .field("kind", &self.kind)
            .field("source", &self.source)
            .field("record_version", &self.record_version)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("refresh_adapter", &self.refresh_adapter)
            // Delegates to OAuthCredential's own redacting impl.
            .field("oauth", &self.oauth)
            // LENGTH ONLY. It is non-secret, and it is the one fact a diagnostic
            // actually needs here: the empty-payload quarantine path exists precisely
            // because a zero-length payload is a real corruption mode.
            .field(
                "payload",
                &format_args!("[{} bytes redacted]", self.payload.len()),
            )
            // Non-secret by design: email and org name are returned to consumers as
            // display metadata on every `get`.
            .field("identity", &self.identity)
            .finish()
    }
}

impl VaultRecord {
    /// Construct an OAuth record at version 1 from a canonical credential and the
    /// opaque payload a consumer should receive. `expires_at_ms` is taken from the
    /// credential so freshness logic has it without decrypting `oauth`.
    pub fn new_oauth(
        source: impl Into<String>,
        refresh_adapter: impl Into<String>,
        oauth: OAuthCredential,
        payload: Vec<u8>,
    ) -> Self {
        let expires_at_ms = oauth.expires_at_ms;
        VaultRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            kind: CredentialKind::Oauth,
            source: source.into(),
            record_version: 1,
            expires_at_ms,
            refresh_adapter: Some(refresh_adapter.into()),
            oauth: Some(oauth),
            payload,
            identity: RecordIdentity::default(),
        }
    }

    /// Attach non-secret account identity (builder-style, used by login flows that
    /// capture identity from the exchange response).
    ///
    /// AN EMAIL WITH NO `account_id` IS NORMALISED AWAY HERE rather than stored,
    /// because that shape is worse than storing nothing: the read surface serves
    /// `account_id` as the identity consumers resolve and `email` as display, so the
    /// record would render a value while resolving nothing and a consumer labelling
    /// per account would collapse its accounts into one unlabelled entry -- a symptom
    /// that reads as "identity was never captured".
    ///
    /// Enforced at the sink rather than trusted at each source. There are three
    /// capture sites and they do not share a shape: `account_id` has exactly two
    /// origins (Anthropic's inline account uuid, ChatGPT's token claim) while `email`
    /// has a third (any OIDC `id_token`), so a provider that returns an id_token
    /// without either account form produces the bad shape without anyone writing it
    /// deliberately. xAI requests `openid`+`email` and matches neither account form,
    /// so it is one provider-side response change away from doing exactly that.
    ///
    /// Normalising beats refusing: an identity is display metadata, and failing a
    /// login over it would trade a labelling gap for a lost credential.
    pub fn with_identity(mut self, identity: RecordIdentity) -> Self {
        self.identity = identity.normalized();
        self
    }

    /// Construct a static (non-refreshable) record at version 1: an API key, DSN,
    /// session cookie, or opaque blob. No OAuth, no refresh adapter.
    pub fn new_static(
        kind: CredentialKind,
        source: impl Into<String>,
        payload: Vec<u8>,
        expires_at_ms: Option<i64>,
    ) -> Self {
        debug_assert!(
            !matches!(kind, CredentialKind::Oauth),
            "new_static is for non-oauth kinds; use new_oauth for oauth"
        );
        VaultRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            kind,
            source: source.into(),
            record_version: 1,
            expires_at_ms,
            refresh_adapter: None,
            oauth: None,
            payload,
            identity: RecordIdentity::default(),
        }
    }

    /// Construct a manually captured session-cookie record. Cookie headers cannot
    /// carry `Set-Cookie` expiry attributes, so their expiry stays absent and provider
    /// rejection is reported through the normal auth-failure path.
    pub fn new_cookie(source: impl Into<String>, payload: Vec<u8>) -> Self {
        Self::new_static(CredentialKind::Cookie, source, payload, None)
    }

    /// Whether this record's credential is refreshable (OAuth with an adapter).
    pub fn is_refreshable(&self) -> bool {
        self.kind == CredentialKind::Oauth && self.refresh_adapter.is_some() && self.oauth.is_some()
    }

    /// Serialize the record body to the bytes that get encrypted. JSON is used for
    /// forward-compatible, self-describing field evolution under `schema_version`.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Decode a record body from decrypted plaintext bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payload never reaches a `Debug` rendering, in EITHER shape it could take.
    ///
    /// THE OBVIOUS VERSION OF THIS TEST PASSES ON THE BROKEN IMPL, which is the whole
    /// reason it is written this way. The derived `Debug` printed `payload: [115, 107,
    /// 45, ...]`, so a test asserting the secret's TEXT is absent finds nothing and goes
    /// green against the exact code it exists to reject. The leak and the assertion were
    /// looking at different encodings of the same bytes.
    ///
    /// So it asserts on the byte rendering too, and asserts the redaction marker IS
    /// present -- otherwise an impl that rendered nothing at all would also pass.
    #[test]
    fn debug_never_renders_payload_bytes_in_any_encoding() {
        let secret = b"sk-SECRET-ACCESS";
        let rec =
            VaultRecord::new_static(CredentialKind::ApiKey, "operator", secret.to_vec(), None);
        let rendered = format!("{rec:?}");

        assert!(
            !rendered.contains("sk-SECRET-ACCESS"),
            "the payload rendered as text: {rendered}"
        );
        // The shape the DERIVED impl actually produced. Without this arm the test is
        // green on the defect.
        let as_bytes = secret
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            !rendered.contains(&as_bytes),
            "the payload rendered as a byte array, which is the form the derived impl \
             leaked and the form a reader mistakes for noise: {rendered}"
        );
        // Proves the rendering happened at all, and that the length -- the one fact a
        // diagnostic needs -- survives.
        assert!(
            rendered.contains("16 bytes redacted"),
            "the redaction marker and byte count must be present: {rendered}"
        );
    }

    /// The identity shape that looks captured and serves as though it was not.
    ///
    /// `email` alone type-checks, stores, and serves — and then a consumer joining on
    /// `account_id` resolves nothing, so its accounts collapse into one unlabelled
    /// entry. The symptom is indistinguishable from never having captured an identity,
    /// which is why this is a predicate a capture site can be tested against rather
    /// than a sentence in a doc comment.
    #[test]
    fn an_email_without_an_account_id_is_not_servable() {
        let email_only = RecordIdentity {
            account_id: None,
            email: Some("a@x.com".into()),
            org_name: None,
        };
        assert!(
            !email_only.is_servable(),
            "email alone renders a value while resolving no identity"
        );

        // THE DISAMBIGUATORS: a predicate that simply returned false would satisfy the
        // assertion above. Each of these is a shape that MUST stay servable.
        assert!(
            RecordIdentity {
                account_id: Some("a@x.com".into()),
                email: Some("a@x.com".into()),
                org_name: None,
            }
            .is_servable(),
            "an email in both fields is the correct shape for an opaque-token provider"
        );
        assert!(
            RecordIdentity {
                account_id: Some("acct-uuid".into()),
                email: None,
                org_name: None,
            }
            .is_servable(),
            "an account_id with no email is fine — identity resolves"
        );
        assert!(
            RecordIdentity::default().is_servable(),
            "a record that captured nothing is not the failure being described: it \
             claims no identity, so nothing is misled"
        );
    }

    /// The sink drops an email that arrives without an `account_id`.
    ///
    /// The predicate alone only describes the bad shape; this is what stops it being
    /// STORED. Three capture sites write identities and they do not share a shape, so
    /// checking each source is a rule someone has to remember at a fourth -- and the
    /// site most likely to produce it (an OIDC id_token from a provider with no
    /// account claim) reaches the bad shape without anyone writing it deliberately.
    #[test]
    fn an_email_without_an_account_id_is_not_stored_on_the_record() {
        let record = VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None)
            .with_identity(RecordIdentity {
                account_id: None,
                email: Some("a@x.com".into()),
                org_name: Some("Acme".into()),
            });
        assert_eq!(
            record.identity.email, None,
            "an email that resolves no identity must not be stored: it renders a \
             value while labelling nothing"
        );
        assert_eq!(
            record.identity.org_name.as_deref(),
            Some("Acme"),
            "org_name is display-only and independent -- dropping it too would lose \
             information for no reason"
        );

        // THE DISAMBIGUATOR: a sink that dropped every identity would satisfy the
        // assertion above. A servable identity must survive intact.
        let kept = VaultRecord::new_static(CredentialKind::ApiKey, "t", b"k".to_vec(), None)
            .with_identity(RecordIdentity {
                account_id: Some("acct-1".into()),
                email: Some("a@x.com".into()),
                org_name: None,
            });
        assert_eq!(kept.identity.account_id.as_deref(), Some("acct-1"));
        assert_eq!(kept.identity.email.as_deref(), Some("a@x.com"));
    }

    fn oauth_cred() -> OAuthCredential {
        OAuthCredential {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_at_ms: Some(123),
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            scopes: vec![],
        }
    }

    #[test]
    fn oauth_record_round_trips_and_is_refreshable() {
        let r = VaultRecord::new_oauth("opencode", "anthropic", oauth_cred(), b"payload".to_vec());
        assert_eq!(r.schema_version, RECORD_SCHEMA_VERSION);
        assert_eq!(r.record_version, 1);
        assert_eq!(r.expires_at_ms, Some(123), "expiry mirrored from oauth");
        assert!(r.is_refreshable());
        let bytes = r.encode().unwrap();
        let back = VaultRecord::decode(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn static_record_is_not_refreshable() {
        let r =
            VaultRecord::new_static(CredentialKind::ApiKey, "operator", b"sk-123".to_vec(), None);
        assert!(!r.is_refreshable());
        assert!(r.oauth.is_none());
        assert!(r.refresh_adapter.is_none());
        let back = VaultRecord::decode(&r.encode().unwrap()).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn cookie_record_preserves_opaque_bytes_without_expiry_or_identity() {
        let payload = b" session=abc=123; preference=space value; ending=%".to_vec();
        let record = VaultRecord::new_cookie("operator", payload.clone());

        assert_eq!(record.kind, CredentialKind::Cookie);
        assert_eq!(record.payload, payload);
        assert_eq!(record.expires_at_ms, None);
        assert_eq!(record.identity, RecordIdentity::default());
        assert!(!record.is_refreshable());
        assert_eq!(
            VaultRecord::decode(&record.encode().unwrap()).unwrap(),
            record
        );
    }

    /// Pre-cookie record bodies used only the enum strings below. Seal those exact old
    /// plaintexts, then reopen and decode them to prove the additive enum variant does
    /// not make a persisted record of any pre-existing kind unreadable.
    #[test]
    fn existing_sealed_record_bodies_decode_after_adding_cookie_kind() {
        use crate::envelope::{open, seal, RecordBinding};
        use crate::key::{MasterKey, MASTER_KEY_LEN};

        let old_records: &[(CredentialKind, &[u8])] = &[
            (
                CredentialKind::Oauth,
                br#"{"schema_version":1,"kind":"oauth","source":"old","record_version":1,"expires_at_ms":123,"refresh_adapter":"old","oauth":{"access_token":"a","refresh_token":"r","expires_at_ms":123,"token_url":"https://example.invalid/token","client_id":null,"scopes":[]},"payload":[111,108,100]}"#,
            ),
            (CredentialKind::ApiKey, br#"{"schema_version":1,"kind":"api_key","source":"old","record_version":1,"expires_at_ms":null,"refresh_adapter":null,"oauth":null,"payload":[111,108,100]}"#),
            (CredentialKind::Dsn, br#"{"schema_version":1,"kind":"dsn","source":"old","record_version":1,"expires_at_ms":null,"refresh_adapter":null,"oauth":null,"payload":[111,108,100]}"#),
            (CredentialKind::Opaque, br#"{"schema_version":1,"kind":"opaque","source":"old","record_version":1,"expires_at_ms":null,"refresh_adapter":null,"oauth":null,"payload":[111,108,100]}"#),
            (CredentialKind::SigningKey, br#"{"schema_version":1,"kind":"signing_key","source":"old","record_version":1,"expires_at_ms":null,"refresh_adapter":null,"oauth":null,"payload":[111,108,100]}"#),
        ];
        let key = MasterKey::from_bytes([42; MASTER_KEY_LEN]);

        for (index, (expected_kind, old_body)) in old_records.iter().enumerate() {
            let id = format!("old:{index}");
            let binding = RecordBinding {
                credential_id: &id,
                record_version: 1,
            };
            let sealed = seal(&key, old_body, &binding).expect("seal historic body");
            let reopened = open(&key, &sealed, &binding).expect("open historic body");
            let record = VaultRecord::decode(&reopened).expect("decode historic body");
            assert_eq!(record.kind, *expected_kind, "historic {id} kind survives");
            assert_eq!(record.payload, b"old");
        }
    }

    #[test]
    fn kind_serializes_snake_case() {
        let json = serde_json::to_string(&CredentialKind::ApiKey).unwrap();
        assert_eq!(json, "\"api_key\"");
        assert_eq!(
            serde_json::to_string(&CredentialKind::Cookie).unwrap(),
            "\"cookie\""
        );
    }
}
