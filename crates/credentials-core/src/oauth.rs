//! The canonical OAuth credential.
//!
//! Every source format (opencode's `auth.json`, pi, antigravity) is parsed by its
//! importer into this ONE canonical shape, and the bounded refresh adapters
//! operate exclusively on it — never on raw provider JSON. That is what keeps
//! per-provider format knowledge at the import boundary instead of leaking it into
//! the refresh path: an adapter is handed a canonical credential and a token
//! endpoint, and it knows how to exchange a refresh token for a new access token.
//!
//! The access and refresh tokens are secrets. This type therefore has a redacted
//! `Debug` (it renders presence and non-secret metadata, never token bytes) and is
//! never logged in the clear. The whole [`VaultRecord`](crate::record::VaultRecord)
//! it lives in is encrypted at rest as one unit.

use serde::{Deserialize, Serialize};

pub const CUSTODY_TOMBSTONE_PREFIX: &str = "claustrum-tombstone:v1:";

fn is_custody_tombstone(value: &str) -> bool {
    value.starts_with(CUSTODY_TOMBSTONE_PREFIX)
}

/// A canonical OAuth credential: the provider-agnostic fields a refresh exchange
/// needs, plus the current tokens. Importers map each source format into this;
/// refresh adapters read and update it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthCredential {
    /// The current access token (bearer credential handed to the provider API).
    /// Secret.
    pub access_token: String,
    /// The current refresh token, exchanged at `token_url` for a new access token.
    /// Secret. Rotated by the provider on refresh for providers that follow
    /// RFC 9700 refresh-token rotation.
    pub refresh_token: String,
    /// Access-token expiry as a Unix timestamp in milliseconds, if the source
    /// provides one. Used to decide when a `get` must trigger a refresh.
    pub expires_at_ms: Option<i64>,
    /// The provider's token endpoint — where a refresh exchange is sent. Stored
    /// per-credential (canonicalized at import) so the refresh path never hardcodes
    /// or re-derives provider URLs.
    pub token_url: String,
    /// The OAuth client id, when the provider's refresh grant requires one.
    pub client_id: Option<String>,
    /// The granted scopes, when the source records them (re-sent on refresh by
    /// providers that require it). Empty when not applicable.
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl OAuthCredential {
    /// Whether the access token is expired (or within `skew_ms` of expiring) at
    /// `now_ms`. A credential with no recorded expiry is treated as not-expired
    /// here (freshness is then driven by `report_auth_failure` / `min_ttl_ms`),
    /// so this never forces a refresh it cannot reason about.
    pub fn is_access_expired(&self, now_ms: i64, skew_ms: i64) -> bool {
        match self.expires_at_ms {
            Some(exp) => now_ms.saturating_add(skew_ms) >= exp,
            None => false,
        }
    }

    /// Parse a source format's raw JSON into the canonical credential. This is the
    /// import boundary: per-source field knowledge lives HERE, never in the refresh
    /// path. v1 sources share the `auth.json` shape `{ refresh, access, expires }`
    /// (epoch-ms expiry) that the opencode / pi / antigravity logins write; the
    /// `token_url` / `client_id` an adapter needs are NOT in that file (the adapter
    /// carries the provider defaults), so they are left empty here and the adapter
    /// fills them. Unknown sources are rejected rather than guessed.
    ///
    /// `raw_json` here is a SINGLE provider's entry. The real on-disk `auth.json` is a
    /// MAP keyed by provider name; use [`import_provider`](Self::import_provider) to
    /// select one provider's entry from that map.
    pub fn import(source: &str, raw_json: &[u8]) -> Result<Self, ImportError> {
        match source {
            "opencode" | "pi" => Self::from_auth_json(raw_json),
            // The gemini-cli login (`~/.gemini/oauth_creds.json`) is a SINGLE-credential
            // file with its own field names. It is the correct source for a Google
            // credential the GoogleAdapter can refresh: that adapter uses the public
            // gemini-cli OAuth client, and a Google refresh token only refreshes against
            // its minting client — so a google token minted by some OTHER client (e.g.
            // opencode's own) cannot be refreshed here and must come from gemini-cli.
            "gemini-cli" => Self::from_gemini_creds(raw_json),
            other => Err(ImportError::UnknownSource(other.to_string())),
        }
    }

    /// Parse one provider's entry from a multi-provider auth file: the real
    /// `auth.json` is a JSON object keyed by provider (e.g. `{ "anthropic": { refresh,
    /// access, expires }, "google": { ... } }`), so `provider = "anthropic"` selects
    /// that sub-object and parses it like a single entry. This lets an operator point
    /// the importer at the real file once per provider instead of pre-extracting each
    /// sub-object by hand. A missing provider key is a typed error.
    pub fn import_provider(
        source: &str,
        raw_json: &[u8],
        provider: &str,
    ) -> Result<Self, ImportError> {
        match source {
            "opencode" | "pi" => {
                let map: serde_json::Value = serde_json::from_slice(raw_json)
                    .map_err(|e| ImportError::Malformed(e.to_string()))?;
                let entry = map
                    .get(provider)
                    .ok_or_else(|| ImportError::ProviderNotFound(provider.to_string()))?;
                let sub =
                    serde_json::to_vec(entry).map_err(|e| ImportError::Malformed(e.to_string()))?;
                Self::from_auth_json(&sub)
            }
            // gemini-cli's oauth_creds.json is a SINGLE-credential file, not a
            // provider-keyed map, so `--provider` does not apply: import it with the
            // plain `import` path (no `--provider`).
            "gemini-cli" => Err(ImportError::Malformed(
                "source 'gemini-cli' is a single-credential file; import without --provider".into(),
            )),
            other => Err(ImportError::UnknownSource(other.to_string())),
        }
    }

    /// Parse a gemini-cli `oauth_creds.json`: `{ "access_token": ..., "refresh_token":
    /// ..., "expiry_date": <epoch_ms> }`. This is the file the gemini-cli login writes
    /// (`~/.gemini/oauth_creds.json`); `expiry_date` is epoch MILLISECONDS, the same
    /// unit the canonical credential stores, and is optional. The refresh token is
    /// required (a credential with no refresh token cannot be kept fresh).
    fn from_gemini_creds(raw_json: &[u8]) -> Result<Self, ImportError> {
        #[derive(Deserialize)]
        struct GeminiCreds {
            #[serde(default)]
            access_token: Option<String>,
            #[serde(default)]
            refresh_token: Option<String>,
            #[serde(default)]
            expiry_date: Option<i64>,
        }
        let creds: GeminiCreds =
            serde_json::from_slice(raw_json).map_err(|e| ImportError::Malformed(e.to_string()))?;
        let refresh_token = creds
            .refresh_token
            .filter(|s| !s.is_empty())
            .ok_or(ImportError::MissingField("refresh_token"))?;
        let access_token = creds.access_token.unwrap_or_default();
        Ok(OAuthCredential {
            access_token,
            refresh_token,
            expires_at_ms: creds.expiry_date,
            // The GoogleAdapter supplies the gemini-cli public client + token URL.
            token_url: String::new(),
            client_id: None,
            scopes: Vec::new(),
        })
    }

    /// Parse the shared `auth.json` per-provider entry: `{ "refresh": ..., "access":
    /// ..., "expires": <epoch_ms> }`. `expires` is optional.
    fn from_auth_json(raw_json: &[u8]) -> Result<Self, ImportError> {
        #[derive(Deserialize)]
        struct AuthEntry {
            #[serde(default)]
            refresh: Option<String>,
            #[serde(default)]
            access: Option<String>,
            #[serde(default)]
            expires: Option<i64>,
        }
        let entry: AuthEntry =
            serde_json::from_slice(raw_json).map_err(|e| ImportError::Malformed(e.to_string()))?;
        let refresh_token = entry
            .refresh
            .filter(|s| !s.is_empty())
            .ok_or(ImportError::MissingField("refresh"))?;
        let access_token = entry.access.unwrap_or_default();
        if is_custody_tombstone(&refresh_token) || is_custody_tombstone(&access_token) {
            return Err(ImportError::CustodyTombstone);
        }
        Ok(OAuthCredential {
            access_token,
            refresh_token,
            expires_at_ms: entry.expires,
            // The adapter supplies the provider's token URL / client id; the import
            // file does not carry them.
            token_url: String::new(),
            client_id: None,
            scopes: Vec::new(),
        })
    }
}

/// Parse an antigravity credential from the antigravity-auth opencode plugin's
/// accounts store (`~/.config/opencode/antigravity-accounts.json`, a `version: 4`
/// file `{ accounts: [...], activeIndex }`). Each account carries a BARE
/// `refreshToken` plus an optional `projectId` / `managedProjectId`. This reads the
/// selected account and PACKS the refresh into the canonical
/// `<refresh>|<projectId>|<managedProjectId>` form the antigravity refresh adapter
/// reads back (the project segment is empty when absent; the managed segment is
/// appended only when present).
///
/// `account` selects the account: `None` uses `accounts[activeIndex]`; `Some(s)`
/// matches an account `email` (forward-compat with multi-account
/// `antigravity:google:<email>`), or `s` as a numeric index. A store with no usable
/// account is a typed error.
///
/// Returns the account's `email` ALONGSIDE the credential, because it is the only
/// per-account identity this provider has. Antigravity access tokens are opaque
/// Google tokens rather than JWTs, so the parse-live claim path that serves
/// `account_id` for other providers cannot work here -- if the email is dropped at
/// ingest, nothing downstream can tell two antigravity accounts apart, and a consumer
/// labelling per account collapses them into one unlabelled entry.
pub fn import_antigravity_account(
    raw_json: &[u8],
    account: Option<&str>,
) -> Result<ImportedAntigravityAccount, ImportError> {
    // Account fields are camelCase in the on-disk file (refreshToken, managedProjectId).
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Account {
        #[serde(default)]
        email: Option<String>,
        #[serde(default)]
        refresh_token: Option<String>,
        #[serde(default)]
        project_id: Option<String>,
        #[serde(default)]
        managed_project_id: Option<String>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Store {
        #[serde(default)]
        accounts: Vec<Account>,
        #[serde(default)]
        active_index: usize,
    }
    let store: Store =
        serde_json::from_slice(raw_json).map_err(|e| ImportError::Malformed(e.to_string()))?;
    if store.accounts.is_empty() {
        return Err(ImportError::Malformed(
            "no antigravity accounts in file".into(),
        ));
    }
    let acct = match account {
        None => store
            .accounts
            .get(store.active_index)
            .or_else(|| store.accounts.first())
            .ok_or(ImportError::Malformed("activeIndex out of range".into()))?,
        Some(sel) => store
            .accounts
            .iter()
            .find(|a| a.email.as_deref() == Some(sel))
            .or_else(|| {
                sel.parse::<usize>()
                    .ok()
                    .and_then(|i| store.accounts.get(i))
            })
            .ok_or_else(|| ImportError::ProviderNotFound(sel.to_string()))?,
    };
    let refresh = acct
        .refresh_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(ImportError::MissingField("refreshToken"))?;
    // Pack as `<refresh>|<projectId>` (empty middle segment when projectId absent),
    // then append `|<managed>` only if present.
    let project_segment = acct.project_id.as_deref().unwrap_or("");
    let packed = match acct.managed_project_id.as_deref().filter(|s| !s.is_empty()) {
        Some(managed) => format!("{refresh}|{project_segment}|{managed}"),
        None => format!("{refresh}|{project_segment}"),
    };
    Ok(ImportedAntigravityAccount {
        oauth: OAuthCredential {
            access_token: String::new(),
            refresh_token: packed,
            expires_at_ms: None,
            token_url: String::new(),
            client_id: None,
            scopes: Vec::new(),
        },
        // Empty is not a value: the field is optional in the store, and an empty
        // string would present downstream as an account labelled with nothing.
        email: acct
            .email
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(Into::into),
    })
}

/// One antigravity account read out of the plugin's store: the credential, plus the
/// non-secret identity that came with it.
///
/// A struct rather than a tuple so the caller cannot silently swap the two, and so
/// adding a further identity field later does not churn every call site.
#[derive(Debug, Clone)]
pub struct ImportedAntigravityAccount {
    /// The packed OAuth credential the antigravity refresh adapter reads back.
    pub oauth: OAuthCredential,
    /// The account's email, when the store carried one. Non-secret, and the only
    /// stable per-account identifier available for this provider.
    pub email: Option<String>,
}

/// Extract a static API key from an auth file. Returns the raw key bytes for a
/// `CredentialKind::ApiKey` static record. The real opencode `auth.json` is a map
/// keyed by provider; `provider` selects one `{ "type": "api", "key": "..." }` entry
/// (the shape opencode writes for api-key providers). A missing provider, a
/// non-api-key entry, or an absent key is a typed error.
pub fn import_api_key(
    source: &str,
    raw_json: &[u8],
    provider: &str,
) -> Result<Vec<u8>, ImportError> {
    match source {
        "opencode" | "pi" => {
            let map: serde_json::Value = serde_json::from_slice(raw_json)
                .map_err(|e| ImportError::Malformed(e.to_string()))?;
            let entry = map
                .get(provider)
                .ok_or_else(|| ImportError::ProviderNotFound(provider.to_string()))?;
            // opencode tags api-key entries `"type":"api"`; reject an oauth entry so a
            // wrong --kind can't silently store an oauth blob as an api key.
            if let Some(ty) = entry.get("type").and_then(|t| t.as_str()) {
                if ty != "api" {
                    return Err(ImportError::Malformed(format!(
                        "provider '{provider}' is type '{ty}', not 'api' (use the oauth import path)"
                    )));
                }
            }
            let key = entry
                .get("key")
                .and_then(|k| k.as_str())
                .filter(|s| !s.is_empty())
                .ok_or(ImportError::MissingField("key"))?;
            if is_custody_tombstone(key) {
                return Err(ImportError::CustodyTombstone);
            }
            Ok(key.as_bytes().to_vec())
        }
        other => Err(ImportError::UnknownSource(other.to_string())),
    }
}

/// A credential-import failure.
#[derive(Debug)]
pub enum ImportError {
    /// The source name is not one of the supported importers.
    UnknownSource(String),
    /// The source JSON did not decode.
    Malformed(String),
    /// A required field (a refresh token) was absent.
    MissingField(&'static str),
    /// The requested provider key was not present in a multi-provider auth file.
    ProviderNotFound(String),
    /// Claustrum's tombstone is an ownership marker, never importable credential material.
    CustodyTombstone,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::UnknownSource(s) => write!(f, "unknown import source '{s}'"),
            ImportError::Malformed(m) => write!(f, "malformed import json: {m}"),
            ImportError::MissingField(field) => {
                write!(f, "import missing required field '{field}'")
            }
            ImportError::ProviderNotFound(p) => {
                write!(f, "provider '{p}' not found in auth file")
            }
            ImportError::CustodyTombstone => write!(
                f,
                "refusing Claustrum tombstone material; run ck auth migrate-opencode or ck auth migrate-opencode --restore"
            ),
        }
    }
}

impl std::error::Error for ImportError {}

impl std::fmt::Debug for OAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render token bytes. Presence + non-secret metadata only.
        f.debug_struct("OAuthCredential")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OAuthCredential {
        OAuthCredential {
            access_token: "access-abc".into(),
            refresh_token: "refresh-xyz".into(),
            expires_at_ms: Some(1_000_000),
            token_url: "https://example.test/oauth/token".into(),
            client_id: Some("client-1".into()),
            scopes: vec!["a".into(), "b".into()],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let c = sample();
        let json = serde_json::to_vec(&c).unwrap();
        let back: OAuthCredential = serde_json::from_slice(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn debug_redacts_tokens() {
        let rendered = format!("{:?}", sample());
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("access-abc"), "no access token in Debug");
        assert!(
            !rendered.contains("refresh-xyz"),
            "no refresh token in Debug"
        );
        // Non-secret metadata is fine to show.
        assert!(rendered.contains("example.test"));
    }

    #[test]
    fn imports_auth_json_shape() {
        let raw = br#"{"refresh":"r-tok","access":"a-tok","expires":1700000000000}"#;
        let c = OAuthCredential::import("opencode", raw).expect("import");
        assert_eq!(c.refresh_token, "r-tok");
        assert_eq!(c.access_token, "a-tok");
        assert_eq!(c.expires_at_ms, Some(1_700_000_000_000));
        // The adapter fills token_url/client_id; the import file does not carry them.
        assert!(c.token_url.is_empty());
        assert!(c.client_id.is_none());
    }

    #[test]
    fn import_provider_selects_one_entry_from_a_multi_provider_auth_json() {
        // The real opencode auth.json shape: a map keyed by provider.
        let raw = br#"{
            "anthropic": {"refresh":"a-r","access":"a-a","expires":111},
            "google":    {"refresh":"g-r","access":"","expires":0}
        }"#;
        let a = OAuthCredential::import_provider("opencode", raw, "anthropic").expect("anthropic");
        assert_eq!(a.refresh_token, "a-r");
        assert_eq!(a.access_token, "a-a");
        // Google's already-empty access token imports fine (refresh repopulates it).
        let g = OAuthCredential::import_provider("opencode", raw, "google").expect("google");
        assert_eq!(g.refresh_token, "g-r");
        assert!(g.access_token.is_empty());
        // A provider key not present is a typed error, not a silent empty import.
        assert!(matches!(
            OAuthCredential::import_provider("opencode", raw, "openai"),
            Err(ImportError::ProviderNotFound(p)) if p == "openai"
        ));
    }

    #[test]
    fn imports_api_key_from_auth_json_map() {
        let raw = br#"{
            "deepseek": {"type":"api","key":"sk-deep-123"},
            "anthropic": {"type":"oauth","refresh":"r","access":"a"}
        }"#;
        let key = import_api_key("opencode", raw, "deepseek").expect("deepseek key");
        assert_eq!(key, b"sk-deep-123");
        // An oauth entry is rejected by the api-key path (wrong --kind guard).
        assert!(matches!(
            import_api_key("opencode", raw, "anthropic"),
            Err(ImportError::Malformed(_))
        ));
        // A missing provider is a typed error.
        assert!(matches!(
            import_api_key("opencode", raw, "absent"),
            Err(ImportError::ProviderNotFound(p)) if p == "absent"
        ));
        // A missing key is a typed error.
        let nokey = br#"{"x":{"type":"api"}}"#;
        assert!(matches!(
            import_api_key("opencode", nokey, "x"),
            Err(ImportError::MissingField("key"))
        ));
    }

    #[test]
    fn import_refuses_claustrum_tombstone_material() {
        let api = br#"{"deepseek":{"type":"api","key":"claustrum-tombstone:v1:deepseek"}}"#;
        let error =
            import_api_key("opencode", api, "deepseek").expect_err("tombstone api key must refuse");
        assert!(error.to_string().contains("migrate-opencode"));

        let oauth = br#"{"anthropic":{"type":"oauth","refresh":"claustrum-tombstone:v1:anthropic","access":"claustrum-tombstone:v1:anthropic","expires":0}}"#;
        let error = OAuthCredential::import_provider("opencode", oauth, "anthropic")
            .expect_err("tombstone oauth tokens must refuse");
        assert!(error.to_string().contains("migrate-opencode"));
    }

    #[test]
    fn imports_antigravity_accounts_store_and_packs_managed_project() {
        // The version:4 accounts-array store the antigravity plugin writes.
        let raw = br#"{
            "version": 4,
            "activeIndex": 1,
            "accounts": [
                {"email":"a@x.com","refreshToken":"1//0-aaa","managedProjectId":"proj-a"},
                {"email":"b@x.com","refreshToken":"1//0-bbb","managedProjectId":"encouraging-env-qwp21"}
            ]
        }"#;
        // activeIndex picks account[1].
        let c = import_antigravity_account(raw, None).expect("active account");
        assert_eq!(
            c.oauth.refresh_token, "1//0-bbb||encouraging-env-qwp21",
            "packs <refresh>||<managed> (empty plain project segment)"
        );
        assert!(
            c.oauth.access_token.is_empty(),
            "antigravity store carries no access token"
        );
        // effective_project_id returns the managed id.
        assert_eq!(
            crate::refresh_adapters::antigravity::effective_project_id(&c.oauth.refresh_token)
                .as_deref(),
            Some("encouraging-env-qwp21")
        );
        // THE IDENTITY COMES BACK WITH THE SELECTED ACCOUNT, and it must be the
        // selected one rather than the first: antigravity access tokens are opaque, so
        // this email is the only thing that can tell two accounts apart downstream, and
        // returning the wrong account's email is worse than returning none.
        assert_eq!(
            c.email.as_deref(),
            Some("b@x.com"),
            "the active account's email, not the store's first"
        );
        // Select a specific account by email (forward-compat multi-account).
        let a = import_antigravity_account(raw, Some("a@x.com")).expect("by email");
        assert_eq!(a.oauth.refresh_token, "1//0-aaa||proj-a");
        assert_eq!(a.email.as_deref(), Some("a@x.com"), "tracks the selection");
        // Select by numeric index.
        let byidx = import_antigravity_account(raw, Some("0")).expect("by index");
        assert_eq!(byidx.oauth.refresh_token, "1//0-aaa||proj-a");
        assert_eq!(byidx.email.as_deref(), Some("a@x.com"));
        // An account with NO email is None rather than an empty string, which would
        // present downstream as an account labelled with nothing.
        let no_email = import_antigravity_account(
            br#"{"version":4,"activeIndex":0,"accounts":[{"refreshToken":"1//0-ccc"}]}"#,
            None,
        )
        .expect("account without an email");
        assert_eq!(no_email.email, None);
        assert_eq!(no_email.oauth.refresh_token, "1//0-ccc|");
        // An unknown selector is a typed error; an empty store is rejected.
        assert!(matches!(
            import_antigravity_account(raw, Some("nope@x.com")),
            Err(ImportError::ProviderNotFound(_))
        ));
        assert!(matches!(
            import_antigravity_account(br#"{"version":4,"accounts":[]}"#, None),
            Err(ImportError::Malformed(_))
        ));
    }

    #[test]
    fn imports_gemini_cli_creds_shape() {
        // The gemini-cli login file: distinct field names, expiry_date in epoch ms.
        let raw = br#"{"access_token":"ya29.live","refresh_token":"1//0g-refresh","expiry_date":1700000000000,"token_type":"Bearer"}"#;
        let c = OAuthCredential::import("gemini-cli", raw).expect("gemini import");
        assert_eq!(c.refresh_token, "1//0g-refresh");
        assert_eq!(c.access_token, "ya29.live");
        assert_eq!(c.expires_at_ms, Some(1_700_000_000_000));
        assert!(
            c.token_url.is_empty(),
            "adapter supplies the gemini token url"
        );
        // A gemini-cli file with no refresh token is rejected (can't be kept fresh).
        assert!(matches!(
            OAuthCredential::import("gemini-cli", br#"{"access_token":"a"}"#),
            Err(ImportError::MissingField("refresh_token"))
        ));
        // gemini-cli is a single-credential file: --provider does not apply.
        assert!(matches!(
            OAuthCredential::import_provider("gemini-cli", raw, "google"),
            Err(ImportError::Malformed(_))
        ));
    }

    #[test]
    fn import_rejects_unknown_source_and_missing_refresh() {
        assert!(matches!(
            OAuthCredential::import("nope", b"{}"),
            Err(ImportError::UnknownSource(_))
        ));
        assert!(matches!(
            OAuthCredential::import("opencode", br#"{"access":"a"}"#),
            Err(ImportError::MissingField("refresh"))
        ));
        assert!(matches!(
            OAuthCredential::import("opencode", b"not json"),
            Err(ImportError::Malformed(_))
        ));
    }

    #[test]
    fn expiry_uses_skew_and_treats_absent_as_fresh() {
        let mut c = sample();
        c.expires_at_ms = Some(1000);
        assert!(c.is_access_expired(1000, 0), "at expiry is expired");
        assert!(c.is_access_expired(900, 200), "within skew is expired");
        assert!(!c.is_access_expired(799, 200), "outside skew is fresh");
        c.expires_at_ms = None;
        assert!(!c.is_access_expired(i64::MAX, 0), "no expiry => not forced");
    }
}
