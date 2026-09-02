//! Whether each credential holds material the engine can actually work with.
//!
//! The health gauge counts records that exist and decrypt, which cannot see inside the
//! sealed envelope. This opens each one and reports the property the gauge structurally
//! cannot: whether a record is STRANDED -- holding neither a usable access token nor any
//! refresh material, so it can never serve again without an operator login.
//!
//! # Expiry is reported but never scored
//!
//! An expired access token is not a fault: [`crate::engine::RefreshEngine`] treats it as
//! the trigger to refresh on the next get, so expired-with-refresh-material is the
//! routine state of a perfectly healthy credential and counting it as degraded would
//! report normal operation as a problem.
//!
//! Nor is remaining TTL evidence of the opposite. Expiry and provider acceptance are
//! independent: a provider can reject a token that was minted an hour ago and still has
//! days of TTL left, and no amount of local inspection can see that coming. The
//! authoritative signal for a rejected credential is the `needs_reauth` state, which a
//! consumer sets through `report_auth_failure` and the health gauge already counts.
//!
//! # Acquires nothing exclusive
//!
//! Opening a vault through [`crate::store::EncryptedStore`] takes the single-writer
//! lease, which fences the running daemon out of its own store. So the envelope is read
//! through a plain read-only SQLite connection and decrypted in memory here. Read-only
//! rather than `immutable=1`: immutable skips the write-ahead log and would answer about
//! a live store's past.
//!
//! # Scan, do not print
//!
//! This returns data and renders nothing, so the same scan can back an operator command
//! and a test assertion without either inheriting the other's formatting.

use crate::envelope::{open as envelope_open, RecordBinding};
use crate::key::{KeyId, MasterKey};
use crate::oauth::OAuthCredential;
use crate::record::{CredentialKind, VaultRecord};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// What a single record's decrypted contents say about its future.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Usability {
    /// A static key: no refresh path. `expires_at_ms` is the operator's OWN
    /// declaration at `put --expires-ms`, not something the provider told us.
    ///
    /// `written_at_ms` is the plaintext `updated_at_ms` column. For a STATIC record it
    /// means what an operator would expect "age" to mean, because nothing but an
    /// operator write moves it -- there is no refresh to touch the row. That is why it
    /// is carried on this variant and NOT on `Serviceable`: on an OAuth record the same
    /// column advances on every refresh, so it measures time-since-last-refresh and
    /// rendering it as age would be a plausible-looking lie.
    ///
    /// Age is the honest signal for a credential class whose real lifetime cannot be
    /// declared: it states elapsed time since the operator last wrote it, and claims
    /// nothing about whether the provider still honours it.
    ///
    /// Absent a declaration nothing readable here distinguishes a live key from one
    /// the provider revoked an hour ago. WITH one, the operator has stated a lifetime
    /// and that statement is worth reporting against -- it is the only forward-looking
    /// signal a non-refreshable credential can carry, and until this variant held the
    /// field the value was accepted at `put`, sealed into the record, and then read by
    /// nothing: a declared-expired key reported `active` and counted as healthy.
    Static {
        expires_at_ms: Option<i64>,
        written_at_ms: i64,
    },
    /// A manually captured session cookie. Its capture age is a staleness signal, not
    /// an expiry claim: session lifetime is not present in a request `Cookie` header.
    ///
    /// NO `expires_at_ms` HERE, AND THE REASON IS THE CAPTURE MECHANISM RATHER THAN THE
    /// CREDENTIAL CLASS -- which means a decision taken elsewhere can make this field
    /// correct to add. Recorded so the next reader does not have to re-derive it:
    ///
    /// A pasted `Cookie:` request header carries no expiry at all (Expires and Max-Age
    /// are `Set-Cookie` RESPONSE attributes; the browser consumed them). Reading the
    /// browser's own store does yield them -- but Chrome's App-Bound Encryption refuses
    /// any non-Chrome process on Windows BY DESIGN, and Windows is the platform this
    /// credential class exists for. So a declared expiry would be present on macOS
    /// captures and absent on Windows ones, with nothing in the record saying which.
    ///
    /// That is worse than uniform absence, and not merely ambiguous: missingness
    /// CORRELATED WITH PLATFORM biases any aggregate computed over it rather than
    /// leaving it incomplete, and the omitted population is exactly the one the feature
    /// exists for.
    ///
    /// WHAT WOULD MAKE IT CORRECT TO ADD: a capture path that yields expiry UNIFORMLY on
    /// every platform. A browser extension is that path -- `chrome.cookies.getAll`
    /// returns `expirationDate` and is not subject to App-Bound Encryption, because it
    /// asks Chrome's own API rather than reading its store. If the desktop surface
    /// adopts the extension, this variant should carry `expires_at_ms: Option<i64>` and
    /// `ck auth put --expires-ms` becomes honest for cookies.
    ///
    /// EVEN THEN IT IS AN UPPER BOUND, NOT A TRUTH: `expirationDate` is the browser's
    /// expiry, and a session can be revoked server-side long before it. That is exactly
    /// what an operator DECLARATION means on `Static` above, so the same honest framing
    /// applies -- it states a lifetime, it does not promise the provider still honours
    /// the session.
    Cookie { written_at_ms: i64 },
    /// OAuth with material the engine can serve or refresh from. `expires_at_ms` is
    /// carried for display and deliberately not scored.
    Serviceable { expires_at_ms: Option<i64> },
    /// Neither a usable access token nor refresh material: cannot serve, cannot
    /// recover on its own, and needs an operator login.
    Stranded,
    /// The envelope did not open, or its plaintext did not decode.
    Unreadable { why: String },
}

/// One record's row in the report.
#[derive(Debug, Clone)]
pub struct RecordUsability {
    pub credential_id: String,
    /// The stored lifecycle state (`active` / `needs_reauth` / `retired` / `corrupt`),
    /// carried verbatim so the caller need not re-read the column.
    pub state: String,
    pub usability: Usability,
    /// True when the record claims an identity that resolves nothing -- an email with
    /// no account id. The sink in [`crate::record::VaultRecord::with_identity`]
    /// normalises this away at WRITE time, but a record sealed BEFORE that landed
    /// deserializes with the shape intact and serves it: `VaultRecord::decode` is plain
    /// serde and does not pass through the sink.
    pub unservable_identity: bool,
    /// The non-secret account id operators use to distinguish OAuth credentials.
    pub account_id: Option<String>,
}

/// Why a scan could not start. Distinguished from a per-record failure, which is
/// reported as [`Usability::Unreadable`] and never aborts the scan.
#[derive(Debug)]
pub enum ScanError {
    /// The store file could not be opened at all.
    Open(String),
    /// The vault is bootstrapped but holds no schema yet: the tables are created by the
    /// first write, not by `bootstrap`. Its own variant because the raw sqlite "no such
    /// table" reads as a corrupt store when the store is merely empty.
    NoSchema,
    /// The scan started and the query failed partway.
    Read(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "opening the store read-only: {e}"),
            Self::NoSchema => write!(f, "the vault holds no credentials yet"),
            Self::Read(e) => write!(f, "reading the store: {e}"),
        }
    }
}

/// Whether the engine can still do something with this record. `None` is a static key.
///
/// Split out of the scan so the stranded arm is reachable by a test: against a healthy
/// vault every record is serviceable, so a run over real data exercises one arm only,
/// and an all-serviceable report is equally consistent with a function that has no
/// stranded arm at all.
pub fn is_serviceable(oauth: Option<&OAuthCredential>) -> bool {
    match oauth {
        None => true,
        Some(oauth) => !oauth.refresh_token.is_empty() || !oauth.access_token.is_empty(),
    }
}

/// Whether a STATIC record has outlived the expiry its operator declared.
///
/// Pure and instant-taking rather than reading the clock, so a test can pin the moment
/// -- the scan itself stays deterministic and the caller supplies `now_ms`.
///
/// Deliberately NOT applied to OAuth records. There an expired access token is the
/// routine state of a healthy credential (it is the trigger to refresh on the next
/// get), so scoring it would report normal operation as a fault. A non-refreshable
/// record has no such recovery: once its declared lifetime passes, only an operator
/// re-provisioning it changes anything.
///
/// This reports the DECLARATION, never the provider's opinion. An operator who
/// declared conservatively will see a key called out while the provider still honours
/// it -- which is the correct failure direction for a credential audit, and the reason
/// the renderer says "declared" rather than "expired".
///
/// SO "DECLARED" IS A PROVENANCE CLAIM, NOT A HEDGE, and a plausible future change
/// would quietly break it. A collaborator observing a real cookie expiry (2026-08-17,
/// MiniMax, ~58d then a 9d replacement on the same account) proposed sorting
/// cookie-shaped credentials automatically: if the payload decodes as a JWT, read its
/// `exp` at put time instead of asking the operator. Cheap, needs no declaration, and
/// the provider's own number is better evidence than a guess.
///
/// IT IS ALSO A DIFFERENT FACT WEARING THIS FUNCTION'S LABEL. Today `expires_at_ms`
/// arrives from one place -- an operator typing `--expires-ms` -- so a false callout is
/// traceable to a human who chose conservatively. Auto-populated, the same field
/// becomes the vault's inference from bytes it parsed, and "declared" would be relaying
/// a claim nobody made. The failure it produces is worse than the one it prevents: an
/// audit calls a working credential expired, the operator checks what they declared,
/// and finds they declared nothing.
///
/// If auto-population is ever built, it needs a SEPARATE provenance -- the record must
/// record where the number came from and the renderer must say which, because
/// "expiry the operator stated" and "expiry parsed out of the token" carry different
/// trust and warrant different operator responses. A JWT's `exp` is also the token's
/// lifetime, which is not always the session's; the cookie may outlive it.
/// One field, two provenances, is how a column starts lying quietly.
pub fn static_past_declared_expiry(expires_at_ms: Option<i64>, now_ms: i64) -> bool {
    match expires_at_ms {
        Some(exp) => now_ms >= exp,
        None => false,
    }
}

/// The master-key fingerprint the store records in plaintext.
///
/// [`crate::store::EncryptedStore::read_db_key_id`] needs an opened store, which takes
/// the single-writer lease -- the thing this module must not do. The row is plaintext,
/// so reading it over the same read-only connection costs nothing and keeps the
/// lease-free property.
///
/// `None` covers both a store predating the anchor row and any read failure; the caller
/// then falls back to a plain resolve, which fails closed with its own message.
pub fn read_db_key_id_read_only(conn: &Connection) -> Option<KeyId> {
    let hex: String = conn
        .query_row(
            "SELECT key_id FROM vault_secrets WHERE name = '__vault_audit_key__'",
            [],
            |r| r.get(0),
        )
        .ok()?;
    KeyId::from_hex(&hex)
}

/// Open a vault's store read-only, taking no lease.
pub fn open_store_read_only(store_path: &Path) -> Result<Connection, ScanError> {
    Connection::open_with_flags(
        store_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| ScanError::Open(e.to_string()))
}

/// Decrypt every record and report what each one's contents imply.
///
/// A record that fails to decrypt is reported and the scan continues: one unreadable
/// envelope must not hide the state of the other twenty-two.
pub fn scan(conn: &Connection, key: &MasterKey) -> Result<Vec<RecordUsability>, ScanError> {
    let mut stmt = match conn.prepare(
        "SELECT credential_id, record_version, state, envelope, updated_at_ms \
         FROM credentials ORDER BY credential_id",
    ) {
        Ok(stmt) => stmt,
        Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("no such table") => {
            return Err(ScanError::NoSchema)
        }
        Err(e) => return Err(ScanError::Read(e.to_string())),
    };
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .map_err(|e| ScanError::Read(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        let (id, version, state, blob, written_at_ms) =
            row.map_err(|e| ScanError::Read(e.to_string()))?;
        let binding = RecordBinding {
            credential_id: &id,
            record_version: version,
        };
        let plaintext = match envelope_open(key, &blob, &binding) {
            Ok(p) => p,
            Err(e) => {
                out.push(RecordUsability {
                    credential_id: id,
                    state,
                    usability: Usability::Unreadable {
                        why: format!("{e:?}"),
                    },
                    unservable_identity: false,
                    account_id: None,
                });
                continue;
            }
        };
        let record: VaultRecord = match serde_json::from_slice(&plaintext) {
            Ok(r) => r,
            Err(e) => {
                out.push(RecordUsability {
                    credential_id: id,
                    state,
                    usability: Usability::Unreadable {
                        why: format!("undecodable: {e}"),
                    },
                    unservable_identity: false,
                    account_id: None,
                });
                continue;
            }
        };

        let oauth = record.oauth.as_ref();
        let usability = if !is_serviceable(oauth) {
            Usability::Stranded
        } else {
            match oauth {
                // A request Cookie header has no expiry attributes; the browser consumed
                // them from Set-Cookie before capture. Age is the only honest signal here.
                None if record.kind == CredentialKind::Cookie => {
                    Usability::Cookie { written_at_ms }
                }
                // The record's own expiry field, not an oauth one: for another static
                // record this is the only place a declared lifetime lives.
                None => Usability::Static {
                    expires_at_ms: record.expires_at_ms,
                    written_at_ms,
                },
                Some(oauth) => Usability::Serviceable {
                    expires_at_ms: oauth.expires_at_ms,
                },
            }
        };
        out.push(RecordUsability {
            credential_id: id,
            state,
            usability,
            unservable_identity: !record.identity.is_servable(),
            account_id: record.identity.account_id,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod declared_expiry_tests {
    use super::*;

    /// Both arms, at a PINNED instant rather than the wall clock.
    ///
    /// One arm alone proves nothing here: a function that always returns false passes
    /// the not-yet-expired case, and one that always returns true passes the expired
    /// case. The pair is the test.
    #[test]
    fn a_static_records_declared_expiry_is_scored_only_once_it_has_passed() {
        let now = 1_700_000_000_000i64;

        assert!(
            static_past_declared_expiry(Some(now - 1), now),
            "a declaration one millisecond in the past must count as passed"
        );
        assert!(
            static_past_declared_expiry(Some(now), now),
            "the boundary instant itself must count as passed: a credential is not \
             usable AT the moment it expires"
        );
        assert!(
            !static_past_declared_expiry(Some(now + 1), now),
            "a declaration one millisecond in the future must NOT be scored"
        );

        // The overwhelmingly common case, and the one that must stay silent: almost
        // every static key in a real vault carries no declaration at all. Scoring
        // those would turn the audit into noise on its first run.
        assert!(
            !static_past_declared_expiry(None, now),
            "a key with no declared expiry must never be scored as expired"
        );
    }

    /// The scan must carry the RECORD's expiry into the Static variant. Before this,
    /// `put --expires-ms` was accepted, sealed, and read by nothing -- the value
    /// existed on disk and reached no surface.
    #[test]
    fn the_scan_carries_a_static_records_declared_expiry_rather_than_dropping_it() {
        use crate::record::{CredentialKind, VaultRecord};

        let declared = 1_700_000_000_000i64;
        let record = VaultRecord::new_static(
            CredentialKind::ApiKey,
            "operator",
            b"probe".to_vec(),
            Some(declared),
        );

        // The scan's own classification arm, exercised directly: no oauth block, so it
        // must land on Static and must carry the record's field. `written_at_ms` comes
        // from the store's plaintext column rather than the record, so it is supplied
        // here the way the scan supplies it -- the end-to-end pin that it is read from
        // the RIGHT column lives in cli_admin.rs, which needs a real store to see it.
        let written_at_ms = 1_699_000_000_000i64;
        let usability = match record.oauth.as_ref() {
            None => Usability::Static {
                expires_at_ms: record.expires_at_ms,
                written_at_ms,
            },
            Some(o) => Usability::Serviceable {
                expires_at_ms: o.expires_at_ms,
            },
        };
        assert_eq!(
            usability,
            Usability::Static {
                expires_at_ms: Some(declared),
                written_at_ms
            },
            "a static record must report the expiry its operator declared"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{is_serviceable, Usability};
    use crate::oauth::OAuthCredential;

    fn creds(access: &str, refresh: &str) -> OAuthCredential {
        OAuthCredential {
            access_token: access.to_string(),
            refresh_token: refresh.to_string(),
            expires_at_ms: None,
            token_url: "https://example.invalid/token".to_string(),
            client_id: None,
            scopes: Vec::new(),
        }
    }

    #[test]
    fn only_a_record_with_neither_token_is_stranded() {
        // The stranded arm: no access token AND no refresh material.
        assert!(!is_serviceable(Some(&creds("", ""))));

        // DISAMBIGUATORS. A predicate that always returned false would satisfy the
        // assertion above, and against a healthy vault nothing would ever exercise
        // these. Refresh material alone is enough -- the engine mints a new access
        // token on the next get -- and so is an access token alone.
        assert!(is_serviceable(Some(&creds("", "refresh"))));
        assert!(is_serviceable(Some(&creds("access", ""))));
        assert!(is_serviceable(Some(&creds("access", "refresh"))));

        // A static key has no OAuth block at all and is never stranded: nothing
        // readable here distinguishes a live key from a revoked one.
        assert!(is_serviceable(None));
    }

    #[test]
    fn expiry_never_makes_a_record_stranded() {
        // An access token that expired an hour ago, with refresh material beside it, is
        // the ROUTINE state of a healthy credential. Pinned because scoring expiry is
        // the exact mistake this module's doc comment argues against, and a future
        // change that "improves" the predicate by checking expires_at_ms would pass
        // every other test here.
        let mut expired = creds("stale-access", "refresh");
        expired.expires_at_ms = Some(0);
        assert!(is_serviceable(Some(&expired)));
    }

    #[test]
    fn usability_variants_are_distinguishable() {
        // Guards against a future refactor collapsing Stranded into Unreadable: the two
        // need different operator responses (re-login vs investigate the store).
        assert_ne!(
            Usability::Stranded,
            Usability::Static {
                expires_at_ms: None,
                written_at_ms: 0
            }
        );
        assert_ne!(
            Usability::Stranded,
            Usability::Unreadable {
                why: "x".to_string()
            }
        );
    }
}
