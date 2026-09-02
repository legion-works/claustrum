//! End-to-end tests of the offline admin CLI binary.
//!
//! Drives the real `ck-auth` process against a temp vault dir with an
//! operator key path (so no keychain is touched), exercising the structural
//! master-key proof and the audit chain end-to-end: bootstrap a key, put a
//! credential, mint a handle, list + verify the audit chain. Also proves the
//! single-writer lease makes admin writes mutually exclusive with a held lease.

use std::path::PathBuf;
use std::process::Command;

use base64::Engine;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::key::MasterKey;
use credentials_core::record::CredentialKind;
use credentials_core::store::EncryptedStore;
use ring::signature::{UnparsedPublicKey, ED25519};

/// Point this suite at a specific `ck-auth` instead of the one cargo just built.
///
/// `CARGO_BIN_EXE_*` resolves per-profile and cargo rebuilds before running, so
/// `cargo test` -- with or without `--release` -- always drives a binary produced for
/// the test run, never a staged one. A green suite is therefore evidence about the
/// SOURCE and none at all about the bytes being shipped.
///
/// That matters most for THIS binary. `ck-auth` is what an operator reaches for during
/// an incident and the only thing that takes the single-writer lease to mutate the
/// vault, so a broken artifact is discovered while trying to repair something else.
/// `scripts/release-build.sh` sets this after staging.
const CLI_BIN_ENV: &str = "CRED_CLI_BIN";

fn cli() -> Command {
    // REFUSES a bad override rather than falling back: a typo that silently tested the
    // cargo-built binary would report exactly the green the caller was hoping for.
    match std::env::var_os(CLI_BIN_ENV) {
        Some(raw) => {
            let path = PathBuf::from(raw);
            assert!(
                path.is_file(),
                "{CLI_BIN_ENV} points at {} which is not a file — refusing to fall back \
                 to the cargo-built binary, because a silent fallback would report the \
                 staged artifact as verified when it was never run",
                path.display()
            );
            Command::new(path)
        }
        None => Command::new(env!("CARGO_BIN_EXE_ck-auth")),
    }
}

/// Both documented orders of a global flag must reach the same vault.
///
/// The verb is positional and is read before the flags, so a flag written BEFORE it
/// would be taken as the verb itself and produce "unexpected argument '<path>' for
/// '--data-dir'" -- a message naming the flag as a verb, from an invocation the help
/// text presents as correct. Nothing about the parser is visible to a caller, so the
/// two orders have to be equivalent rather than one of them being a rule to learn.
///
/// Driven through the real binary, because the ordering fix lives in argv handling
/// before dispatch: a unit test calling the helper directly passes whether or not
/// anything invokes it.
/// A github_app deposit must NOT land as a static record.
///
/// Static is what `put` builds for every other kind, and it is precisely wrong here:
/// `credential.get` would serve the PEM verbatim, and a consumer putting newline-laden
/// key material into an HTTP header fails before the wire. That is the failure plexus
/// hit on 2026-08-17, and this asserts the SHAPE that prevents it rather than the CLI's
/// success message -- "created" printed identically for the broken shape.
#[test]
fn a_github_app_deposit_lands_oauth_shaped_rather_than_static() {
    let rig = tmp_root("github-app-put");
    std::fs::create_dir_all(&rig).unwrap();
    let key = rig.join("master.key");
    std::fs::write(&key, "11".repeat(32)).unwrap();
    let data_dir = rig.join("vault");
    let pem = rig.join("app.pem");
    // Shape only -- this test never signs, so PEM-looking text is enough.
    std::fs::write(
        &pem,
        "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----",
    )
    .unwrap();

    let run = |args: &[&str]| {
        let out = cli()
            .args([
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--key-path",
                key.to_str().unwrap(),
            ])
            .args(args)
            .output()
            .expect("cli runs");
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    run(&["bootstrap"]);
    let (stdout, stderr) = run(&[
        "put",
        "--id",
        "github_app:probe",
        "--payload-file",
        pem.to_str().unwrap(),
        "--client-id",
        "Iv23TESTCLIENT",
    ]);
    assert!(
        stdout.contains("created"),
        "deposit failed: {stdout}{stderr}"
    );

    // `usable` renders the record KIND, which is the observable separating the two
    // shapes: an oauth row mints on get, a static row serves its bytes forever.
    let (listed, _) = run(&["usable"]);
    let row = listed
        .lines()
        .find(|l| l.contains("github_app:probe"))
        .unwrap_or_else(|| panic!("no github_app row in:\n{listed}"));
    assert!(
        row.contains("oauth"),
        "a github_app deposit must be oauth-shaped so it can mint; got: {row}"
    );

    // Both refusals: a github_app record with no client_id could never mint, so it must
    // not be creatable at all, and client_id is meaningless on a static kind.
    let (_, e1) = run(&[
        "put",
        "--id",
        "apikey:x",
        "--payload",
        "y",
        "--client-id",
        "z",
    ]);
    assert!(e1.contains("only to a github_app"), "got: {e1}");
    let (_, e2) = run(&[
        "put",
        "--id",
        "github_app:y",
        "--payload-file",
        pem.to_str().unwrap(),
    ]);
    assert!(e2.contains("needs --client-id"), "got: {e2}");

    let _ = std::fs::remove_dir_all(&rig);
}

#[test]
fn a_global_flag_before_the_verb_reaches_the_same_vault_as_one_after_it() {
    let root = tmp_root("flag-order");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let mut boot = cli();
    boot.arg("bootstrap")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path);
    assert!(boot.output().expect("bootstrap").status.success());

    // Flags AFTER the verb: the form that has always worked.
    let mut after = cli();
    after
        .arg("list")
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path);
    let after = after.output().expect("list, flags after verb");

    // Flags BEFORE the verb: the form the help text documents.
    let mut before = cli();
    before
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("--key-path")
        .arg(&key_path)
        .arg("list");
    let before = before.output().expect("list, flags before verb");

    assert!(
        before.status.success(),
        "a global flag before the verb must not be read as the verb; got: {}",
        String::from_utf8_lossy(&before.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&after.stdout),
        "both orders must address the same vault and print the same inventory"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A fresh directory for one test, unique across PROCESSES and not merely within one.
///
/// The previous version keyed on `pid + tag + seq` and called `create_dir_all`, which
/// is unique within a process and NOT across processes: Windows recycles PIDs from a
/// small pool, the seam CI step runs several `cargo test` invocations in sequence, and
/// `create_dir_all` on an existing path SUCCEEDS. So a later binary could inherit an
/// earlier one's `pid+tag+seq` and silently adopt its leftover vault -- a `store.db`
/// sealed under one master key beside a key file holding another.
///
/// That is the shape of the flake this replaced: `an_antigravity_import_...` failed on
/// Windows with "no master key slot holds the key this vault is sealed under", from a
/// DOCS-ONLY commit, and the same tree passed on re-run. Leftovers accumulate only
/// from tests that panic (cleanup runs at the end, and a panic skips it), which is why
/// it is rare and why an occurrence needs an earlier failure to set it up.
///
/// Two changes, and the second is the one that earns its keep:
///
/// - a nanosecond component, so two processes cannot derive the same path;
/// - `create_dir` rather than `create_dir_all`, so a collision REFUSES instead of
///   reusing. If this ever fires, the hypothesis above is confirmed by name rather
///   than re-derived from a symptom three layers downstream. If the antigravity flake
///   recurs WITHOUT this firing, the hypothesis is wrong and the next investigation
///   starts somewhere genuinely different.
fn tmp_root(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!(
        "ck-cred-cli-{}-{}-{}-{nanos:09}",
        std::process::id(),
        tag,
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&d).unwrap_or_else(|e| {
        panic!(
            "temp root {} could not be created fresh ({e}). AlreadyExists here means a \
             path collision across processes, and reusing it would hand this test a \
             stale vault whose store and key file disagree.",
            d.display()
        )
    });
    d
}

struct GrantCliVault {
    root: PathBuf,
    data_dir: PathBuf,
    key_path: PathBuf,
}

impl GrantCliVault {
    fn new(tag: &str) -> Self {
        let root = tmp_root(tag);
        let data_dir = root.join("vault");
        let key_path = root.join("master.key");
        std::fs::create_dir_all(&data_dir).expect("vault directory");
        Self {
            root,
            data_dir,
            key_path,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&self.data_dir)
            .arg("--key-path")
            .arg(&self.key_path)
            .output()
            .expect("run ck-auth")
    }

    fn bootstrap(&self) {
        let out = self.run(&["bootstrap"]);
        assert!(
            out.status.success(),
            "bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

impl Drop for GrantCliVault {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn grant_row_fields<'a>(stdout: &'a str, credential_prefix: &str) -> Vec<&'a str> {
    stdout
        .lines()
        .find(|line| line.contains(credential_prefix))
        .unwrap_or_else(|| panic!("grant row for {credential_prefix} missing from:\n{stdout}"))
        .split_whitespace()
        .collect()
}

#[test]
fn grants_help_describes_the_read_only_inventory() {
    let out = cli()
        .args(["help", "grants"])
        .output()
        .expect("run grants help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ck auth grants"));
    assert!(stdout.contains("principal kind"));
    assert!(stdout.contains("creation time"));
    assert!(stdout.contains("no grants"));
}

#[test]
fn offline_grants_lists_a_newly_minted_grant_with_creation_time() {
    let vault = GrantCliVault::new("grants-created");
    vault.bootstrap();

    let created = vault.run(&[
        "grant",
        "--principal",
        "agent",
        "--prefix",
        "operator:",
        "--operation",
        "read",
    ]);
    assert!(
        created.status.success(),
        "grant failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let listed = vault.run(&["grants"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.status.success(), "grants failed: {stdout}");
    let fields = grant_row_fields(&stdout, "operator:");
    assert_eq!(
        &fields[..4],
        &["reserved", "agent", "operator:", "read"],
        "grant rows must expose each requested column: {stdout}"
    );
    assert_eq!(fields.len(), 6, "timestamp should be two formatted columns");
    assert!(
        fields[4].len() == 10 && fields[4].as_bytes()[4] == b'-' && fields[4].as_bytes()[7] == b'-',
        "creation date must use the CLI time-column format: {stdout}"
    );
    assert!(
        fields[5].len() == 8 && fields[5].as_bytes()[2] == b':' && fields[5].as_bytes()[5] == b':',
        "creation time must use the CLI time-column format: {stdout}"
    );
}

#[test]
fn grants_keep_read_and_sign_rows_separate_and_sort_by_prefix_then_operation() {
    let vault = GrantCliVault::new("grants-operations");
    vault.bootstrap();

    for (prefix, operation) in [("z:", "sign"), ("z:", "read"), ("a:", "sign")] {
        let created = vault.run(&[
            "grant",
            "--principal",
            "agent",
            "--prefix",
            prefix,
            "--operation",
            operation,
        ]);
        assert!(
            created.status.success(),
            "grant {prefix} {operation} failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );
    }

    let listed = vault.run(&["grants"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(listed.status.success(), "grants failed: {stdout}");
    let rows: Vec<Vec<&str>> = stdout
        .lines()
        .filter(|line| line.contains("reserved"))
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), 3, "every grant needs its own row: {stdout}");
    assert_eq!(&rows[0][..4], &["reserved", "agent", "a:", "sign"]);
    assert_eq!(&rows[1][..4], &["reserved", "agent", "z:", "read"]);
    assert_eq!(&rows[2][..4], &["reserved", "agent", "z:", "sign"]);
}

#[test]
fn revoked_grant_disappears_from_the_grants_listing() {
    let vault = GrantCliVault::new("grants-revoked");
    vault.bootstrap();
    let created = vault.run(&[
        "grant",
        "--principal",
        "agent",
        "--prefix",
        "operator:",
        "--operation",
        "read",
    ]);
    assert!(created.status.success());
    assert!(String::from_utf8_lossy(&vault.run(&["grants"]).stdout).contains("operator:"));

    let revoked = vault.run(&[
        "revoke-grant",
        "--principal",
        "agent",
        "--prefix",
        "operator:",
        "--operation",
        "read",
    ]);
    assert!(
        revoked.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let listed = vault.run(&["grants"]);
    assert!(listed.status.success());
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        "no grants",
        "a revoked grant must no longer be listed"
    );
}

#[test]
fn empty_grants_prints_an_explicit_no_grants_line() {
    let vault = GrantCliVault::new("grants-empty");
    vault.bootstrap();

    let listed = vault.run(&["grants"]);
    assert!(listed.status.success());
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        "no grants",
        "an empty grant table must not be silent"
    );
}

#[test]
fn bootstrap_put_mint_audit_end_to_end() {
    let root = tmp_root("e2e");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap a master key.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    let out = c.output().expect("run bootstrap");
    assert!(
        out.status.success(),
        "bootstrap: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // put an api_key credential.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("operator:db")
        .arg("--payload")
        .arg("sk-secret");
    global(&mut c);
    let out = c.output().expect("run put");
    assert!(
        out.status.success(),
        "put: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // mint a handle for it: stdout is the raw handle.
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("operator:db");
    global(&mut c);
    let out = c.output().expect("run mint-handle");
    assert!(
        out.status.success(),
        "mint: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let handle = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(handle.starts_with("ckh_"), "raw handle on stdout: {handle}");

    // verify-audit: the chain (put + mint_handle entries) must be intact.
    let mut c = cli();
    c.arg("verify-audit");
    global(&mut c);
    let out = c.output().expect("run verify-audit");
    assert!(
        out.status.success(),
        "verify-audit: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("intact"));

    // audit list shows the operations with the offline-cli actor.
    let mut c = cli();
    c.arg("audit");
    global(&mut c);
    let out = c.output().expect("run audit");
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(listing.contains("put"), "audit lists the put: {listing}");
    assert!(
        listing.contains("mint_handle"),
        "audit lists the mint: {listing}"
    );
    assert!(listing.contains("offline-cli"), "actor recorded: {listing}");

    // list shows the credential id + its active state (no secrets, no decrypt).
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let out = c.output().expect("run list");
    assert!(
        out.status.success(),
        "list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = String::from_utf8_lossy(&out.stdout);
    assert!(rows.contains("operator:db"), "list names the id: {rows}");
    assert!(rows.contains("active"), "list shows state: {rows}");
    assert!(
        !rows.contains("sk-secret"),
        "list must never print the payload: {rows}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A minted signing key is stored under the signing kind, can sign, and publishes the
/// matching public key. Inspecting the decrypted record and verifying the signature
/// proves the command's output is tied to the stored key rather than only its text.
#[test]
fn mint_signing_key_custodies_a_usable_key_and_prints_its_public_half() {
    let root = tmp_root("mint-signing-key");
    let data_dir = root.join("vault");
    let key_path = root.join("master.key");
    std::fs::write(&key_path, "11".repeat(32)).expect("write operator master key");

    let run = |args: &[&str]| {
        cli()
            .args([
                "--data-dir",
                data_dir.to_str().expect("data dir utf8"),
                "--key-path",
                key_path.to_str().expect("key path utf8"),
            ])
            .args(args)
            .output()
            .expect("run CLI")
    };

    let first = run(&["mint-signing-key", "--id", "signing:agent-assertion:7"]);
    assert!(
        first.status.success(),
        "first mint: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    let first_public = first_stdout
        .lines()
        .find_map(|line| line.strip_prefix("public_key_hex "))
        .expect("mint must print public key hex")
        .to_string();
    let first_key_id = first_stdout
        .lines()
        .find_map(|line| line.strip_prefix("key_id "))
        .expect("mint must print key id")
        .to_string();
    assert_eq!(first_public.len(), 64, "Ed25519 public keys are 32 bytes");
    assert_eq!(first_key_id.len(), 16, "key_id is eight digest bytes");
    assert!(
        !first_stdout.contains("PRIVATE KEY"),
        "the private PEM must never reach command output"
    );

    // Create-only is the safe default: an operator must explicitly acknowledge an
    // overwrite because an existing generation may already have signed artifacts.
    let duplicate = run(&["mint-signing-key", "--id", "signing:agent-assertion:7"]);
    assert!(
        !duplicate.status.success(),
        "minting an existing id without --replace must refuse"
    );

    let replacement = run(&[
        "mint-signing-key",
        "--id",
        "signing:agent-assertion:7",
        "--replace",
    ]);
    assert!(
        replacement.status.success(),
        "replacement mint: {}",
        String::from_utf8_lossy(&replacement.stderr)
    );
    let replacement_stdout = String::from_utf8_lossy(&replacement.stdout);
    let public_hex = replacement_stdout
        .lines()
        .find_map(|line| line.strip_prefix("public_key_hex "))
        .expect("replacement must print public key hex");
    let key_id = replacement_stdout
        .lines()
        .find_map(|line| line.strip_prefix("key_id "))
        .expect("replacement must print key id");
    assert_ne!(
        first_public, public_hex,
        "a replacement must generate a fresh key pair, not reprint the old public key"
    );

    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = open_sqlite(&descriptor).expect("open minted vault");
    EncryptedStore::migrate(&sqlite).expect("migrate minted vault");
    let vault = EncryptedStore::open(sqlite, MasterKey::from_bytes([0x11; 32]))
        .expect("open minted vault with operator key");
    let record = vault
        .get("signing:agent-assertion:7")
        .expect("read minted signing record");
    assert_eq!(record.kind, CredentialKind::SigningKey);

    let payload = b"canonical JSON bytes";
    let signature = credentials_core::signing::sign_ed25519(
        std::str::from_utf8(&record.payload).expect("mint stores PEM"),
        payload,
    )
    .expect("the minted record must be usable by credential.sign");
    let public: Vec<u8> = (0..public_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&public_hex[i..i + 2], 16).expect("public hex"))
        .collect();
    let raw_signature = base64::engine::general_purpose::STANDARD
        .decode(signature.signature_b64)
        .expect("signature base64");
    UnparsedPublicKey::new(&ED25519, &public)
        .verify(payload, &raw_signature)
        .expect("printed public key must verify the stored key's signature");
    assert_eq!(
        signature.key_id, key_id,
        "key id derives from the public key"
    );

    let wrong_method = run(&["mint-signing-key", "--id", "apikey:cannot-sign"]);
    assert!(
        !wrong_method.status.success()
            && String::from_utf8_lossy(&wrong_method.stderr).contains("requires an id beginning"),
        "minting under a non-signing method must refuse"
    );
    let bypass = run(&[
        "put",
        "--id",
        "signing:agent-assertion:unsafe",
        "--payload",
        "not-a-key",
    ]);
    assert!(
        !bypass.status.success()
            && String::from_utf8_lossy(&bypass.stderr).contains("mint-signing-key"),
        "generic put must not create a signing id with a non-signing record kind"
    );

    drop(vault);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn version_reports_the_built_cli_without_configuration() {
    let out = cli()
        .arg("--version")
        .output()
        .expect("run ck-auth --version");
    assert!(
        out.status.success(),
        "version: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The package version alone was the WHOLE assertion here, which is what let the
    // flag ship answering "is this ck-auth" rather than "which ck-auth": the constant
    // it pinned has not moved in the project's lifetime, so the test passed no matter
    // what code was inside. Now it must also carry the revision field.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stdout = stdout.trim();

    // Shape, not value. The revision is a property of the BINARY UNDER TEST, and under
    // CRED_CLI_BIN that is a staged artifact stamped with a real commit while this test
    // was compiled unstamped -- so asserting equality with the test's own BUILD_REV
    // would fail on exactly the artifact the override exists to verify, and would be
    // asserting the test's build rather than the binary's.
    let rest = stdout
        .strip_prefix(&format!("ck-auth {} (", env!("CARGO_PKG_VERSION")))
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("unexpected --version shape: {stdout}"));
    assert!(
        !rest.is_empty(),
        "the revision field must carry a value, even if it is `unknown`: {stdout}"
    );
    // Without an override this IS the test's own build, so the exact value is still
    // pinned in the ordinary run -- which is what keeps the field from silently
    // becoming a constant again.
    if std::env::var_os(CLI_BIN_ENV).is_none() {
        assert_eq!(rest, credentials_core::contract::BUILD_REV);
    }
}

/// `logout` stops serving reversibly (retire + revoke handles, row + audit kept).
/// `list` and `status` keep the parked row visible without turning it into a health
/// alarm.
#[test]
fn logout_retires_reversibly_without_degrading_health() {
    let root = tmp_root("logout");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap + put + mint a handle.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:x")
        .arg("--payload")
        .arg("sk-x");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("apikey:x");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // status before: ok, 1/1 serving.
    let mut c = cli();
    c.arg("status");
    global(&mut c);
    let out = c.output().expect("run status");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("vault: ok (1/1 serving)"), "pre-logout: {s}");

    // logout by --id (apikey:x is not a login provider).
    let mut c = cli();
    c.arg("logout").arg("--id").arg("apikey:x");
    global(&mut c);
    let out = c.output().expect("run logout");
    assert!(
        out.status.success(),
        "logout: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("revoked 1 handle(s)"),
        "logout revokes the handle: {s}"
    );

    // status after: ok, the id is named as retired, and the ROW SURVIVES (not
    // deleted) — logout is reversible by design.
    let mut c = cli();
    c.arg("status");
    global(&mut c);
    let out = c.output().expect("run status after");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("vault: ok (0/1 serving)"), "post-logout: {s}");
    assert!(
        s.contains("retired") && s.contains("apikey:x"),
        "the logged-out row survives as retired: {s}"
    );
    assert!(
        s.contains("retired: apikey:x"),
        "status names the intentionally parked id: {s}"
    );

    // `list` renders the retirement distinctly as well as `status`.
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let out = c.output().expect("run list after logout");
    let list = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        list.contains("retired") && list.contains("apikey:x"),
        "list distinguishes the retired row: {list}"
    );

    // The audit chain survives and stays intact (logout appended, destroyed nothing).
    let mut c = cli();
    c.arg("verify-audit");
    global(&mut c);
    let out = c.output().expect("run verify-audit");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("intact"));

    let _ = std::fs::remove_dir_all(&root);
}

/// An antigravity import stores an identity a consumer can actually resolve.
///
/// The importer parses the account's email out of the plugin store and, before this
/// was fixed, dropped it. That is invisible from inside the vault: the record stores
/// and serves normally, and the only symptom is downstream, where a consumer joining
/// on `account_id` cannot distinguish two antigravity accounts and collapses them
/// into one unlabelled entry.
///
/// So the assertion is on `account_id`, not `email`. Populating `email` alone would
/// look like a fix, render a value, and leave the symptom exactly as it was --
/// antigravity access tokens are opaque, so there is no live claim to fall back on.
///
/// Driven through the real binary, because the capture happens at the CLI call site:
/// a core-level test of the parser passes whether or not anything stores what it
/// returns.
#[test]
fn an_antigravity_import_stores_a_resolvable_account_identity() {
    use credentials_core::resolver::{KeySource, ResolverConfig};
    use credentials_core::store::EncryptedStore;

    let root = tmp_root("ag-import");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    // The plugin's on-disk shape, with two accounts so the selected one is not also
    // the first -- a capture that always took accounts[0] would otherwise pass.
    let store_json = root.join("antigravity-accounts.json");
    std::fs::write(
        &store_json,
        br#"{"version":4,"activeIndex":1,"accounts":[
              {"email":"first@x.com","refreshToken":"1//0-aaa","projectId":"proj-a"},
              {"email":"active@x.com","refreshToken":"1//0-bbb","projectId":"proj-b"}
            ]}"#,
    )
    .unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };
    let mut boot = cli();
    boot.arg("bootstrap");
    global(&mut boot);
    assert!(boot.output().unwrap().status.success(), "bootstrap");

    let mut imp = cli();
    imp.arg("import")
        .arg("--source")
        .arg("antigravity")
        .arg("--id")
        .arg("antigravity:google")
        .arg("--json")
        .arg(&store_json);
    global(&mut imp);
    let out = imp.output().expect("run import");
    assert!(
        out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Read the stored record back through the real decrypt path.
    let config = ResolverConfig {
        data_dir: data_dir.clone(),
        source: KeySource::OperatorPath {
            path: key_path.clone(),
        },
    };
    let key = credentials_core::resolver::resolve(&config, None).expect("resolve key");
    let sqlite = open_sqlite(&StorageDescriptor {
        // Same shape the other tests in this file use: the module id is imported
        // rather than spelled so a rename cannot silently point this at a different
        // store than the CLI just wrote to.
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .expect("open store");
    EncryptedStore::migrate(&sqlite).expect("migrate");
    let store = EncryptedStore::open(sqlite, key).expect("open vault");
    let record = store.get("antigravity:google").expect("read the record");

    assert_eq!(
        record.identity.account_id.as_deref(),
        Some("active@x.com"),
        "account_id is the field a consumer resolves identity from; without it the \
         record renders an email and still labels nothing"
    );
    assert_eq!(
        record.identity.email.as_deref(),
        Some("active@x.com"),
        "and the display field agrees with it"
    );
    assert!(
        record.identity.is_servable(),
        "the stored identity must satisfy the servable predicate"
    );
    // The identity must track the SELECTED account, not the store's first.
    assert!(
        record
            .oauth
            .as_ref()
            .unwrap()
            .refresh_token
            .starts_with("1//0-bbb"),
        "sanity: the active account's credential was the one imported"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn antigravity_import_prefers_explicit_account_id_and_only_overrides_source_email_when_requested() {
    use credentials_core::resolver::{KeySource, ResolverConfig};

    let root = tmp_root("ag-import-explicit-identity");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).expect("vault dir");
    std::fs::create_dir_all(key_path.parent().expect("key dir")).expect("key dir");
    let source = root.join("antigravity-accounts.json");
    std::fs::write(
        &source,
        br#"{"version":4,"activeIndex":0,"accounts":[{"email":"source@example.com","refreshToken":"1//0-source","projectId":"project"}]}"#,
    )
    .expect("write source");
    let run = |args: &[&str]| -> std::process::Output {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path)
            .output()
            .expect("run ck-auth")
    };
    let open_store = || {
        let key = credentials_core::resolver::resolve(
            &ResolverConfig {
                data_dir: data_dir.clone(),
                source: KeySource::OperatorPath {
                    path: key_path.clone(),
                },
            },
            None,
        )
        .expect("resolve key");
        let sqlite = open_sqlite(&StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        })
        .expect("open store");
        EncryptedStore::migrate(&sqlite).expect("migrate");
        EncryptedStore::open(sqlite, key).expect("open vault")
    };

    assert!(run(&["bootstrap"]).status.success(), "bootstrap");
    assert!(
        run(&[
            "import",
            "--source",
            "antigravity",
            "--id",
            "antigravity:google:source-email",
            "--json",
            source.to_str().expect("source path"),
            "--account-id",
            "acct-explicit",
        ])
        .status
        .success(),
        "explicit account import"
    );
    let store = open_store();
    let source_email = store
        .get("antigravity:google:source-email")
        .expect("record");
    assert_eq!(
        source_email.identity.account_id.as_deref(),
        Some("acct-explicit")
    );
    assert_eq!(
        source_email.identity.email.as_deref(),
        Some("source@example.com"),
        "the source email remains useful display metadata unless an operator overrides it"
    );
    drop(store);

    assert!(
        run(&[
            "import",
            "--source",
            "antigravity",
            "--id",
            "antigravity:google:operator-email",
            "--json",
            source.to_str().expect("source path"),
            "--account-id",
            "acct-operator",
            "--email",
            "operator@example.com",
        ])
        .status
        .success(),
        "operator email import"
    );
    let operator_email = open_store()
        .get("antigravity:google:operator-email")
        .expect("record");
    assert_eq!(
        operator_email.identity.account_id.as_deref(),
        Some("acct-operator")
    );
    assert_eq!(
        operator_email.identity.email.as_deref(),
        Some("operator@example.com")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn import_and_set_identity_attach_sticky_account_metadata_without_replacing_secret_material() {
    use credentials_core::resolver::{KeySource, ResolverConfig};

    let root = tmp_root("import-identity");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).expect("vault dir");
    std::fs::create_dir_all(key_path.parent().expect("key dir")).expect("key dir");
    let source = root.join("auth.json");
    std::fs::write(
        &source,
        r#"{"refresh":"refresh-original","access":"opaque-original","expires":4102444800000}"#,
    )
    .expect("write source");

    let run = |args: &[&str]| -> std::process::Output {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path)
            .output()
            .expect("run ck-auth")
    };
    let open_record = || {
        let config = ResolverConfig {
            data_dir: data_dir.clone(),
            source: KeySource::OperatorPath {
                path: key_path.clone(),
            },
        };
        let key = credentials_core::resolver::resolve(&config, None).expect("resolve key");
        let sqlite = open_sqlite(&StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        })
        .expect("open store");
        EncryptedStore::migrate(&sqlite).expect("migrate");
        EncryptedStore::open(sqlite, key).expect("open vault")
    };

    assert!(run(&["bootstrap"]).status.success(), "bootstrap");
    let imported = run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:anthropic",
        "--json",
        source.to_str().expect("source path"),
        "--account-id",
        "acct-import",
        "--email",
        "import@example.com",
        "--org-name",
        "Import Organization",
    ]);
    assert!(
        imported.status.success(),
        "import: {}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let store = open_record();
    let imported_record = store.get("oauth:anthropic").expect("imported record");
    assert_eq!(
        imported_record.identity.account_id.as_deref(),
        Some("acct-import"),
        "the import flag must land in the identity field consumers resolve"
    );
    drop(store);

    let store = open_record();
    let material_fixture = credentials_core::record::VaultRecord::new_oauth(
        "fixture",
        "anthropic",
        credentials_core::oauth::OAuthCredential {
            access_token: "opaque-fixture-access".to_string(),
            refresh_token: "fixture-refresh-secret".to_string(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://fixture.invalid/token".to_string(),
            client_id: Some("fixture-client".to_string()),
            scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
        },
        b"opaque-fixture-access".to_vec(),
    );
    store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &material_fixture,
            credentials_core::audit::AuditCtx::admin(credentials_core::audit::AuditOp::Import),
        )
        .expect("replace with field-complete OAuth fixture");
    let before_set = store.get("oauth:anthropic").expect("before set");
    drop(store);
    let set = run(&[
        "set-identity",
        "oauth:anthropic",
        "--account-id",
        "acct-set",
        "--email",
        "set@example.com",
    ]);
    assert!(
        set.status.success(),
        "set-identity: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    let store = open_record();
    let after_set = store.get("oauth:anthropic").expect("after set");
    assert_eq!(
        after_set.payload, before_set.payload,
        "set-identity must not rotate payload"
    );
    assert_eq!(
        after_set.oauth, before_set.oauth,
        "set-identity must not replace OAuth material"
    );
    assert_eq!(after_set.identity.account_id.as_deref(), Some("acct-set"));
    assert!(
        store
            .read_audit(None)
            .expect("audit")
            .iter()
            .any(|entry| entry.op == "set_identity"),
        "identity-only writes must leave an audit entry"
    );
    drop(store);

    let usable = run(&["usable"]);
    let usable_stdout = String::from_utf8_lossy(&usable.stdout);
    assert!(
        usable.status.success(),
        "usable: {}",
        String::from_utf8_lossy(&usable.stderr)
    );
    assert!(
        usable_stdout
            .lines()
            .any(|line| line.contains("oauth:anthropic") && line.contains("account=acct-set")),
        "usable must show non-secret account identity presence: {usable_stdout}"
    );

    std::fs::write(
        &source,
        r#"{"refresh":"refresh-rotated","access":"opaque-rotated","expires":4102444800000}"#,
    )
    .expect("rotate source");
    let replacement = run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:anthropic",
        "--json",
        source.to_str().expect("source path"),
        "--replace",
    ]);
    assert!(
        replacement.status.success(),
        "replace: {}",
        String::from_utf8_lossy(&replacement.stderr)
    );
    let sticky = open_record()
        .get("oauth:anthropic")
        .expect("sticky identity");
    assert_eq!(sticky.identity.account_id.as_deref(), Some("acct-set"));
    assert_eq!(
        sticky.oauth.as_ref().expect("OAuth").refresh_token,
        "refresh-rotated"
    );
    assert_eq!(
        sticky.oauth.as_ref().expect("OAuth").access_token,
        "opaque-rotated"
    );

    let cleared = run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:anthropic",
        "--json",
        source.to_str().expect("source path"),
        "--replace",
        "--clear-identity",
    ]);
    assert!(
        cleared.status.success(),
        "clear identity: {}",
        String::from_utf8_lossy(&cleared.stderr)
    );
    let cleared_record = open_record()
        .get("oauth:anthropic")
        .expect("cleared identity");
    assert!(
        cleared_record.identity.is_empty(),
        "--clear-identity must override sticky preservation"
    );
    assert_eq!(
        cleared_record.oauth.as_ref().expect("OAuth").refresh_token,
        "refresh-rotated"
    );
    assert_eq!(
        cleared_record.oauth.as_ref().expect("OAuth").access_token,
        "opaque-rotated"
    );

    assert!(
        run(&[
            "set-identity",
            "oauth:anthropic",
            "--account-id",
            "acct-to-clear",
        ])
        .status
        .success(),
        "set identity before clear"
    );
    assert!(
        run(&["set-identity", "oauth:anthropic", "--clear"])
            .status
            .success(),
        "set-identity --clear"
    );
    assert!(
        open_record()
            .get("oauth:anthropic")
            .expect("cleared by set-identity")
            .identity
            .is_empty(),
        "set-identity --clear must drop metadata without a source re-import"
    );

    let email_only = run(&[
        "import",
        "--source",
        "opencode",
        "--id",
        "oauth:other",
        "--json",
        source.to_str().expect("source path"),
        "--email",
        "missing-account@example.com",
    ]);
    assert!(
        !email_only.status.success(),
        "email without account_id must refuse"
    );
    assert!(
        String::from_utf8_lossy(&email_only.stderr).contains("--account-id is required"),
        "email-only refusal must name the missing field"
    );

    for invalid_value in ["", "account\ncontrol", &"x".repeat(257)] {
        let invalid_output = run(&[
            "set-identity",
            "oauth:anthropic",
            "--account-id",
            invalid_value,
        ]);
        assert!(
            !invalid_output.status.success(),
            "invalid account id {invalid_value:?} must refuse"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// `events` separates three outcomes an operator must not confuse.
///
/// "no events" and "this store cannot record events" would otherwise render the same,
/// and they call for different responses: the first means nothing has gone wrong, the
/// second means the recorder is not installed yet and an incident would leave no trace.
///
/// Also pins that the verb takes NO LEASE. The rows exist to explain a credential that
/// just failed, so requiring the daemon stopped would make the diagnostic unavailable
/// exactly when it is wanted.
#[test]
fn events_distinguishes_no_events_from_no_table_and_takes_no_lease() {
    let root = tmp_root("events");
    let data_dir = root.join("data");
    let key_path = root.join("secrets").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    // A write, so the schema (and with it the events table) is actually created.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:e")
        .arg("--payload")
        .arg("k");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    let mut c = cli();
    c.arg("events");
    global(&mut c);
    let out = c.output().expect("run events");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "events on a migrated vault must succeed"
    );
    assert!(
        text.contains("no authentication events recorded"),
        "an empty table must say so plainly; got: {text}"
    );

    // A store WITHOUT the table: the same command must say something different, because
    // "nothing recorded" and "nothing can be recorded" are different facts.
    let old = root.join("old");
    std::fs::create_dir_all(&old).unwrap();
    let conn = open_sqlite(&StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: old.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .expect("open a bare store");
    drop(conn);

    let mut c = cli();
    c.arg("events").arg("--data-dir").arg(&old);
    let out = c.output().expect("run events on a pre-migration store");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "an absent table is a reportable state, not a failure"
    );
    assert!(
        text.contains("no authentication-event table yet"),
        "an absent table must be distinguishable from an empty one; got: {text}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `invalidate` reports what it actually did, and reaches the state it claims.
///
/// The verb exits 0 for a credential that does not exist -- measured -- printing
/// "invalidated <id>; revoked 0 handle(s)". So an exit status says nothing here, and
/// the observable that separates a real invalidation from a no-op is the reported
/// handle count together with the resulting lifecycle state.
///
/// The store layer's own test covers `invalidate_audited`. This covers the verb: that
/// the CLI reaches that path, that its count comes from the transaction rather than
/// being printed unconditionally, and that a consumer's handle stops resolving.
#[test]
fn invalidate_reports_the_handles_it_revoked_and_leaves_the_row_needing_reauth() {
    let root = tmp_root("invalidate");
    let data_dir = root.join("data");
    let key_path = root.join("secrets").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:inv")
        .arg("--payload")
        .arg("k");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    for _ in 0..2 {
        let mut c = cli();
        c.arg("mint-handle").arg("--id").arg("apikey:inv");
        global(&mut c);
        assert!(c.output().unwrap().status.success());
    }

    let mut c = cli();
    c.arg("invalidate").arg("--id").arg("apikey:inv");
    global(&mut c);
    let out = c.output().expect("run invalidate");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "invalidate: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        report.contains("revoked 2 handle(s)"),
        "the count must come from the transaction, not be printed regardless; got: {report}"
    );

    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("needs_reauth") && rows.contains("apikey:inv"),
        "the row must be left needing reauth: {rows}"
    );

    // The negative arm, and the reason the count above is the assertion rather than
    // the exit status: the same verb on an absent credential also succeeds.
    let mut c = cli();
    c.arg("invalidate").arg("--id").arg("apikey:never-existed");
    global(&mut c);
    let out = c.output().expect("run invalidate on an absent id");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "an absent id still exits 0");
    assert!(
        report.contains("revoked 0 handle(s)"),
        "a no-op must report zero, which is what makes the positive count meaningful; \
         got: {report}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `put --replace` is the routine static-key rotation path: it bumps
/// `record_version` (the consumer cache-invalidation signal) and keeps the
/// existing handle, exactly like `login --replace` does for an OAuth record.
///
/// Note the property under test belongs to the REPLACE APPLIER, not to `put`.
///
/// `put --replace` and `login --replace` both build an `AdminOpBody::Store` carrying
/// `StoreMode::ReplaceUnconditional`, which dispatches to
/// `overwrite_unconditional_audited` — that updates the credential row and never
/// touches the handles table. So a consumer's handle surviving an operator's re-login
/// is this same guarantee, reached through the same code.
///
/// Worth saying because the name says `put`, so someone asking "does a re-login keep
/// my handle?" would not find it here. The OAuth login arm is not driven instead
/// because it needs a real provider exchange; this arm reaches the shared applier
/// offline.
#[test]
fn put_replace_rotates_a_static_key_bumping_version_and_keeping_the_handle() {
    let root = tmp_root("put-replace");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap + create the key + mint a handle for it.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("old-key");
    global(&mut c);
    assert!(c.output().unwrap().status.success());
    let mut c = cli();
    c.arg("mint-handle").arg("--id").arg("apikey:vast");
    global(&mut c);
    let handle = String::from_utf8_lossy(&c.output().unwrap().stdout)
        .trim()
        .to_string();
    assert!(handle.starts_with("ckh_"));

    // The created record is at v1.
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("v1") && rows.contains("apikey:vast"),
        "created at v1: {rows}"
    );

    // A create-mode put on the SAME id must be refused (create-only default) — this
    // is why a dedicated rotation verb is needed at all.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("new-key");
    global(&mut c);
    assert!(
        !c.output().unwrap().status.success(),
        "a plain put on an existing id must fail (create-only)"
    );

    // put --replace rotates it: new payload, version bumps to v2, id stays active.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("new-key")
        .arg("--replace");
    global(&mut c);
    let out = c.output().expect("run put --replace");
    assert!(
        out.status.success(),
        "put --replace: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let rows = String::from_utf8_lossy(&c.output().unwrap().stdout).into_owned();
    assert!(
        rows.contains("active         v2    apikey:vast"),
        "replace bumped the version and kept it active: {rows}"
    );

    // The handle SURVIVES the rotation, asserted on a COUNT rather than on an exit
    // status.
    //
    // `revoke-handle` succeeds for an unknown handle too -- measured: revoking a
    // never-minted string prints "revoked handle" and exits 0, deliberately, since
    // revocation is idempotent and must not confirm whether a handle exists. So
    // asserting that it succeeds proves nothing about the row surviving; it passes
    // just as well against a replace that orphaned every handle.
    //
    // `revoke-all-handles` reports the number it revoked, which is the signal that
    // distinguishes those cases: 1 if the replace kept the row, 0 if it did not.
    let mut c = cli();
    c.arg("revoke-all-handles").arg("--id").arg("apikey:vast");
    global(&mut c);
    let out = c.output().expect("run revoke-all-handles");
    let report = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "revoke-all-handles: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        report.contains("revoked 1 handle"),
        "the pre-rotation handle must still be live after the replace, so exactly one \
         is revoked here; got: {report}"
    );

    // --replace and --expected-hash are mutually exclusive.
    let mut c = cli();
    c.arg("put")
        .arg("--id")
        .arg("apikey:vast")
        .arg("--payload")
        .arg("z")
        .arg("--replace")
        .arg("--expected-hash")
        .arg("00");
    global(&mut c);
    assert!(
        !c.output().unwrap().status.success(),
        "--replace and --expected-hash cannot be combined"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Cookie repair uses the same replacement machinery as static-key rotation, but the
/// captured header comes from a file and must remain a Cookie record with no expiry.
#[test]
fn cookie_put_replace_bumps_version_and_keeps_the_handle_live() {
    let root = tmp_root("cookie-replace");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");
    let global = |command: &mut Command| {
        command
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut bootstrap = cli();
    bootstrap.arg("bootstrap");
    global(&mut bootstrap);
    assert!(bootstrap.output().expect("bootstrap").status.success());

    let payload_file = root.join("cookie.txt");
    std::fs::write(
        &payload_file,
        b" session=old=1; preference=space value; ending=%",
    )
    .expect("write captured cookie");
    let mut put = cli();
    put.arg("put")
        .arg("--id")
        .arg("cookie:qwencloud.com:work")
        .arg("--payload-file")
        .arg(&payload_file);
    global(&mut put);
    let output = put.output().expect("put cookie");
    assert!(
        output.status.success(),
        "cookie deposit: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut mint = cli();
    mint.arg("mint-handle")
        .arg("--id")
        .arg("cookie:qwencloud.com:work");
    global(&mut mint);
    assert!(mint.output().expect("mint handle").status.success());

    std::fs::write(
        &payload_file,
        b" session=new=2; preference=space value; ending=%",
    )
    .expect("write replacement cookie");
    let mut replace = cli();
    replace
        .arg("put")
        .arg("--id")
        .arg("cookie:qwencloud.com:work")
        .arg("--payload-file")
        .arg(&payload_file)
        .arg("--replace");
    global(&mut replace);
    let output = replace.output().expect("replace cookie");
    assert!(
        output.status.success(),
        "cookie replace: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut list = cli();
    list.arg("list");
    global(&mut list);
    let rows = String::from_utf8_lossy(&list.output().expect("list").stdout).into_owned();
    assert!(
        rows.contains("active         v2    cookie:qwencloud.com:work"),
        "replacement must bump the record version: {rows}"
    );

    // A cookie has no declarable expiry: the raw request header holds no Set-Cookie
    // attributes, so a timestamp here would be invented rather than captured.
    let mut expired = cli();
    expired
        .arg("put")
        .arg("--id")
        .arg("cookie:qwencloud.com:work")
        .arg("--payload-file")
        .arg(&payload_file)
        .arg("--expires-ms")
        .arg("1")
        .arg("--replace");
    global(&mut expired);
    let output = expired.output().expect("reject cookie expiry");
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("do not carry an expiry"),
        "cookie expiry must be refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // `revoke-all-handles` reports the real count, unlike idempotent `revoke-handle`.
    // Revoking the original handle proves replacement kept that handle live.
    let mut revoke = cli();
    revoke
        .arg("revoke-all-handles")
        .arg("--id")
        .arg("cookie:qwencloud.com:work");
    global(&mut revoke);
    let output = revoke.output().expect("revoke handles");
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("revoked 1 handle"),
        "replacement must retain the minted handle"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// An empty manual capture must fail during the `put` operation rather than being
/// stored as a successful-but-useless credential response.
#[test]
fn cookie_put_refuses_a_zero_byte_payload_file() {
    let root = tmp_root("cookie-empty");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");
    let global = |command: &mut Command| {
        command
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    let mut bootstrap = cli();
    bootstrap.arg("bootstrap");
    global(&mut bootstrap);
    assert!(bootstrap.output().expect("bootstrap").status.success());
    let payload_file = root.join("empty-cookie.txt");
    std::fs::write(&payload_file, []).expect("write empty capture");

    let mut put = cli();
    put.arg("put")
        .arg("--id")
        .arg("cookie:cursor.com")
        .arg("--payload-file")
        .arg(&payload_file);
    global(&mut put);
    let output = put.output().expect("put empty cookie");
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("payload must not be empty"),
        "zero-byte capture must be refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn admin_write_refused_while_lease_held() {
    // The structural "while stopped" proof: hold the single-writer lease (as the
    // daemon would) and confirm an admin CLI write is refused with the
    // daemon-running exit code (3), not applied.
    let root = tmp_root("lease");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
    };

    // bootstrap first (no lease held yet).
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // Now hold the lease (simulating the running daemon). The namespace MUST match
    // the CLI's ("default", what subc delivers) — the lease key is
    // (module_id, backend, namespace), so a mismatched namespace would take a
    // DIFFERENT lock and the admin write would (wrongly) not be refused.
    let descriptor = StorageDescriptor {
        // Imported rather than spelled: this store must take the SAME lease lock the
        // CLI takes, and the lease key is (module_id, backend, namespace). A literal
        // here drifts silently on a module rename — the two sides then take DIFFERENT
        // locks, the admin write is no longer refused, and this test stops proving
        // mutual exclusion while still passing on its other assertions.
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: "default".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _held = open_sqlite(&descriptor).expect("hold the lease");

    // An admin put must now be refused with exit code 3 (daemon running).
    let mut c = cli();
    c.arg("put").arg("--id").arg("x").arg("--payload").arg("y");
    global(&mut c);
    let out = c.output().expect("run put while leased");
    assert!(
        !out.status.success(),
        "put must fail while the lease is held"
    );
    assert_eq!(out.status.code(), Some(3), "daemon-running exit code");

    // AND THE REFUSAL NAMES THE NO-DOWNTIME FIX. A caller hitting this has no reason
    // to know --subc exists: it lives under `help overrides`, which is exactly where
    // someone who does not know the flag's name will not look. A refusal that names
    // only "stop the daemon" pushes every routine repair through an outage, so the
    // remedy has to travel with the refusal rather than be findable from it.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--subc"),
        "the refusal must name the flag that makes the write succeed; got: {stderr}"
    );
    assert!(
        stderr.contains("stop the daemon"),
        "and must still offer the offline path; got: {stderr}"
    );

    drop(_held);
    let _ = std::fs::remove_dir_all(&root);
}

/// The validation bypass must not exist in a shipped binary.
///
/// `validate_key` has a test-only short circuit so this file's `login --provider zai`
/// test can run without a provider to talk to. On the operator's path an `Invalid`
/// result is the ONLY thing that stops a bad key being stored, so an env var that
/// turns that refusal into a store -- while printing "API key is valid." -- must be
/// compiled out. It is gated on `debug_assertions`.
///
/// Asserted against a real release build rather than by reading the `#[cfg]`, because
/// the claim is about the artifact: a later edit could move the gate, widen it, or add
/// a second read of the same var, and every one of those still reads correctly at the
/// source while shipping the hole.
///
/// The positive control is what makes the absence a measurement: a string known to be
/// present must be found by the identical pipeline, so a scan that silently finds
/// nothing (wrong path, unreadable file, broken pipe) fails here rather than passing as
/// a clean result.
#[test]
#[ignore = "builds the release profile; run explicitly or in the release gate"]
fn validation_bypass_is_absent_from_a_release_build() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let built = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "credentials-module",
            "--bin",
            "ck-auth",
        ])
        .current_dir(&manifest)
        .output()
        .expect("run cargo build");
    assert!(
        built.status.success(),
        "release build failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let exe = manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("target/release/ck-auth");
    let bytes = std::fs::read(&exe).expect("read the release ck-auth");

    let find = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());

    // Positive control first: if this fails the scan is broken, not the binary clean.
    assert!(
        find("API key validation failed"),
        "positive control absent -- the scan cannot see strings it should find, so the \
         bypass check below would pass vacuously"
    );

    assert!(
        !find("CORTEXKIT_TEST_BYPASS_VALIDATION"),
        "the validation bypass env var is present in the release ck-auth binary"
    );
}

/// NOT RUNNABLE AGAINST A STAGED RELEASE ARTIFACT, deliberately on both sides.
///
/// This drives a real `login --provider zai`, which validates the key against the
/// provider's live endpoint. A debug build short-circuits that through
/// `CORTEXKIT_TEST_BYPASS_VALIDATION`; a release build COMPILES THE BYPASS OUT, so the
/// staged binary would attempt a genuine network call and fail.
///
/// Both halves are correct and the conflict is real, so it is skipped under
/// `CRED_CLI_BIN` rather than resolved by weakening either: shipping a validation
/// bypass in a release binary is the worse outcome by a wide margin, and a test that
/// silently passed by reaching a provider would be worse still.
///
/// This is the honest boundary of artifact verification: an arm that depends on a
/// debug-only seam verifies the SOURCE and cannot verify the SHIPPED BYTES. Recorded
/// here so the skip reads as a known limit rather than as flakiness.
#[test]
fn api_key_login_flow_integration() {
    if std::env::var_os(CLI_BIN_ENV).is_some() {
        eprintln!(
            "SKIPPING api_key_login_flow_integration: {CLI_BIN_ENV} is set, and this arm \
             needs the debug-only validation bypass that release builds omit"
        );
        return;
    }
    let root = tmp_root("api-key-login");
    let data_dir = root.join("data");
    let key_dir = root.join("secrets");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key_path = key_dir.join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();

    let global = |c: &mut Command| {
        c.arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path)
            .env("CORTEXKIT_TEST_BYPASS_VALIDATION", "1");
    };

    // bootstrap first.
    let mut c = cli();
    c.arg("bootstrap");
    global(&mut c);
    assert!(c.output().unwrap().status.success());

    // Create a temp file with a dummy key.
    let key_file = root.join("dummy.key");
    std::fs::write(&key_file, "sk-dummy-key\n").unwrap();

    // Run login --provider zai --payload-file <key_file>
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--payload-file")
        .arg(&key_file);
    global(&mut c);
    let out = c.output().expect("run login");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "login failed: stdout: {}, stderr: {}",
        stdout,
        stderr
    );
    assert!(stdout.contains("logged in and stored apikey:zai"));

    // Verify it is stored by listing.
    let mut c = cli();
    c.arg("list");
    global(&mut c);
    let out = c.output().expect("run list");
    let rows = String::from_utf8_lossy(&out.stdout);
    assert!(rows.contains("apikey:zai"));

    // Test that login --id apikey:zai:work passes the id rail
    let key_file2 = root.join("dummy2.key");
    std::fs::write(&key_file2, "sk-dummy-key-2\n").unwrap();
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--id")
        .arg("apikey:zai:work")
        .arg("--payload-file")
        .arg(&key_file2);
    global(&mut c);
    let out = c.output().expect("run login with labeled id");
    assert!(
        out.status.success(),
        "labeled id login failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Test that login --id zai fails the id rail
    let mut c = cli();
    c.arg("login")
        .arg("--provider")
        .arg("zai")
        .arg("--id")
        .arg("zai")
        .arg("--payload-file")
        .arg(&key_file2);
    global(&mut c);
    let out = c.output().expect("run login with invalid id");
    assert!(!out.status.success(), "invalid id login should have failed");
    assert!(String::from_utf8_lossy(&out.stderr).contains("login --id must be"));

    let _ = std::fs::remove_dir_all(&root);
}

/// The rotate verb's HAPPY PATH, end to end through the real binary.
///
/// The crash-cut suite proves the two-slot handover survives a SIGKILL at each cut,
/// but it drives a helper that re-implements the sequence -- parking between steps
/// requires them separated. So the sequence the CLI actually runs (heal, stage,
/// rewrap, promote, in that order) had no test at all: a verb nobody runs casually,
/// because it needs the daemon stopped, and whose first real exercise would be during
/// a key-compromise incident.
///
/// Asserts the four things an operator is relying on when they type it, each of which
/// can fail independently of the printed "rotated master key to ..." line:
///   1. records still decrypt (a rewrap that half-failed prints success too),
///   2. the audit chain still verifies ACROSS the re-seal,
///   3. handles survive, so consumers are not silently cut off,
///   4. a SECOND rotation works on the slot state the first one left behind.
///
/// WHAT PASS 2 DOES NOT PROVE, measured rather than assumed: it does not exercise the
/// heal. Deleting `heal_pending_rotation` leaves this test green, because after a
/// SUCCESSFUL rotation `promote` has already cleared `next`, so the heal is a no-op --
/// it only does work when a PRIOR rotation crashed between rewrap and promote. That
/// state needs a real SIGKILL to produce, and the crash-cut suite's
/// `double-heal-staged` cut is where it is proven. Deleting `promote` also leaves this
/// green, and correctly so: the next rotation's heal recovers exactly that state, which
/// is why the code calls promote hygiene rather than a safety step.
///
/// Recorded because the obvious reading of a two-pass loop is that it covers the
/// second-rotation guards, and it does not.
#[test]
fn the_rotate_verb_leaves_the_vault_usable_and_can_run_twice() {
    let root = tmp_root("rotate-happy");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success());
    assert!(
        run(&["put", "--id", "apikey:one", "--payload", "secret-one"])
            .status
            .success()
    );
    let minted = run(&["mint-handle", "--id", "apikey:one"]);
    assert!(minted.status.success());
    let handle = String::from_utf8_lossy(&minted.stdout).trim().to_string();
    assert!(handle.starts_with("ckh_"), "minted: {handle}");

    for pass in 1..=2 {
        let out = run(&["rotate-master-key"]);
        assert!(
            out.status.success(),
            "rotation {pass} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("rotated master key to key_id"),
            "rotation {pass} printed no new fingerprint"
        );

        // The record must still decrypt UNDER THE NEW KEY. `usable` is the only verb
        // that opens an envelope, so it is the one that can tell a real rewrap from a
        // rotation that reported success and left rows sealed under a key nobody holds.
        let scan = run(&["usable"]);
        let scan_out = String::from_utf8_lossy(&scan.stdout);
        assert!(scan.status.success(), "usable failed after rotation {pass}");
        assert!(
            scan_out.contains("serviceable: 1")
                && scan_out.contains("stranded: 0")
                && scan_out.contains("unreadable: 0"),
            "rotation {pass} left the record unreadable:\n{scan_out}"
        );

        // The chain spans the re-seal: the audit key is stored sealed and re-wrapped
        // with everything else, so a rotation that dropped it would break verification
        // of entries written before it.
        let verified = run(&["verify-audit"]);
        assert!(
            String::from_utf8_lossy(&verified.stdout).contains("intact"),
            "rotation {pass} broke the audit chain"
        );

        // Consumers hold handles and cannot distinguish a revoked one from an unknown
        // one, so a rotation that dropped them would read as an unexplained outage.
        // `revoke-all-handles` reports its count, which is the available proof the row
        // is still there without a live daemon to resolve against.
        let count = run(&["revoke-all-handles", "--id", "apikey:one"]);
        let count_out = String::from_utf8_lossy(&count.stdout);
        assert!(
            count_out.contains("revoked 1 handle"),
            "rotation {pass} lost the pre-rotation handle: {count_out}"
        );
        // Re-mint for the next pass, so pass 2 tests a handle that has itself crossed
        // a rotation.
        assert!(run(&["mint-handle", "--id", "apikey:one"]).status.success());
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// Both binaries report their source revision, and the daemon does it WITHOUT a
/// supervisor.
///
/// `--version` used to print only the package version -- a constant that has not moved
/// in the project's lifetime, so it answered "is this ck-auth" and never "which one".
/// The daemon had no `--version` at all: asking it what it was required starting it,
/// which needs a connection file and a live supervisor, so the identity check depended
/// on the thing being identified already running correctly.
///
/// The daemon arm is the load-bearing one. Its flag is handled before the `--subc`
/// gate, and that ordering is invisible from the code below it: moving argument parsing
/// earlier, or making the gate stricter, would restore the old behaviour with nothing
/// else failing.
#[test]
fn both_binaries_report_a_build_revision_without_a_supervisor() {
    for label in ["ck-auth", "ck-claustrum"] {
        let mut cmd = match label {
            "ck-auth" => cli(),
            _ => std::process::Command::new(env!("CARGO_BIN_EXE_ck-claustrum")),
        };
        let out = cmd
            .arg("--version")
            .output()
            .unwrap_or_else(|e| panic!("run {label} --version: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{label} --version failed: {}{stdout}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.starts_with(label),
            "{label} --version must name the binary: {stdout}"
        );
        // The revision is present as its own field. An unstamped build says `unknown`,
        // which is the honest answer and still proves the field is wired -- the release
        // script is what fills it, and a missing field would read as a stamped build
        // whose revision happened not to print.
        assert!(
            stdout.contains('(') && stdout.contains(')'),
            "{label} --version must carry a revision field: {stdout}"
        );
    }
}

/// `verify-audit` runs against a vault whose lease is HELD, and discriminates.
///
/// It used to go through `open_for_admin`, which takes the single-writer lease, so the
/// tamper-evidence check required stopping the daemon. That is why it had never run on
/// the live store in six weeks: nobody takes the credential vault down for an integrity
/// check, and a mechanism nobody can afford to invoke provides evidence of nothing.
///
/// The lease arm is the load-bearing one. A regression to the lease-taking form would
/// be invisible in every ordinary test -- they all run against an idle vault -- and
/// would only surface when someone tried to verify a live one, which is exactly the
/// situation that never happens.
#[test]
fn verify_audit_reads_a_leased_vault_and_names_a_broken_chain() {
    let root = tmp_root("verify-leased");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success());
    for i in 0..3 {
        assert!(run(&[
            "put",
            "--id",
            &format!("apikey:t{i}"),
            "--payload",
            "secret"
        ])
        .status
        .success());
    }

    // THE ARM THAT MATTERS: hold the single-writer lease, exactly as the running
    // daemon does, and verify anyway.
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _lease = open_sqlite(&descriptor).expect("take the lease as the daemon would");

    let held = run(&["verify-audit"]);
    let held_out = String::from_utf8_lossy(&held.stdout);
    assert!(
        held.status.success(),
        "verify-audit must work while the lease is held: {}{}",
        held_out,
        String::from_utf8_lossy(&held.stderr)
    );
    assert!(
        held_out.contains("intact"),
        "expected an intact chain, got: {held_out}"
    );

    // POSITIVE ARM FOR THE DETECTOR. "Intact" is only worth having if the check can
    // say BROKEN -- an implementation that always reported intact would satisfy every
    // assertion above.
    let db = data_dir.join("store.db");
    let conn = rusqlite::Connection::open(&db).expect("open to tamper");
    conn.execute("UPDATE audit_log SET actor = 'tampered' WHERE seq = 2", [])
        .expect("tamper one row");
    drop(conn);

    let broken = run(&["verify-audit"]);
    let stderr = String::from_utf8_lossy(&broken.stderr);
    assert!(
        !broken.status.success(),
        "a tampered chain must fail: {}",
        String::from_utf8_lossy(&broken.stdout)
    );
    assert!(
        stderr.contains("BROKEN at seq 2"),
        "the refusal must name WHERE the chain broke, so an operator knows what to \
         inspect: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `audit` reads a leased vault, and names WHY a row is flagged.
///
/// Two properties, both invisible until an operator needs them.
///
/// It used to take the single-writer lease, so the forensic log was unreadable while
/// the vault ran -- i.e. whenever anyone actually wanted it. Every column is plaintext,
/// so it needs neither the lease nor a master key.
///
/// And it rendered a bare "ALARM" for any flagged row. The alarm column is set on every
/// admin write BY DESIGN, so admin activity is loud: in the production vault 169 of 172
/// flagged rows are ordinary mints and revokes and 3 are the real detection signal.
/// Collapsing both into one word makes the routine 98% read as faults and buries the
/// thing an operator is scanning for.
#[test]
fn audit_reads_a_leased_vault_and_names_the_alarm_reason() {
    let root = tmp_root("audit-leased");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success());
    assert!(run(&["put", "--id", "apikey:one", "--payload", "secret"])
        .status
        .success());

    // Hold the lease exactly as the running daemon does.
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _lease = open_sqlite(&descriptor).expect("take the lease as the daemon would");

    let out = run(&["audit"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "audit must read while the lease is held: {}{}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );

    // The put is an admin write, so it is flagged -- and the row must say WHICH kind of
    // flag, not merely that there is one.
    assert!(
        stdout.contains("[admin_write]"),
        "a flagged row must name its reason, so routine admin activity is \
         distinguishable from a detection signal: {stdout}"
    );
    assert!(
        !stdout.contains(" ALARM"),
        "the bare ALARM marker collapses a routine admin write and a real anomaly into \
         one word: {stdout}"
    );
    // POSITIVE ARM: an implementation printing nothing at all would satisfy the
    // assertions above. The row itself has to be there.
    assert!(
        stdout.contains("apikey:one"),
        "the entry for the credential must be listed: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A refused verb must not advise a remedy that does not exist for it.
///
/// `rotate-master-key` and `bootstrap` have no admin op, so they can only run offline.
/// The lease refusal used to advise `--subc` for every verb -- following it lands on
/// the identical error, and an operator reasonably concludes the vault is broken. For
/// rotate that happens DURING A KEY COMPROMISE, which is the worst possible moment to
/// be sent through a door that is not there.
///
/// The two arms are asserted together because the fix is a discrimination, not a
/// wording change: making both say "offline only" would pass the first assertion and
/// break every mutation, which really can be committed through the running daemon.
#[test]
fn a_lease_refusal_advises_only_a_remedy_that_exists_for_that_verb() {
    let root = tmp_root("refusal-remedy");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };
    assert!(run(&["bootstrap"]).status.success());

    // Hold the lease exactly as the running daemon does.
    let descriptor = StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: data_dir.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let _lease = open_sqlite(&descriptor).expect("take the lease as the daemon would");

    // NO ROUTE PATH: must say so, and must not point at --subc.
    let rotate = run(&["rotate-master-key"]);
    let rotate_err = String::from_utf8_lossy(&rotate.stderr);
    assert!(!rotate.status.success(), "rotate must refuse under a lease");
    assert!(
        rotate_err.contains("no route path"),
        "rotate has no admin op and must say so: {rotate_err}"
    );
    assert!(
        rotate_err.contains("--subc will NOT help"),
        "the refusal must rule out the remedy an operator would otherwise try: \
         {rotate_err}"
    );

    // ROUTE PATH EXISTS: the mutation arm must still offer --subc. Without this, a
    // "fix" that told every verb to go offline would pass the assertions above while
    // removing the zero-downtime path that 11 of 13 write verbs depend on.
    let put = run(&["put", "--id", "apikey:one", "--payload", "secret"]);
    let put_err = String::from_utf8_lossy(&put.stderr);
    assert!(
        !put.status.success(),
        "an offline put must refuse under a lease"
    );
    assert!(
        put_err.contains("--subc <connection-file>"),
        "a mutation CAN be committed through the running daemon, and the refusal must \
         say so: {put_err}"
    );
    assert!(
        !put_err.contains("no route path"),
        "a mutation must not be described as offline-only: {put_err}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `events` discloses that older rows were discarded, rather than presenting a trimmed
/// window as the whole history.
///
/// The per-credential cap is enforced by a silent DELETE, which is right -- an unbounded
/// diagnostic table on a path a hostile consumer can drive is a disk-exhaustion lever.
/// But it leaves a reader unable to tell "this is everything that happened" from "this
/// is what survived", and those close an investigation in opposite directions: the first
/// says the cause is not here, the second says the evidence is gone.
///
/// A peer hit the same shape tonight in a retention job that pruned 125,000 rows and
/// advanced a tamper-evident seal while logging only on error -- a successful first run
/// and a dead worker were indistinguishable.
#[test]
fn events_discloses_that_the_retention_cap_discarded_older_rows() {
    let root = tmp_root("events-cap");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };
    assert!(run(&["bootstrap"]).status.success());

    // NEGATIVE CONTROL, and it must be a credential WITH events but BELOW the cap.
    //
    // My first version used an EMPTY table, and a mutation that always warns survived
    // it: GROUP BY over zero rows returns nothing whatever the HAVING clause says, so
    // the control could not distinguish a correct check from one that fires
    // unconditionally. An empty-input control tests the input, not the predicate.

    // Flood one credential past the cap directly through the store, which is what a
    // consumer looping on report_auth_failure produces.
    {
        let descriptor = StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let raw = open_sqlite(&descriptor).expect("open");
        // bootstrap provisioned the KEY; the schema arrives on first open by the daemon
        // or CLI, so migrate before opening the vault here.
        credentials_core::store::EncryptedStore::migrate(&raw).expect("migrate");
        let key = credentials_core::resolver::resolve(
            &credentials_core::resolver::ResolverConfig {
                data_dir: data_dir.clone(),
                source: credentials_core::resolver::KeySource::OperatorPath {
                    path: key_path.clone(),
                },
            },
            None,
        )
        .expect("resolve");
        let store = credentials_core::store::EncryptedStore::open(raw, key).expect("vault");
        let rec = credentials_core::record::VaultRecord::new_static(
            credentials_core::record::CredentialKind::ApiKey,
            "test",
            b"secret".to_vec(),
            None,
        );
        store.create("apikey:flooded", &rec).expect("seed");
        // The below-cap sibling: it must NOT appear in the notice.
        store
            .create("apikey:quiet", &rec)
            .expect("seed the quiet one");
        for _ in 0..3 {
            store
                .record_auth_event(
                    "apikey:quiet",
                    credentials_core::store::AuthObservation {
                        kind: "consumer_report",
                        provider_status: Some(401),
                        detail: None,
                        reporter_source: None,
                    },
                    Some(1),
                )
                .expect("record a below-cap event");
        }
        for _ in 0..(credentials_core::store::AUTH_EVENTS_PER_CREDENTIAL + 5) {
            store
                .record_auth_event(
                    "apikey:flooded",
                    credentials_core::store::AuthObservation {
                        kind: "consumer_report",
                        provider_status: Some(401),
                        detail: None,
                        reporter_source: None,
                    },
                    Some(1),
                )
                .expect("record an event");
        }
    }

    let out = run(&["events"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "events must succeed: {stdout}");
    assert!(
        stdout.contains("retention cap"),
        "a credential at the cap must be disclosed, so a trimmed window is not read as \
         the whole history: {stdout}"
    );
    // THE CONTROL THAT DISCRIMINATES: a credential with events but below the cap must
    // NOT be named. A check that fires unconditionally passes every other assertion.
    assert!(
        !stdout.contains("apikey:quiet"),
        "a credential below the cap must not be reported as having lost history -- a \
         notice that names everything tells an operator nothing: {stdout}"
    );
    assert!(
        stdout.contains("apikey:flooded"),
        "the notice must NAME which credential lost history -- 'some rows were \
         discarded' does not tell an operator whether it was the one they are \
         investigating: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `usable` must not promise a refresh that the state makes unreachable.
///
/// An expired access token on an ACTIVE record genuinely does refresh on the next
/// get -- that is the routine state of a healthy credential. On a NEEDS_REAUTH
/// record the same material is inert: `EncryptedStore::get` refuses at the state
/// check, before decrypting and long before the engine could attempt a refresh.
/// There is no next get.
///
/// The old line said "refreshes on next get" for both, which is true of the MATERIAL
/// and false of the RECORD -- and it invites an operator to wait for a recovery that
/// cannot arrive. Live instance: oauth:anthropic:ufuk3 read that way for five hours
/// while three sibling accounts refreshed normally around it.
///
/// Both arms asserted together, because the fix is a discrimination: making every
/// expired row say "unreachable" would satisfy the first assertion and lie about
/// every healthy credential in the vault.
#[test]
fn usable_does_not_promise_a_refresh_the_state_makes_unreachable() {
    let root = tmp_root("usable-unreachable");
    let data_dir = root.join("vault");
    let key_path = root.join("keys").join("master.key");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut c = cli();
        c.args(args)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--key-path")
            .arg(&key_path);
        c.output().expect("run ck-auth")
    };
    assert!(run(&["bootstrap"]).status.success());

    // Two OAuth records with EXPIRED access tokens and live refresh material. They
    // differ only in state, which is the whole point.
    {
        let descriptor = StorageDescriptor {
            module_id: credentials_core::contract::MODULE_ID.into(),
            storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: data_dir.join("store.db").to_string_lossy().into_owned(),
            },
        };
        let raw = open_sqlite(&descriptor).expect("open");
        credentials_core::store::EncryptedStore::migrate(&raw).expect("migrate");
        let key = credentials_core::resolver::resolve(
            &credentials_core::resolver::ResolverConfig {
                data_dir: data_dir.clone(),
                source: credentials_core::resolver::KeySource::OperatorPath {
                    path: key_path.clone(),
                },
            },
            None,
        )
        .expect("resolve");
        let store = credentials_core::store::EncryptedStore::open(raw, key).expect("vault");

        let expired_at = chrono_now_ms() - 60_000;
        for id in ["oauth:healthy", "oauth:dead"] {
            let rec = credentials_core::record::VaultRecord::new_oauth(
                "test",
                "anthropic",
                credentials_core::oauth::OAuthCredential {
                    access_token: "stale".into(),
                    refresh_token: "live-refresh-material".into(),
                    expires_at_ms: Some(expired_at),
                    token_url: "https://example.invalid/token".into(),
                    client_id: None,
                    scopes: Vec::new(),
                },
                b"stale".to_vec(),
            );
            store.create(id, &rec).expect("seed");
        }
        // Only the second is marked dead, exactly as a consumer report would.
        store
            .invalidate_if_version_audited(
                "oauth:dead",
                1,
                credentials_core::audit::AuditCtx::admin(
                    credentials_core::audit::AuditOp::ReportAuthFailure,
                ),
            )
            .expect("mark needs_reauth");
    }

    let out = run(&["usable"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "usable must succeed: {stdout}");

    let dead_line = stdout
        .lines()
        .find(|l| l.contains("oauth:dead"))
        .unwrap_or_else(|| panic!("no line for the dead credential: {stdout}"));
    assert!(
        dead_line.contains("UNREACHABLE"),
        "a needs_reauth record must not promise a refresh that get() refuses before \
         reaching: {dead_line}"
    );

    // THE ARM THAT KEEPS IT HONEST: an active expired record still promises the
    // refresh, because it genuinely happens.
    let healthy_line = stdout
        .lines()
        .find(|l| l.contains("oauth:healthy"))
        .unwrap_or_else(|| panic!("no line for the healthy credential: {stdout}"));
    assert!(
        healthy_line.contains("refreshes on next get"),
        "an ACTIVE expired record is the routine state of a healthy credential and \
         must still say it refreshes: {healthy_line}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64
}

/// The temp-dir connection file is discovered, and ambiguity refuses rather than guesses.
///
/// subc writes `<temp>/subc-<user-token>.connection.json` when `XDG_RUNTIME_DIR` is
/// unset -- which is STOCK MACOS, so this is the default arrangement there rather
/// than an edge case. A CLI that misses it does not fail loudly: it concludes no
/// daemon is running, takes the offline path, hits the single-writer lease, and
/// tells the operator to STOP THE DAEMON -- naming the one remedy they should not
/// use, while never mentioning the `--subc` route that would have worked. Reported
/// from a real box (claustrum#3).
///
/// Drives the DEFAULT path deliberately: auto-discovery is scoped to a defaulted
/// `--data-dir`, because an explicit vault dir means "this vault" and a discovered
/// daemon may serve a different one. So the probe overrides HOME/XDG_DATA_HOME to
/// move the default derivation into a throwaway tree rather than passing --data-dir,
/// which would disable the very thing under test.
#[test]
fn a_temp_dir_connection_file_is_found_and_ambiguity_refuses() {
    let root = std::env::temp_dir().join(format!(
        "ck-disco-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let tmp = root.join("tmp");
    let home = root.join("home");
    std::fs::create_dir_all(&tmp).expect("tmp");
    std::fs::create_dir_all(&home).expect("home");

    // std::env::temp_dir() reads TMPDIR on unix and TMP/TEMP on Windows, so all
    // three must be set or the probe silently scans the REAL temp dir -- which
    // finds nothing, attempts no route, and fails for a reason that has nothing to
    // do with the code under test.
    let point_at_probe_dirs = |cmd: &mut std::process::Command| {
        cmd.env("TMPDIR", &tmp)
            .env("TMP", &tmp)
            .env("TEMP", &tmp)
            .env("HOME", &home)
            .env("XDG_DATA_HOME", home.join("share"))
            .env_remove("XDG_RUNTIME_DIR");
    };

    // --key-path, NOT CK_MASTER_KEY_PATH: that env var is the DAEMON's override,
    // and parse_global takes the FLAG only. Passing the env var leaves the CLI on
    // the keychain backend, where the outcome depends on whether the platform has a
    // keychain binary at all rather than on discovery. (--key-path is safe here
    // because only an explicit --data-dir disables auto-discovery.)
    let run = |key: Option<&std::path::Path>| -> String {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ck-auth"));
        cmd.arg("list");
        if let Some(k) = key {
            cmd.arg("--key-path").arg(k);
        }
        point_at_probe_dirs(&mut cmd);
        let out = cmd.output().expect("run list");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };

    // A REAL vault in the default location, so `list` gets past key resolution and
    // the route attempt is reachable. Without this the one-candidate and
    // no-candidate paths produce byte-identical output ("no master key has been
    // provisioned") and the assertion below proves nothing -- measured, not assumed.
    let key_path = root.join("master.key");
    let mut boot = std::process::Command::new(env!("CARGO_BIN_EXE_ck-auth"));
    boot.arg("bootstrap").arg("--key-path").arg(&key_path);
    point_at_probe_dirs(&mut boot);
    let bootstrap = boot.output().expect("bootstrap");
    assert!(
        bootstrap.status.success(),
        "probe vault must bootstrap: {}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );

    // NO candidate: nothing is discovered, so no route is attempted at all.
    let none_found = run(Some(key_path.as_path()));
    assert!(
        !none_found.contains("no live module"),
        "with no connection file anywhere, the CLI must not attempt a route: {none_found}"
    );

    // ONE candidate: discovered, so a route IS attempted -- and fails, because the
    // file is a stub. The attempt is the observable difference, and it is what the
    // temp-dir arm exists to produce.
    std::fs::write(tmp.join("subc-1000.connection.json"), "{}").expect("write one");
    let single = run(Some(key_path.as_path()));
    assert!(
        single.contains("no live module"),
        "one candidate must be DISCOVERED and routed to (the stub then fails, which \
         is the observable proof the arm ran): {single}"
    );
    assert!(
        !single.contains("not guessing which daemon is yours"),
        "exactly one candidate must be used rather than refused: {single}"
    );

    // TWO candidates: refuse and name them. On a shared temp dir the token exists
    // precisely so different OS users do not collide, so two files mean two users --
    // picking one could point an admin op at another user's daemon.
    std::fs::write(tmp.join("subc-1001.connection.json"), "{}").expect("write two");
    let ambiguous = run(Some(key_path.as_path()));
    assert!(
        ambiguous.contains("not guessing which daemon is yours"),
        "two candidates must REFUSE rather than pick one: {ambiguous}"
    );
    assert!(
        ambiguous.contains("subc-1000.connection.json")
            && ambiguous.contains("subc-1001.connection.json"),
        "the refusal must name both so --subc can be chosen: {ambiguous}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `ck auth usable` reports a static record's AGE from the store's plaintext
/// updated_at_ms, end to end against a real store.
///
/// The failure this exists for is a WRONG COLUMN INDEX in the scan's row mapping.
/// `updated_at_ms` and `record_version` are both i64, so reading the wrong one
/// compiles, runs, and renders a plausible-looking age: version 1 read as a
/// millisecond timestamp is 1970, i.e. "written 20000d ago". No unit test on the
/// predicate can see that, because the predicate never touches the query.
///
/// So a record written seconds ago must report 0 days -- a value only the right column
/// can produce.
#[test]
fn usable_reports_a_static_records_age_from_the_stores_own_timestamp() {
    let root = tmp_root("age-probe");
    let data = root.join("vault");
    let key = root.join("master.key");
    std::fs::create_dir_all(&data).expect("data dir");

    let run = |args: &[&str]| -> std::process::Output {
        let mut cmd = cli();
        cmd.args(args)
            .arg("--data-dir")
            .arg(&data)
            .arg("--key-path")
            .arg(&key)
            .output()
            .expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success(), "bootstrap");

    let payload = root.join("p.txt");
    std::fs::write(&payload, "probe-key").expect("payload");
    let put = run(&[
        "put",
        "--id",
        "apikey:age-probe",
        "--payload-file",
        payload.to_str().unwrap(),
    ]);
    assert!(
        put.status.success(),
        "put: {}",
        String::from_utf8_lossy(&put.stderr)
    );

    let out = run(&["usable"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let line = text
        .lines()
        .find(|l| l.contains("apikey:age-probe"))
        .unwrap_or_else(|| panic!("no row for the probe credential in:\n{text}"));

    assert!(
        line.contains("written 0d ago"),
        "a record written seconds ago must report 0 days. Any other number means the \
         scan read the wrong column -- record_version is also i64, and as a millisecond \
         timestamp it lands in 1970. Got: {line}"
    );
}

/// Equal write ages have opposite operational meanings for an API key and a session
/// cookie. The cookie row must make that staleness interpretation visible without
/// inventing a lifetime threshold.
#[test]
fn usable_distinguishes_a_cookie_age_from_an_api_key_age() {
    let root = tmp_root("cookie-usable");
    let data = root.join("vault");
    let key = root.join("master.key");
    std::fs::create_dir_all(&data).expect("data dir");

    let run = |args: &[&str]| -> std::process::Output {
        let mut command = cli();
        command
            .args(args)
            .arg("--data-dir")
            .arg(&data)
            .arg("--key-path")
            .arg(&key)
            .output()
            .expect("run ck-auth")
    };

    assert!(run(&["bootstrap"]).status.success(), "bootstrap");
    assert!(
        run(&["put", "--id", "apikey:age-compare", "--payload", "same-age"])
            .status
            .success(),
        "put API key"
    );
    let cookie_file = root.join("cookie.txt");
    std::fs::write(&cookie_file, b"session=same-age; ending=%").expect("write cookie");
    assert!(
        run(&[
            "put",
            "--id",
            "cookie:cursor.com",
            "--payload-file",
            cookie_file.to_str().expect("utf8 path"),
        ])
        .status
        .success(),
        "put cookie"
    );

    let out = run(&["usable"]);
    assert!(
        out.status.success(),
        "usable: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let api = text
        .lines()
        .find(|line| line.contains("apikey:age-compare"))
        .unwrap_or_else(|| panic!("missing API-key row in:\n{text}"));
    let cookie = text
        .lines()
        .find(|line| line.contains("cookie:cursor.com"))
        .unwrap_or_else(|| panic!("missing cookie row in:\n{text}"));

    assert!(
        api.contains("static") && api.contains("written 0d ago"),
        "API-key age is neutral inventory: {api}"
    );
    assert!(
        cookie.contains("cookie")
            && cookie.contains("session cookie")
            && cookie.contains("captured 0d ago")
            && cookie.contains("staleness signal"),
        "cookie age must be rendered as a staleness signal: {cookie}"
    );
    assert_ne!(
        api, cookie,
        "identical ages must render as different credential kinds"
    );

    let _ = std::fs::remove_dir_all(&root);
}
