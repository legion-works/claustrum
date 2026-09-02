#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
use credentials_core::store::EncryptedStore;
#[path = "../src/bin/cli_support/credential_client.rs"]
mod credential_client;
#[path = "../src/bin/cli_support/opencode_files.rs"]
mod opencode_files;
#[path = "../src/bin/cli_support/route_client.rs"]
mod route_client;

use serde_json::{json, Value};

mod common;
use common::tmp_root;

fn cli() -> Command {
    match std::env::var_os("CRED_CLI_BIN") {
        Some(path) => Command::new(path),
        None => Command::new(env!("CARGO_BIN_EXE_ck-auth")),
    }
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

fn read_raw_handle_fixture(
    name: &str,
    raw: &str,
) -> Result<opencode_files::HandleFile, opencode_files::OpenCodeFilesError> {
    let root = tmp_root(name);
    let handles = root.join("opencode-handles.json");
    std::fs::write(&handles, raw).expect("handle fixture");
    std::fs::set_permissions(
        &handles,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("mode");
    let result = opencode_files::read_handle_file(&handles);
    let _ = std::fs::remove_dir_all(root);
    result
}

#[test]
fn the_golden_tombstone_matches_the_rust_contract() {
    let golden: Value = serde_json::from_str(include_str!(
        "../../../packages/opencode/golden/tombstone.json"
    ))
    .expect("golden tombstone json");
    let fixtures = opencode_files::golden_tombstone_fixtures().expect("rust fixtures");

    assert_eq!(fixtures.api.provider, golden["fixtures"]["api"]["provider"]);
    assert_eq!(fixtures.api.entry, golden["fixtures"]["api"]["entry"]);
    assert_eq!(
        fixtures.oauth.provider,
        golden["fixtures"]["oauth"]["provider"]
    );
    assert_eq!(fixtures.oauth.entry, golden["fixtures"]["oauth"]["entry"]);
}

#[test]
fn an_auth_file_with_a_mode_other_than_0600_is_refused() {
    let root = tmp_root("auth-mode");
    let auth = root.join("auth.json");
    std::fs::write(&auth, r#"{"deepseek":{"type":"api","key":"x"}}"#).expect("auth");
    std::fs::set_permissions(&auth, std::os::unix::fs::PermissionsExt::from_mode(0o640))
        .expect("mode");

    let err = opencode_files::read_auth_entries(&auth).expect_err("insecure mode refuses");
    assert!(err.to_string().contains("0600"), "unexpected error: {err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_unknown_handle_shape_is_refused() {
    let root = tmp_root("unknown-handle-shape");
    let handles = root.join("opencode-handles.json");
    std::fs::write(
        &handles,
        r#"{"version":1,"providers":[{"provider":"deepseek","shape":"unknown","serve":"opencode-claustrum","accounts":[]}]}"#,
    )
    .expect("handle file");
    std::fs::set_permissions(
        &handles,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("mode");

    let err = opencode_files::read_handle_file(&handles).expect_err("unknown shape refuses");
    assert!(
        err.to_string().contains("unknown variant"),
        "unknown shape must produce a named refusal: {err}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_handle_file_with_duplicate_providers_is_refused() {
    let err = read_raw_handle_fixture(
        "duplicate-handle-provider",
        r#"{"version":1,"providers":[{"provider":"deepseek","shape":"api","serve":"opencode-claustrum","accounts":[]},{"provider":"deepseek","shape":"api","serve":"opencode-claustrum","accounts":[]}]}"#,
    )
    .expect_err("duplicate providers refuse");

    assert!(
        err.to_string().contains("duplicates provider"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_handle_file_with_duplicate_labels_within_one_provider_is_refused() {
    let err = read_raw_handle_fixture(
        "duplicate-handle-label",
        r#"{"version":1,"providers":[{"provider":"deepseek","shape":"api","serve":"opencode-claustrum","accounts":[{"label":"main","handle":"ckh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","credential_id":"apikey:deepseek:main"},{"label":"main","handle":"ckh_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","credential_id":"apikey:deepseek:backup"}]}]}"#,
    )
    .expect_err("duplicate labels refuse");

    assert!(
        err.to_string().contains("duplicates account label"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_handle_file_with_a_malformed_capability_is_refused() {
    let err = read_raw_handle_fixture(
        "malformed-handle",
        r#"{"version":1,"providers":[{"provider":"deepseek","shape":"api","serve":"opencode-claustrum","accounts":[{"label":"main","handle":"ckh_too-short","credential_id":"apikey:deepseek:main"}]}]}"#,
    )
    .expect_err("malformed handle refuses");

    assert!(
        err.to_string().contains("invalid handle"),
        "unexpected error: {err}"
    );
}

#[test]
fn hostile_provider_ids_and_account_labels_are_refused_by_the_rust_handle_validator() {
    for (provider, label) in [
        ("__proto__", "main"),
        ("constructor", "main"),
        ("prototype", "main"),
        ("DeepSeek", "main"),
        ("deepseek", "bad label"),
    ] {
        let raw = format!(
            r#"{{"version":1,"providers":[{{"provider":"{provider}","shape":"api","serve":"opencode-claustrum","accounts":[{{"label":"{label}","handle":"ckh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","credential_id":"apikey:deepseek:main"}}]}}]}}"#
        );
        let err =
            read_raw_handle_fixture("hostile-provider-id", &raw).expect_err("hostile id refuses");
        assert!(
            err.to_string().contains("invalid"),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn handle_file_debug_redacts_live_and_superseded_capabilities() {
    let file = opencode_files::HandleFile {
        version: 1,
        providers: vec![opencode_files::HandleProvider {
            provider: "deepseek".into(),
            shape: opencode_files::HandleShape::Api,
            serve: "opencode-claustrum".into(),
            accounts: vec![opencode_files::HandleAccount {
                label: "main".into(),
                handle: "ckh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                credential_id: "apikey:deepseek:main".into(),
                superseded: vec!["ckh_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()],
            }],
        }],
    };

    let rendered = format!("{file:?}");
    assert!(!rendered.contains("ckh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(!rendered.contains("ckh_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
}

#[test]
fn custody_file_reads_are_capped_and_writes_require_a_trusted_parent_with_0600_at_create() {
    let root = tmp_root("custody-file-caps");
    let auth = root.join("auth.json");
    let handles = root.join("handles.json");
    std::fs::write(
        &auth,
        format!(
            r#"{{"deepseek":{{"type":"api","key":"x"}},"padding":"{}"}}"#,
            "x".repeat(1024 * 1024)
        ),
    )
    .expect("auth fixture");
    std::fs::write(
        &handles,
        format!(
            r#"{{"version":1,"providers":[],"padding":"{}"}}"#,
            "x".repeat(256 * 1024)
        ),
    )
    .expect("handle fixture");
    for path in [&auth, &handles] {
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("fixture mode");
    }
    assert!(opencode_files::read_auth_entries(&auth)
        .expect_err("auth cap")
        .to_string()
        .contains("1 MiB"));
    assert!(opencode_files::read_handle_file(&handles)
        .expect_err("handle cap")
        .to_string()
        .contains("256 KiB"));

    // The tempfile is unobservable after rename, so the source assertion pins the creation primitive itself.
    let source = include_str!("../src/bin/cli_support/opencode_files.rs");
    assert!(source.contains("OpenOptionsExt") && source.contains(".mode(0o600)"));
    std::fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o777))
        .expect("unsafe parent mode");
    let err = opencode_files::write_auth_entry(
        &root.join("unsafe-auth.json"),
        "deepseek",
        json!({"type":"api","key":"x"}),
    )
    .expect_err("world-writable parent refuses");
    assert!(
        err.to_string().contains("parent directory"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_handle_file_with_an_empty_credential_id_is_refused() {
    let err = read_raw_handle_fixture(
        "empty-credential-id",
        r#"{"version":1,"providers":[{"provider":"deepseek","shape":"api","serve":"opencode-claustrum","accounts":[{"label":"main","handle":"ckh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","credential_id":""}]}]}"#,
    )
    .expect_err("empty credential id refuses");

    assert!(
        err.to_string().contains("invalid credential id"),
        "unexpected error: {err}"
    );
}

#[test]
fn a_handle_file_with_a_malformed_superseded_capability_is_refused() {
    let err = read_raw_handle_fixture(
        "malformed-superseded-handle",
        r#"{"version":1,"providers":[{"provider":"deepseek","shape":"api","serve":"opencode-claustrum","accounts":[{"label":"main","handle":"ckh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","credential_id":"apikey:deepseek:main","superseded":["not-a-handle"]}]}]}"#,
    )
    .expect_err("malformed superseded handle refuses");

    assert!(
        err.to_string().contains("invalid superseded handle"),
        "unexpected error: {err}"
    );
}

#[test]
fn an_unknown_opencode_auth_shape_is_refused() {
    let root = tmp_root("unknown-shape");
    let auth = root.join("auth.json");
    std::fs::write(&auth, r#"{"deepseek":{"type":"mystery","token":"x"}}"#).expect("auth");
    std::fs::set_permissions(&auth, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("mode");

    let err = opencode_files::read_auth_entries(&auth).expect_err("unknown type refuses");
    assert!(
        err.to_string().contains("unknown auth shape"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_auth_entry_write_preserves_unrelated_entries_and_mode() {
    let root = tmp_root("atomic-auth");
    let auth = root.join("auth.json");
    let unrelated =
        json!({"type":"oauth","access":"other-access","refresh":"other-refresh","expires":7});
    std::fs::write(
        &auth,
        serde_json::to_vec(&json!({"other": unrelated, "deepseek": {"type":"api","key":"old"}}))
            .unwrap(),
    )
    .expect("auth");
    std::fs::set_permissions(&auth, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("mode");

    opencode_files::write_auth_entry(&auth, "deepseek", json!({"type":"api","key":"new"}))
        .expect("atomic write");
    let entries = opencode_files::read_auth_entries(&auth).expect("read auth");
    assert_eq!(entries.get("other"), Some(&unrelated));
    assert_eq!(entries["deepseek"], json!({"type":"api","key":"new"}));
    assert_eq!(mode(&auth), 0o600);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_handle_file_round_trip_preserves_order_and_0600() {
    let root = tmp_root("handle-order");
    let handles = root.join("nested").join("opencode-handles.json");
    let file = opencode_files::HandleFile {
        version: 1,
        providers: vec![
            opencode_files::HandleProvider {
                provider: "deepseek".into(),
                shape: opencode_files::HandleShape::Api,
                serve: "opencode-claustrum".into(),
                accounts: vec![
                    opencode_files::HandleAccount {
                        label: "first".into(),
                        handle: "ckh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                        credential_id: "apikey:deepseek:first".into(),
                        superseded: Vec::new(),
                    },
                    opencode_files::HandleAccount {
                        label: "second".into(),
                        handle: "ckh_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                        credential_id: "apikey:deepseek:second".into(),
                        superseded: Vec::new(),
                    },
                ],
            },
            opencode_files::HandleProvider {
                provider: "anthropic".into(),
                shape: opencode_files::HandleShape::Oauth,
                serve: "opencode-claustrum".into(),
                accounts: vec![opencode_files::HandleAccount {
                    label: "work".into(),
                    handle: "ckh_ccccccccccccccccccccccccccccccccccccccccccc".into(),
                    credential_id: "oauth:anthropic:work".into(),
                    superseded: Vec::new(),
                }],
            },
        ],
    };
    opencode_files::write_handle_file(&handles, &file).expect("write handles");
    assert_eq!(mode(handles.parent().unwrap()), 0o700);
    assert_eq!(mode(&handles), 0o600);
    assert_eq!(
        opencode_files::read_handle_file(&handles).expect("read handles"),
        file
    );

    std::fs::write(
        &handles,
        r#"{"version":1,"providers":[{"provider":"deepseek","shape":"api","accounts":[]}]}"#,
    )
    .expect("bad handles");
    std::fs::set_permissions(
        &handles,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("mode");
    let err = opencode_files::read_handle_file(&handles).expect_err("missing serve rejects");
    assert!(err.to_string().contains("serve"), "unexpected error: {err}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_online_get_uses_an_owned_capability_without_an_admin_read() {
    let root = tmp_root("online-get");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let conn = spawn_route_daemon(
        &root,
        observed.clone(),
        json!({
            "result": {"payload": [115, 101, 99, 114, 101, 116], "record_version": 12, "expires_at_ms": 99}
        }),
    );

    let served = credential_client::get_online(&conn, &root, "ckh_owned_capability")
        .expect("capability read succeeds");
    assert_eq!(served.payload, b"secret");
    assert_eq!(served.record_version, 12);
    assert_eq!(served.expires_at_ms, Some(99));
    let methods = observed.lock().expect("methods").clone();
    assert_eq!(methods, vec!["route.open", "credential.get"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_online_get_maps_needs_reauth_without_returning_material() {
    let root = tmp_root("needs-reauth");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let conn = spawn_route_daemon(
        &root,
        observed,
        json!({
            "result": {"error": {"class":"auth_required", "code":"needs_reauth"}}
        }),
    );

    let err = credential_client::get_online(&conn, &root, "ckh_owned_capability")
        .expect_err("needs reauth is typed");
    assert!(matches!(
        err,
        credential_client::CredentialReadError::NeedsReauth
    ));
    let text = format!("{err:?} {err}");
    assert!(
        !text.contains("ckh_owned_capability"),
        "handle leaked: {text}"
    );
    assert!(!text.contains("secret"), "payload leaked: {text}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_golden_handle_file_matches_the_rust_contract_byte_for_byte() {
    let bytes = include_str!("../../../packages/opencode/golden/handles.json");
    let file: opencode_files::HandleFile =
        serde_json::from_str(bytes).expect("golden handles json");
    let rendered = serde_json::to_string_pretty(&file).expect("render golden handles");
    assert_eq!(rendered, bytes.trim_end());
}

fn spawn_route_daemon(root: &Path, observed: Arc<Mutex<Vec<String>>>, response: Value) -> PathBuf {
    use subc_protocol::{Flags, Frame, FrameType, Priority};
    use subc_transport::{
        authenticate_server, connection_file, read_frame, write_frame, ConnectionInfo, Endpoint,
    };

    let listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let key = vec![9; 32];
    let daemon_id = [4; 16];
    let conn = root.join("subc-connection.json");
    connection_file::write_atomic(
        &conn,
        &ConnectionInfo {
            schema: connection_file::SCHEMA_VERSION,
            wire_version: None,
            endpoints: vec![Endpoint {
                host: "127.0.0.1".into(),
                port,
            }],
            key: key.clone(),
            daemon_id,
            pid: std::process::id(),
            daemon_ver: "test".into(),
        },
    )
    .expect("connection file");

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let (mut stream, _) = listener.accept().await.expect("accept");
            authenticate_server(
                &mut stream,
                &key,
                &daemon_id,
                "test",
                std::time::Duration::from_secs(3),
            )
            .await
            .expect("handshake");

            let open = read_frame(&mut stream)
                .await
                .expect("read route open")
                .expect("route frame");
            let open_body: Value = serde_json::from_slice(&open.body).expect("route open json");
            observed
                .lock()
                .expect("methods")
                .push(open_body["op"].as_str().unwrap_or_default().to_string());
            let route = Frame::build(
                FrameType::Response,
                Flags::new(false, Priority::Passive, false),
                0,
                0,
                open.header.corr,
                serde_json::to_vec(&json!({"route_channel": 7, "route_epoch": 3})).unwrap(),
            )
            .unwrap();
            write_frame(&mut stream, &route)
                .await
                .expect("write route open");

            let get = read_frame(&mut stream)
                .await
                .expect("read credential get")
                .expect("get frame");
            let get_body: Value = serde_json::from_slice(&get.body).expect("credential get json");
            observed
                .lock()
                .expect("methods")
                .push(get_body["method"].as_str().unwrap_or_default().to_string());
            assert_eq!(get_body["method"], "credential.get");
            assert_eq!(get_body["params"]["handle"], "ckh_owned_capability");
            assert_eq!(get_body["params"]["force_refresh"], false);
            assert_eq!(get_body["params"]["min_ttl_ms"], 0);
            let reply = Frame::build(
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                7,
                3,
                get.header.corr,
                serde_json::to_vec(&response).unwrap(),
            )
            .unwrap();
            write_frame(&mut stream, &reply)
                .await
                .expect("write get response");
        });
    });
    conn
}

struct MigrationRig {
    root: PathBuf,
    vault: PathBuf,
    key: PathBuf,
    auth: PathBuf,
    handles: PathBuf,
}

impl MigrationRig {
    fn new(tag: &str, entries: Value) -> Self {
        let root = tmp_root(tag);
        let vault = root.join("vault");
        let key = root.join("master.key");
        let auth = root.join("auth.json");
        let handles = root.join("handles.json");
        std::fs::create_dir_all(&vault).expect("vault directory");
        std::fs::write(&auth, serde_json::to_vec(&entries).expect("auth json")).expect("auth file");
        std::fs::set_permissions(&auth, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("auth mode");
        let rig = Self {
            root,
            vault,
            key,
            auth,
            handles,
        };
        let boot = rig.run(&["bootstrap"]);
        assert!(
            boot.status.success(),
            "bootstrap failed: {}",
            String::from_utf8_lossy(&boot.stderr)
        );
        rig
    }

    fn run(&self, args: &[&str]) -> Output {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&self.vault)
            .arg("--key-path")
            .arg(&self.key)
            .output()
            .expect("run ck-auth")
    }

    fn run_with_stdin(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = cli()
            .args(args)
            .arg("--data-dir")
            .arg(&self.vault)
            .arg("--key-path")
            .arg(&self.key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ck-auth");
        child
            .stdin
            .take()
            .expect("stdin pipe")
            .write_all(input)
            .expect("write stdin");
        child.wait_with_output().expect("wait ck-auth")
    }

    fn run_with_env(&self, args: &[&str], key: &str, value: &str) -> Output {
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&self.vault)
            .arg("--key-path")
            .arg(&self.key)
            .env(key, value)
            .output()
            .expect("run ck-auth with test seam")
    }

    fn migrate(&self, extra: &[&str]) -> Output {
        let mut args = vec![
            "migrate-opencode",
            "--auth-file",
            self.auth.to_str().unwrap(),
            "--handle-file",
            self.handles.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    fn migrate_with_env(&self, extra: &[&str], key: &str, value: &str) -> Output {
        let mut args = vec![
            "migrate-opencode",
            "--auth-file",
            self.auth.to_str().unwrap(),
            "--handle-file",
            self.handles.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        cli()
            .args(args)
            .arg("--data-dir")
            .arg(&self.vault)
            .arg("--key-path")
            .arg(&self.key)
            .env(key, value)
            .output()
            .expect("run ck-auth with test seam")
    }

    fn set_auth(&self, entries: Value) {
        std::fs::write(&self.auth, serde_json::to_vec(&entries).expect("auth json"))
            .expect("rewrite auth");
        std::fs::set_permissions(
            &self.auth,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("auth mode");
    }
}

impl Drop for MigrationRig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn open_vault(rig: &MigrationRig) -> EncryptedStore {
    let config = credentials_core::resolver::ResolverConfig {
        data_dir: rig.vault.clone(),
        source: credentials_core::resolver::KeySource::OperatorPath {
            path: rig.key.clone(),
        },
    };
    let key = credentials_core::resolver::resolve(&config, None).expect("resolve test key");
    let sqlite = open_sqlite(&StorageDescriptor {
        module_id: credentials_core::contract::MODULE_ID.into(),
        storage_namespace: credentials_core::contract::STORAGE_NAMESPACE.into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: rig.vault.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .expect("open scratch vault");
    EncryptedStore::migrate(&sqlite).expect("migrate scratch vault");
    EncryptedStore::open(sqlite, key).expect("open scratch vault")
}

fn route_response(payload: &[u8]) -> Value {
    json!({"result": {"payload": payload, "record_version": 1, "expires_at_ms": null}})
}

fn spawn_migration_route_daemon(
    root: &Path,
    observed: Arc<Mutex<Vec<String>>>,
    responses: Arc<Mutex<Vec<Value>>>,
) -> PathBuf {
    use subc_protocol::{Flags, Frame, FrameType, Priority};
    use subc_transport::{
        authenticate_server, connection_file, read_frame, write_frame, ConnectionInfo, Endpoint,
    };

    let listener =
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let key = vec![8; 32];
    let daemon_id = [5; 16];
    let conn = root.join("migration-subc.json");
    connection_file::write_atomic(
        &conn,
        &ConnectionInfo {
            schema: connection_file::SCHEMA_VERSION,
            wire_version: None,
            endpoints: vec![Endpoint {
                host: "127.0.0.1".into(),
                port,
            }],
            key: key.clone(),
            daemon_id,
            pid: std::process::id(),
            daemon_ver: "test".into(),
        },
    )
    .expect("connection file");
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept");
                authenticate_server(
                    &mut stream,
                    &key,
                    &daemon_id,
                    "test",
                    std::time::Duration::from_secs(3),
                )
                .await
                .expect("handshake");
                let first = read_frame(&mut stream)
                    .await
                    .expect("read first")
                    .expect("first frame");
                let first_body: Value = serde_json::from_slice(&first.body).expect("first json");
                if first_body["op"] == "catalog.list" {
                    observed
                        .lock()
                        .expect("observed")
                        .push("catalog.list".into());
                    let reply = Frame::build(
                        FrameType::Response,
                        Flags::new(false, Priority::Passive, false),
                        0,
                        0,
                        first.header.corr,
                        serde_json::to_vec(&json!({"modules": []})).unwrap(),
                    )
                    .unwrap();
                    write_frame(&mut stream, &reply)
                        .await
                        .expect("catalog response");
                    continue;
                }
                observed
                    .lock()
                    .expect("observed")
                    .push(first_body["op"].as_str().unwrap_or_default().into());
                let opened = Frame::build(
                    FrameType::Response,
                    Flags::new(false, Priority::Passive, false),
                    0,
                    0,
                    first.header.corr,
                    serde_json::to_vec(&json!({"route_channel": 7, "route_epoch": 3})).unwrap(),
                )
                .unwrap();
                write_frame(&mut stream, &opened)
                    .await
                    .expect("route response");
                let get = read_frame(&mut stream)
                    .await
                    .expect("read get")
                    .expect("get frame");
                let get_body: Value = serde_json::from_slice(&get.body).expect("get json");
                observed
                    .lock()
                    .expect("observed")
                    .push(get_body["method"].as_str().unwrap_or_default().into());
                let response = responses.lock().expect("responses").remove(0);
                let reply = Frame::build(
                    FrameType::Response,
                    Flags::new(false, Priority::Interactive, false),
                    7,
                    3,
                    get.header.corr,
                    serde_json::to_vec(&response).unwrap(),
                )
                .unwrap();
                write_frame(&mut stream, &reply)
                    .await
                    .expect("get response");
            }
        });
    });
    conn
}

#[test]
fn the_migrate_opencode_dry_run_writes_nothing_and_prints_a_non_secret_plan() {
    let rig = MigrationRig::new(
        "migration-dry",
        json!({"deepseek": {"type": "api", "key": "dry-secret"}}),
    );
    let before = std::fs::read(&rig.auth).expect("auth before");
    let out = rig.migrate(&["--dry-run"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(stdout.contains("dry_run compare=absent"));
    assert!(!rig.handles.exists());
    assert_eq!(std::fs::read(&rig.auth).expect("auth after"), before);
    assert!(!stdout.contains("dry-secret") && !stderr.contains("dry-secret"));
}

#[test]
fn the_provider_shape_table_parses_the_eight_refused_ids_and_excludes_copilot() {
    let table: Value = serde_json::from_str(include_str!(
        "../src/bin/cli_support/opencode-provider-shapes.json"
    ))
    .expect("provider shape table parses");
    let definitions = table["shape_definitions"]
        .as_object()
        .expect("shape definitions object");
    let mut providers = Vec::new();
    for shape in definitions.values() {
        assert!(shape["why"].as_str().is_some_and(|why| !why.is_empty()));
        assert!(shape["if_forced"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
    for (provider, shape) in table["providers"].as_object().expect("providers object") {
        assert!(shape["shapes"]
            .as_array()
            .is_some_and(|shapes| !shapes.is_empty()));
        assert!(shape["sites"].as_array().is_some_and(|sites| sites
            .iter()
            .all(|site| site.as_str().is_some_and(|site| site.contains(':')))));
        providers.push(provider.as_str());
    }
    providers.sort_unstable();
    assert_eq!(providers.len(), 8);
    assert!(providers.contains(&"amazon-bedrock"));
    assert!(providers.contains(&"azure"));
    assert!(!providers.contains(&"github-copilot"));
    assert!(table["examined_servable"].get("github-copilot").is_some());
    assert_eq!(
        table["maintainer_note"].as_array().expect("maintainer notes"),
        &vec![
            Value::String("attribute each hit by walking the custom() map keys backwards, not by eyeballing (first pass put two gitlab sites under sap-ai-core; PRIVATE-TOKEN header was the only tell)".into()),
            Value::String("cross-reference the oauth-gate list — it is what keeps false entries like copilot out; a delta without both checks stated is refusable".into()),
        ]
    );
}

#[test]
fn the_migrate_opencode_refuses_an_api_env_provider_with_its_source_citation() {
    let rig = MigrationRig::new(
        "migration-shape-refusal",
        json!({"amazon-bedrock": {"type": "api", "key": "bedrock-secret"}}),
    );
    let out = rig.migrate(&["--dry-run"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("provider=amazon-bedrock refused shape=api-env"));
    assert!(stdout.contains("provider.ts:324"));
    assert!(stdout.contains("--force-shape"));
}

#[test]
fn the_migrate_opencode_force_shape_overrides_a_provider_shape_refusal() {
    let rig = MigrationRig::new(
        "migration-shape-force",
        json!({"amazon-bedrock": {"type": "api", "key": "bedrock-secret"}}),
    );
    let out = rig.migrate(&["--dry-run", "--force-shape"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("provider=amazon-bedrock credential_id=apikey:amazon-bedrock:main dry_run")
    );
    assert!(stdout.contains("the sentinel lands in process.env (e.g. AWS_BEARER_TOKEN_BEDROCK)"));
    assert!(stdout.contains("availability-only, sentinel non-secret"));
}

#[test]
fn the_migrate_opencode_migrates_safe_providers_while_refusing_unsafe_shapes() {
    let rig = MigrationRig::new(
        "migration-shape-mixed",
        json!({
            "deepseek": {"type": "api", "key": "deepseek-secret"},
            "amazon-bedrock": {"type": "api", "key": "bedrock-secret"}
        }),
    );
    let out = rig.migrate(&[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("provider=deepseek credential_id=apikey:deepseek:main"));
    assert!(stdout.contains("provider=amazon-bedrock refused shape=api-env"));
    let auth: Value =
        serde_json::from_slice(&std::fs::read(&rig.auth).expect("auth")).expect("auth json");
    assert_eq!(auth["deepseek"]["key"], "claustrum-tombstone:v1:deepseek");
    assert_eq!(auth["amazon-bedrock"]["key"], "bedrock-secret");
}

#[test]
fn opencode_account_add_refuses_a_provider_forced_across_the_fetch_seam() {
    let rig = MigrationRig::new(
        "account-add-shape-refusal",
        json!({"amazon-bedrock": {"type": "api", "key": "bedrock-secret"}}),
    );
    assert!(rig.migrate(&["--force-shape"]).status.success());
    let key_file = rig.root.join("alt.key");
    std::fs::write(&key_file, b"alt-secret").expect("key file");
    let out = rig.run(&[
        "opencode-account",
        "add",
        "--provider",
        "amazon-bedrock",
        "--label",
        "alt",
        "--key-file",
        key_file.to_str().expect("key path"),
        "--handle-file",
        rig.handles.to_str().expect("handle path"),
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("shape=api-env"));
    assert!(stderr.contains("provider.ts:324"));
}

#[test]
fn usable_warns_when_an_existing_tombstone_has_an_unsafe_provider_shape() {
    let rig = MigrationRig::new("usable-shape-warning", json!({}));
    let data_home = rig.root.join("data");
    let auth = data_home.join("opencode").join("auth.json");
    std::fs::create_dir_all(auth.parent().expect("auth parent")).expect("auth parent");
    std::fs::write(
        &auth,
        serde_json::to_vec(&json!({
            "amazon-bedrock": {"type": "api", "key": "claustrum-tombstone:v1:amazon-bedrock"}
        }))
        .expect("auth json"),
    )
    .expect("auth file");
    std::fs::set_permissions(&auth, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("auth mode");
    let out = cli()
        .arg("usable")
        .arg("--data-dir")
        .arg(&rig.vault)
        .arg("--key-path")
        .arg(&rig.key)
        .env("XDG_DATA_HOME", &data_home)
        .output()
        .expect("run usable");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("WARN: OpenCode tombstone provider=amazon-bedrock shape=api-env"));
    assert!(stdout.contains("migrate-opencode --restore amazon-bedrock"));
}

#[test]
fn the_migrate_opencode_first_run_stores_writes_a_handle_and_then_tombstones() {
    let rig = MigrationRig::new(
        "migration-first",
        json!({"deepseek": {"type": "api", "key": "first-secret"}}),
    );
    let out = rig.migrate(&[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let auth: Value =
        serde_json::from_slice(&std::fs::read(&rig.auth).expect("auth")).expect("auth json");
    assert_eq!(
        auth["deepseek"],
        json!({"type":"api", "key":"claustrum-tombstone:v1:deepseek"})
    );
    let handles = opencode_files::read_handle_file(&rig.handles).expect("handles");
    assert_eq!(
        handles.providers[0].accounts[0].credential_id,
        "apikey:deepseek:main"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("first-secret"));
}

#[test]
fn the_migrate_opencode_rerun_with_identical_material_is_a_no_op() {
    let rig = MigrationRig::new(
        "migration-identical",
        json!({"deepseek": {"type": "api", "key": "same-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    rig.set_auth(json!({"deepseek": {"type": "api", "key": "same-secret"}}));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let conn = spawn_migration_route_daemon(
        &rig.root,
        observed,
        Arc::new(Mutex::new(vec![route_response(b"same-secret")])),
    );
    let out = rig.migrate(&["--subc", conn.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("identical"));
}

#[test]
fn the_migrate_opencode_different_material_refuses_without_replace() {
    let rig = MigrationRig::new(
        "migration-different",
        json!({"deepseek": {"type": "api", "key": "old-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    rig.set_auth(json!({"deepseek": {"type": "api", "key": "new-secret"}}));
    let conn = spawn_migration_route_daemon(
        &rig.root,
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(vec![route_response(b"old-secret")])),
    );
    let out = rig.migrate(&["--subc", conn.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("differs; rerun with --replace"));
}

#[test]
fn the_migrate_opencode_replace_rotates_the_handle_after_rereading_the_auth_entry() {
    let rig = MigrationRig::new(
        "migration-replace",
        json!({"deepseek": {"type": "api", "key": "old-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let old = opencode_files::read_handle_file(&rig.handles)
        .unwrap()
        .providers[0]
        .accounts[0]
        .handle
        .clone();
    rig.set_auth(json!({"deepseek": {"type": "api", "key": "new-secret"}}));
    let conn = spawn_migration_route_daemon(
        &rig.root,
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(vec![route_response(b"old-secret")])),
    );
    let out = rig.migrate(&["--replace", "--subc", conn.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let new = opencode_files::read_handle_file(&rig.handles)
        .unwrap()
        .providers[0]
        .accounts[0]
        .handle
        .clone();
    assert_ne!(old, new);
}

#[test]
fn the_migrate_opencode_remints_and_compares_a_lost_handle() {
    let rig = MigrationRig::new(
        "migration-lost",
        json!({"deepseek": {"type": "api", "key": "lost-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    rig.set_auth(json!({"deepseek": {"type": "api", "key": "lost-secret"}}));
    let mut handles = opencode_files::read_handle_file(&rig.handles).unwrap();
    let lost_handle = format!("ckh_{}", "l".repeat(43));
    handles.providers[0].accounts[0].handle = lost_handle.clone();
    opencode_files::write_handle_file(&rig.handles, &handles).unwrap();
    let conn = spawn_migration_route_daemon(
        &rig.root,
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(vec![
            json!({"result":{"error":{"code":"not_found"}}}),
            route_response(b"lost-secret"),
        ])),
    );
    let out = rig.migrate(&["--subc", conn.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(
        opencode_files::read_handle_file(&rig.handles)
            .unwrap()
            .providers[0]
            .accounts[0]
            .handle,
        lost_handle
    );
}

#[test]
fn the_migrate_opencode_handle_write_failure_leaves_the_real_auth_entry_untouched() {
    let rig = MigrationRig::new(
        "migration-write-failure",
        json!({"deepseek": {"type": "api", "key": "write-secret"}}),
    );
    let out = rig.run(&[
        "migrate-opencode",
        "--auth-file",
        rig.auth.to_str().unwrap(),
        "--handle-file",
        "/dev/null/handles.json",
    ]);
    assert!(!out.status.success());
    let auth: Value = serde_json::from_slice(&std::fs::read(&rig.auth).unwrap()).unwrap();
    assert_eq!(auth["deepseek"]["key"], "write-secret");
}

#[cfg(feature = "opencode-test-seam")]
#[test]
fn the_migrate_opencode_tombstone_reread_failure_keeps_the_old_handle_until_rerun() {
    let rig = MigrationRig::new(
        "migration-tombstone-seam",
        json!({"deepseek": {"type": "api", "key": "old-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let h1 = opencode_files::read_handle_file(&rig.handles)
        .expect("first handles")
        .providers[0]
        .accounts[0]
        .handle
        .clone();
    rig.set_auth(json!({"deepseek": {"type": "api", "key": "new-secret"}}));
    let conn = spawn_migration_route_daemon(
        &rig.root,
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(vec![route_response(b"old-secret")])),
    );
    let out = rig.migrate_with_env(
        &["--replace", "--subc", conn.to_str().unwrap()],
        "CK_OPENCODE_TEST_FAIL_TOMBSTONE_REREAD",
        "1",
    );
    assert!(
        !out.status.success(),
        "the seam must stop after writing the tombstone"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("re-run converges"));

    let auth: Value =
        serde_json::from_slice(&std::fs::read(&rig.auth).expect("auth")).expect("auth json");
    assert_eq!(
        auth["deepseek"],
        json!({"type":"api", "key":"claustrum-tombstone:v1:deepseek"})
    );
    let handles: Value = serde_json::from_slice(&std::fs::read(&rig.handles).expect("handles"))
        .expect("handles json");
    let account = &handles["providers"][0]["accounts"][0];
    let h2 = account["handle"].as_str().expect("new handle").to_string();
    assert_ne!(h1, h2);
    assert_eq!(account["superseded"], json!([h1]));
    let store = open_vault(&rig);
    assert_eq!(
        store.resolve_handle(&h1).expect("H1 remains live"),
        "apikey:deepseek:main"
    );
    assert_eq!(
        store.resolve_handle(&h2).expect("H2 is live"),
        "apikey:deepseek:main"
    );
    drop(store);
    let audit = String::from_utf8_lossy(&rig.run(&["audit"]).stdout).to_string();
    assert!(audit.contains("mint_handle"));
    assert!(!audit.contains("revoke_handle"));

    let rerun = rig.migrate(&[]);
    assert!(
        rerun.status.success(),
        "{}",
        String::from_utf8_lossy(&rerun.stderr)
    );
    let handles: Value =
        serde_json::from_slice(&std::fs::read(&rig.handles).expect("handles after rerun"))
            .expect("handles json");
    assert_eq!(handles["providers"][0]["accounts"][0]["handle"], h2);
    assert!(handles["providers"][0]["accounts"][0]
        .get("superseded")
        .is_none());
    let store = open_vault(&rig);
    assert!(
        store.resolve_handle(&h1).is_err(),
        "H1 is revoked on convergence"
    );
    assert_eq!(
        store.resolve_handle(&h2).expect("H2 remains live"),
        "apikey:deepseek:main"
    );
    let audit = String::from_utf8_lossy(&rig.run(&["audit"]).stdout).to_string();
    assert!(audit.contains("revoke_handle"));
}

#[test]
fn the_migrate_opencode_restore_writes_the_real_entry_then_drops_its_handle() {
    let rig = MigrationRig::new(
        "migration-restore",
        json!({"deepseek": {"type": "api", "key": "restore-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let conn = spawn_migration_route_daemon(
        &rig.root,
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(vec![route_response(b"restore-secret")])),
    );
    let out = rig.migrate(&["--restore", "deepseek", "--subc", conn.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let auth: Value = serde_json::from_slice(&std::fs::read(&rig.auth).unwrap()).unwrap();
    assert_eq!(auth["deepseek"]["key"], "restore-secret");
    assert!(opencode_files::read_handle_file(&rig.handles)
        .unwrap()
        .providers
        .is_empty());
}

#[test]
fn the_migrate_opencode_restore_refuses_a_record_that_needs_reauthentication() {
    let rig = MigrationRig::new(
        "migration-reauth",
        json!({"deepseek": {"type": "api", "key": "reauth-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let conn = spawn_migration_route_daemon(
        &rig.root,
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(vec![
            json!({"result":{"error":{"class":"auth_required","code":"needs_reauth"}}}),
        ])),
    );
    let out = rig.migrate(&["--restore", "deepseek", "--subc", conn.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains(
        "refusing restore for apikey:deepseek:main: vault record needs re-authentication"
    ));
}

#[test]
fn the_migrate_opencode_preserves_repeated_provider_filters_and_skips_oauth_by_default() {
    let rig = MigrationRig::new(
        "migration-filter",
        json!({"deepseek": {"type": "api", "key": "one"}, "groq": {"type": "api", "key": "two"}, "anthropic": {"type":"oauth","access":"a","refresh":"r","expires":0}}),
    );
    let out = rig.migrate(&["--provider", "groq", "--provider", "deepseek"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.find("provider=groq").unwrap() < stdout.find("provider=deepseek").unwrap());
    let auth: Value = serde_json::from_slice(&std::fs::read(&rig.auth).unwrap()).unwrap();
    assert_eq!(auth["anthropic"]["type"], "oauth");
}

#[test]
fn the_migrate_opencode_leaves_a_legacy_two_segment_record_untouched() {
    let rig = MigrationRig::new(
        "migration-legacy",
        json!({"deepseek": {"type": "api", "key": "legacy-secret"}}),
    );
    assert!(rig
        .run(&[
            "put",
            "--id",
            "apikey:deepseek",
            "--payload",
            "legacy-secret"
        ])
        .status
        .success());
    assert!(rig.migrate(&[]).status.success());
    let listed = rig.run(&["list"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("apikey:deepseek"));
    assert!(String::from_utf8_lossy(&listed.stdout).contains("apikey:deepseek:main"));
}

#[test]
fn the_opencode_account_add_imports_mints_and_appends_the_account() {
    let rig = MigrationRig::new(
        "account-add",
        json!({"deepseek": {"type": "api", "key": "main-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let key_file = rig.root.join("alt.key");
    std::fs::write(&key_file, b"alt-secret").expect("key file");

    let out = rig.run(&[
        "opencode-account",
        "add",
        "--provider",
        "deepseek",
        "--label",
        "alt",
        "--key-file",
        key_file.to_str().unwrap(),
        "--handle-file",
        rig.handles.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let handles = opencode_files::read_handle_file(&rig.handles).expect("handles");
    assert_eq!(
        handles.providers[0]
            .accounts
            .iter()
            .map(|account| account.label.as_str())
            .collect::<Vec<_>>(),
        ["main", "alt"]
    );
    let store = open_vault(&rig);
    assert_eq!(
        store
            .get("apikey:deepseek:alt")
            .expect("alt record")
            .payload,
        b"alt-secret"
    );
}

#[test]
fn the_opencode_account_add_before_preserves_the_requested_order() {
    let rig = MigrationRig::new(
        "account-before",
        json!({"deepseek": {"type": "api", "key": "main-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let key_file = rig.root.join("priority.key");
    std::fs::write(&key_file, b"priority-secret").expect("key file");

    let out = rig.run(&[
        "opencode-account",
        "add",
        "--provider",
        "deepseek",
        "--label",
        "priority",
        "--key-file",
        key_file.to_str().unwrap(),
        "--before",
        "main",
        "--handle-file",
        rig.handles.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let handles = opencode_files::read_handle_file(&rig.handles).expect("handles");
    assert_eq!(
        handles.providers[0]
            .accounts
            .iter()
            .map(|account| account.label.as_str())
            .collect::<Vec<_>>(),
        ["priority", "main"]
    );
}

#[test]
fn the_opencode_account_add_key_file_stdin_does_not_echo_material() {
    let rig = MigrationRig::new(
        "account-stdin",
        json!({"deepseek": {"type": "api", "key": "main-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let material = b"stdin-secret\n";
    let out = rig.run_with_stdin(
        &[
            "opencode-account",
            "add",
            "--provider",
            "deepseek",
            "--label",
            "stdin",
            "--key-file",
            "-",
            "--handle-file",
            rig.handles.to_str().unwrap(),
        ],
        material,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(!stdout.contains("stdin-secret") && !stderr.contains("stdin-secret"));
    assert_eq!(
        open_vault(&rig)
            .get("apikey:deepseek:stdin")
            .expect("stdin record")
            .payload,
        b"stdin-secret"
    );
}

#[cfg(feature = "opencode-test-seam")]
#[test]
fn the_opencode_account_add_recovers_a_mint_before_handle_write_with_one_live_handle() {
    let rig = MigrationRig::new(
        "account-add-handle-write-crash",
        json!({"deepseek": {"type": "api", "key": "main-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let key_file = rig.root.join("alt.key");
    std::fs::write(&key_file, b"alt-secret").expect("key file");
    let args = [
        "opencode-account",
        "add",
        "--provider",
        "deepseek",
        "--label",
        "alt",
        "--key-file",
        key_file.to_str().unwrap(),
        "--handle-file",
        rig.handles.to_str().unwrap(),
    ];
    let interrupted = rig.run_with_env(&args, "CK_OPENCODE_TEST_FAIL_HANDLE_WRITE", "1");
    assert!(
        !interrupted.status.success(),
        "the seam must stop before the handle file write"
    );

    let observed = Arc::new(Mutex::new(Vec::new()));
    let connection = spawn_migration_route_daemon(
        &rig.root,
        observed,
        Arc::new(Mutex::new(vec![route_response(b"alt-secret")])),
    );
    let mut rerun_args = args.to_vec();
    rerun_args.extend(["--subc", connection.to_str().unwrap()]);
    let recovered = rig.run(&rerun_args);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let handles = opencode_files::read_handle_file(&rig.handles).expect("recovered handles");
    assert_eq!(
        handles.providers[0]
            .accounts
            .iter()
            .filter(|account| account.label == "alt")
            .count(),
        1
    );
    let audit = String::from_utf8_lossy(&rig.run(&["audit"]).stdout).to_ascii_lowercase();
    assert!(
        audit.contains("revoke_handle"),
        "recovery must revoke the stranded capability: {audit}"
    );
}

#[test]
fn the_opencode_account_remove_revokes_the_handle_but_keeps_the_vault_record() {
    let rig = MigrationRig::new(
        "account-remove",
        json!({"deepseek": {"type": "api", "key": "main-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let key_file = rig.root.join("alt.key");
    std::fs::write(&key_file, b"alt-secret").expect("key file");
    assert!(rig
        .run(&[
            "opencode-account",
            "add",
            "--provider",
            "deepseek",
            "--label",
            "alt",
            "--key-file",
            key_file.to_str().unwrap(),
            "--handle-file",
            rig.handles.to_str().unwrap(),
        ])
        .status
        .success());
    let handles = opencode_files::read_handle_file(&rig.handles).expect("handles");
    let alt_handle = handles.providers[0].accounts[1].handle.clone();

    let out = rig.run(&[
        "opencode-account",
        "remove",
        "--provider",
        "deepseek",
        "--label",
        "alt",
        "--handle-file",
        rig.handles.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let handles = opencode_files::read_handle_file(&rig.handles).expect("handles");
    assert_eq!(handles.providers[0].accounts.len(), 1);
    let store = open_vault(&rig);
    assert!(store.resolve_handle(&alt_handle).is_err());
    assert_eq!(
        store
            .get("apikey:deepseek:alt")
            .expect("record remains")
            .payload,
        b"alt-secret"
    );
}

#[test]
fn the_opencode_account_list_shows_non_secret_state_without_credential_get() {
    let rig = MigrationRig::new(
        "account-list",
        json!({"deepseek": {"type": "api", "key": "main-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let observed = Arc::new(Mutex::new(Vec::new()));
    let conn = spawn_migration_route_daemon(
        &rig.root,
        observed.clone(),
        Arc::new(Mutex::new(Vec::new())),
    );
    let out = rig.run(&[
        "opencode-account",
        "list",
        "--provider",
        "deepseek",
        "--handle-file",
        rig.handles.to_str().unwrap(),
        "--subc",
        conn.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("main") && stdout.contains("active") && stdout.contains("v1"));
    assert!(!stdout.contains("main-secret"));
    assert!(!observed
        .lock()
        .expect("observed")
        .iter()
        .any(|method| method == "credential.get"));
}

#[test]
fn the_opencode_account_rejects_duplicate_or_invalid_labels_without_any_write() {
    let rig = MigrationRig::new(
        "account-invalid",
        json!({"deepseek": {"type": "api", "key": "main-secret"}}),
    );
    assert!(rig.migrate(&[]).status.success());
    let auth_before = std::fs::read(&rig.auth).expect("auth before");
    let handles_before = std::fs::read(&rig.handles).expect("handles before");
    let audit_before = rig.run(&["audit"]).stdout;
    let key_file = rig.root.join("invalid.key");
    std::fs::write(&key_file, b"should-not-store").expect("key file");

    for (label, refusal) in [
        ("main", "account label 'main' already exists"),
        ("bad:label", "must not contain ':'"),
    ] {
        let out = rig.run(&[
            "opencode-account",
            "add",
            "--provider",
            "deepseek",
            "--label",
            label,
            "--key-file",
            key_file.to_str().unwrap(),
            "--handle-file",
            rig.handles.to_str().unwrap(),
        ]);
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(refusal),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read(&rig.auth).expect("auth after"), auth_before);
        assert_eq!(
            std::fs::read(&rig.handles).expect("handles after"),
            handles_before
        );
    }
    assert_eq!(rig.run(&["audit"]).stdout, audit_before);
    assert!(String::from_utf8_lossy(&rig.run(&["list"]).stdout).contains("apikey:deepseek:main"));
}
