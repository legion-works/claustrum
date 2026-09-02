#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[path = "../src/bin/cli_support/credential_client.rs"]
mod credential_client;
#[path = "../src/bin/cli_support/opencode_files.rs"]
mod opencode_files;
#[path = "../src/bin/cli_support/route_client.rs"]
mod route_client;

use serde_json::{json, Value};

fn tmp_root(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ck-opencode-{tag}-{}-{}-{nanos}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).expect("fresh test root");
    root
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn opencode_files_golden_tombstone_matches_rust_contract() {
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
fn opencode_files_reject_auth_mode_other_than_0600() {
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
fn opencode_files_reject_unknown_auth_shape() {
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
fn opencode_files_atomic_write_preserves_unrelated_entries_and_mode() {
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
fn opencode_files_handle_round_trip_preserves_order_and_0600() {
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
                        handle: "ckh_first".into(),
                        credential_id: "apikey:deepseek:first".into(),
                    },
                    opencode_files::HandleAccount {
                        label: "second".into(),
                        handle: "ckh_second".into(),
                        credential_id: "apikey:deepseek:second".into(),
                    },
                ],
            },
            opencode_files::HandleProvider {
                provider: "anthropic".into(),
                shape: opencode_files::HandleShape::Oauth,
                serve: "opencode-claustrum".into(),
                accounts: vec![opencode_files::HandleAccount {
                    label: "work".into(),
                    handle: "ckh_work".into(),
                    credential_id: "oauth:anthropic:work".into(),
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
fn opencode_files_online_get_uses_owned_capability_without_admin_read() {
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
fn opencode_files_get_maps_needs_reauth_without_returning_material() {
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
