#![allow(dead_code)]
//! Shared consumer-side wire driver for the credentials-module e2e tests.
//!
//! Drives the consumer path against the vault daemon: authenticate as a client,
//! `catalog.list`, `route.open` the ManagementSurface, then the read-surface ops
//! (`credential.get` / `status` / ...) on the route channel. Mirrors the proven
//! ai-provider-quota consumer driver; only the module id and ops differ.

use std::{
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use serde_json::Value;
use subc_core::{read_frame, write_frame, Frame};
use subc_protocol::{BindIdentity, Flags, FrameType, Priority, RouteTarget};
use subc_transport::{authenticate_client, connection_file};
use tokio::{
    net::TcpStream,
    time::{timeout, Instant},
};

pub const MODULE_ID: &str = "claustrum";
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
pub const READ_TIMEOUT: Duration = Duration::from_secs(15);

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
/// - a nanosecond component, making concurrent path collisions vanishingly unlikely;
/// - `create_dir` rather than `create_dir_all`, so a collision REFUSES instead of
///   reusing. If this ever fires, the hypothesis above is confirmed by name rather
///   than re-derived from a symptom three layers downstream. If the antigravity flake
///   recurs WITHOUT this firing, the hypothesis is wrong and the next investigation
///   starts somewhere genuinely different.
pub fn tmp_root(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!(
        "ck-cred-cli-{}-{}-{}-{nanos:09}",
        process::id(),
        tag,
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
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

/// A temp path unique across PROCESSES, not merely within one.
///
/// The doc comment here used to promise "no collision across tests", which the
/// mechanism did not deliver: `pid + counter` is unique within one process and
/// collides between processes as soon as the OS recycles a PID. Windows does that from
/// a small pool, and the seam CI step runs several `cargo test` invocations in
/// sequence, so an inherited path hands a later test an earlier one's leftover vault --
/// a store sealed under one master key beside a key file holding another. A stronger
/// claim than the code supports is worse than none, because it stops the next reader
/// checking.
///
/// Callers here create the directory themselves, so this cannot refuse a collision the
/// way `tmp_root` does; the nanosecond component only makes one unlikely.
pub fn unique_temp_dir(label: &str) -> PathBuf {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{label}-{}-{n}-{nanos:09}", process::id()))
}

/// Connect to a daemon from its connection file and complete the client HMAC
/// handshake.
pub async fn connect_consumer(connection_file_path: &Path) -> TcpStream {
    let conn = connection_file::read(connection_file_path).unwrap();
    let endpoint = conn.endpoints.first().unwrap();
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .unwrap();
    authenticate_client(&mut stream, &conn, Duration::from_secs(2))
        .await
        .unwrap();
    stream
}

/// A live route binding: wire v2 route identity is `(channel, epoch)` and every
/// route-scoped frame must carry both (the daemon's relay drops mismatches).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub channel: u16,
    pub epoch: u32,
}

/// Send a channel-0 control request and read until its channel-0 reply for `corr`.
pub async fn control_rpc(stream: &mut TcpStream, corr: u64, body: Value) -> Frame {
    // Channel-0 control frames carry the reserved epoch 0 (wire v2 §3.1).
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    read_until_channel0(stream, corr).await
}

async fn read_until_channel0(stream: &mut TcpStream, corr: u64) -> Frame {
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.channel == 0
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
            && frame.header.corr == corr
        {
            return frame;
        }
    }
}

pub async fn read_frame_timeout(stream: &mut TcpStream) -> Frame {
    timeout(READ_TIMEOUT, async {
        read_frame(stream)
            .await
            .unwrap()
            .expect("connection should stay open")
    })
    .await
    .expect("timed out waiting for a frame")
}

/// `catalog.list` → the `modules` array.
pub async fn catalog_list(stream: &mut TcpStream, corr: u64) -> Vec<Value> {
    let frame = control_rpc(stream, corr, serde_json::json!({ "op": "catalog.list" })).await;
    assert_eq!(frame.header.ty, FrameType::Response);
    let value: Value = serde_json::from_slice(&frame.body).unwrap();
    value["modules"].as_array().cloned().unwrap_or_default()
}

/// Poll `catalog.list` until the vault module appears (the real daemon spawns the
/// module asynchronously, so registration is not immediate after connect).
pub async fn wait_for_catalog(stream: &mut TcpStream, module_id: &str, wait: Duration) {
    let deadline = Instant::now() + wait;
    let mut corr = 1000;
    loop {
        let modules = catalog_list(stream, corr).await;
        if modules.iter().any(|m| m["module_id"] == module_id) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "module {module_id} did not appear in catalog within {wait:?}"
        );
        corr += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn json_route_open(project_root: &Path) -> Value {
    let target = RouteTarget::ManagementSurface {
        module_id: MODULE_ID.to_string(),
    };
    let identity = BindIdentity {
        project_root: project_root.to_path_buf(),
        harness: "credentials-e2e".to_string(),
        session: "session-1".to_string(),
    };
    serde_json::json!({
        "op": "route.open",
        "target": target,
        "identity": identity,
    })
}

/// `route.open` the management surface; returns the route binding.
pub async fn route_open(stream: &mut TcpStream, project_root: &Path, corr: u64) -> Route {
    let frame = control_rpc(stream, corr, json_route_open(project_root)).await;
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "route.open should succeed: {}",
        String::from_utf8_lossy(&frame.body)
    );
    let value: Value = serde_json::from_slice(&frame.body).unwrap();
    Route {
        channel: value["route_channel"].as_u64().unwrap() as u16,
        epoch: value["route_epoch"].as_u64().unwrap() as u32,
    }
}

/// Send a raw data-plane request on the route channel; returns the decoded body of
/// the terminal Response (panics on Error).
pub async fn raw_route_request(
    stream: &mut TcpStream,
    route: Route,
    corr: u64,
    body: Value,
) -> Value {
    let frame = raw_route_frame(stream, route, corr, body).await;
    match frame.header.ty {
        FrameType::Response => serde_json::from_slice(&frame.body).unwrap(),
        FrameType::Error => panic!(
            "route request returned error: {}",
            String::from_utf8_lossy(&frame.body)
        ),
        ty => panic!("unexpected route frame {ty:?}"),
    }
}

/// Like [`raw_route_request`] but returns the raw terminal frame (Response OR
/// Error) for callers asserting the error contract.
pub async fn raw_route_frame(
    stream: &mut TcpStream,
    route: Route,
    corr: u64,
    body: Value,
) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        route.channel,
        route.epoch,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame).await.unwrap();
    loop {
        let frame = read_frame_timeout(stream).await;
        if frame.header.corr == corr
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            return frame;
        }
    }
}

/// `credential.get { handle }` on the route channel; returns the decoded body.
pub async fn credential_get(
    stream: &mut TcpStream,
    route: Route,
    corr: u64,
    handle: &str,
) -> Value {
    raw_route_request(
        stream,
        route,
        corr,
        serde_json::json!({ "method": "credential.get", "params": { "handle": handle } }),
    )
    .await
}

/// `credential.report_auth_failure { handle, provider_status, record_version }`.
///
/// Exists so a deploy's reachability probe can drive the report arm against a STAGED
/// binary before placement. Nothing else in this suite reported over the wire, which
/// meant the one behaviour a stale-not-dead deploy changes had no end-to-end driver:
/// the difference between a binary that latches and one that marks stale is invisible
/// to every other leg of the acceptance ladder.
pub async fn credential_report_auth_failure(
    stream: &mut TcpStream,
    route: Route,
    corr: u64,
    handle: &str,
    provider_status: u16,
    record_version: u64,
) -> Value {
    raw_route_request(
        stream,
        route,
        corr,
        serde_json::json!({
            "method": "credential.report_auth_failure",
            "params": {
                "handle": handle,
                "provider_status": provider_status,
                "record_version": record_version,
            },
        }),
    )
    .await
}

/// `credential.get_many { items: [{handle}, ...] }` on the route channel.
pub async fn credential_get_many(
    stream: &mut TcpStream,
    route: Route,
    corr: u64,
    handles: &[&str],
) -> Value {
    let items: Vec<Value> = handles
        .iter()
        .map(|h| serde_json::json!({ "handle": h }))
        .collect();
    raw_route_request(
        stream,
        route,
        corr,
        serde_json::json!({ "method": "credential.get_many", "params": { "items": items } }),
    )
    .await
}

/// Count `audit_log` rows flagged as an alarm with a given reason, by reading the
/// vault's sqlite directly. Call only AFTER the daemon is stopped (it holds the
/// single-writer lease while alive). `db_path` is `<data_dir>/store.db`.
pub fn count_alarm_rows(db_path: &Path, reason: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open vault db for audit read");
    conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE alarm = 1 AND alarm_reason = ?1",
        rusqlite::params![reason],
        |r| r.get::<_, i64>(0),
    )
    .expect("count alarm rows")
}
