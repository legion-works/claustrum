//! The CLI's route-plane admin client: commit an admin op to the RUNNING module.
//!
//! When the daemon is up it holds the single-writer lease, so the offline path
//! (which takes the lease) cannot write. This client talks to the running module
//! over the subc route plane instead, authenticating each op with a master-key
//! challenge-response (the module's Gate 2). The CLI resolves the SAME master key
//! from the keychain WITHOUT opening the database or taking the lease — the
//! challenge returns the module's `key_id`, and `resolver::resolve_for_db` loads
//! the slot whose fingerprint matches it. BOTH slots are searched: a rotation that
//! crashed before its promote leaves the live key in `Next`, and it stays there
//! until someone rotates again.
//!
//! Fallback discipline (Oracle finding 10): the caller falls back to the offline
//! lease path ONLY when no live module is reachable. Once an `admin.op` has been
//! sent, a lost response is INDETERMINATE — the op may have committed — so this
//! never silently retries or falls back after dispatch; it returns a distinct error
//! the CLI surfaces as "verify with list/verify-audit before retrying".

use credentials_core::admin_auth::{AdminMacKey, TranscriptParts, ADMIN_NONCE_LEN, VAULT_ID_LEN};
use credentials_core::admin_ops::AdminOpBody;
use credentials_core::resolver::{self, ResolverConfig};
use credentials_core::vault_id_for;
use serde_json::{json, Value};
use subc_protocol::FrameType;
use subc_transport::write_frame;
use tokio::net::TcpStream;

use crate::route_client;

/// The outcome of attempting a route-plane commit.
pub enum RouteCommit {
    /// The op committed on the running module; carries its JSON result.
    Committed(Value),
    /// No live module was reachable (no connection file, no daemon, or the vault
    /// module is not in the catalog). The caller MAY fall back to the offline path
    /// — nothing was dispatched.
    NoLiveModule(String),
    /// The module refused the op (auth, gate, or a store error). Terminal — do NOT
    /// fall back (the module is alive and said no).
    Refused(String),
    /// The op was dispatched but the outcome is UNKNOWN (connection dropped after
    /// send). Do NOT fall back or retry blindly — the op may have committed.
    Indeterminate(String),
}

/// Try to commit `op` to a running module. `data_dir` locates the vault (for the
/// key resolution and vault-id derivation); `config` is the key-source resolver;
/// `conn_path` is the subc connection file (from `--subc`, or the default probe
/// path). Absence of the file ⇒ no daemon ⇒ the caller may go offline.
pub fn commit(
    data_dir: &std::path::Path,
    config: &ResolverConfig,
    conn_path: &std::path::Path,
    op: &AdminOpBody,
) -> RouteCommit {
    let vault_id = match vault_id_for(data_dir) {
        Some(v) => v,
        None => return RouteCommit::NoLiveModule("cannot derive vault id".into()),
    };
    let op_bytes = match op.to_bytes() {
        Ok(b) => b,
        Err(e) => return RouteCommit::Refused(format!("encoding op: {e}")),
    };

    run_async(async move { commit_async(conn_path, &vault_id, config, &op_bytes).await })
}

fn run_async<F: std::future::Future<Output = RouteCommit>>(fut: F) -> RouteCommit {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return RouteCommit::NoLiveModule(format!("runtime: {e}")),
    };
    rt.block_on(fut)
}

async fn commit_async(
    conn_path: &std::path::Path,
    vault_id: &[u8; VAULT_ID_LEN],
    config: &ResolverConfig,
    op_bytes: &[u8],
) -> RouteCommit {
    let mut stream = match route_client::connect(conn_path).await {
        Ok(stream) => stream,
        Err(e) => return RouteCommit::NoLiveModule(e),
    };

    // The vault module must be catalog-live; otherwise there is no module to admin.
    match route_client::catalog_has_module(&mut stream).await {
        Ok(true) => {}
        Ok(false) => {
            return RouteCommit::NoLiveModule("vault module not in catalog".into());
        }
        Err(e) => return RouteCommit::NoLiveModule(format!("catalog.list: {e}")),
    }

    // Wire v2: route identity is (channel, epoch); every route frame must carry
    // the epoch the route was opened under, or the daemon's relay drops it.
    let route = match route_client::open_route(stream, &config.data_dir, "ck-auth", "admin").await {
        Ok(route) => route,
        Err(e) => return RouteCommit::NoLiveModule(format!("route.open: {e}")),
    };
    let route_channel = route.channel;
    let route_epoch = route.epoch;
    let mut stream = route.stream;

    // admin.challenge: fetch a nonce + the module's key_id (so we resolve the SAME
    // key) + its vault_id (so we confirm we are talking to the intended vault).
    let (nonce, key_id_hex, module_vault_id_hex) =
        match challenge(&mut stream, route_channel, route_epoch).await {
            Ok(v) => v,
            Err(RpcFail::Refused(m)) => return RouteCommit::Refused(m),
            Err(RpcFail::Transport(m)) => return RouteCommit::NoLiveModule(m),
        };

    // Confirm the module's vault identity matches the vault we were pointed at. A
    // mismatch means the connection file points at a DIFFERENT vault's module — do
    // not sign an op for it.
    if module_vault_id_hex != hex(vault_id) {
        return RouteCommit::Refused(
            "the running module is a different vault (vault-id mismatch); not committing".into(),
        );
    }

    // Resolve the master key by the module's key_id, WITHOUT opening the DB or
    // taking the lease.
    //
    // `resolve_for_db` rather than `resolve`, and the name understates it here: it
    // takes the fingerprint as an argument and never touches the database, so the
    // module's challenge reply serves as the anchor exactly as the DB row does for
    // the daemon. The difference that matters is that it searches BOTH key slots.
    //
    // This used to be `resolve`, justified by "rotation is offline-only, so the live
    // key is the Current slot". That reasoning is sound and the conclusion is still
    // wrong: a rotation that crashed after the rewrap and before the promote leaves
    // the vault sealed under `Next`, and it STAYS there. The daemon boots fine --
    // it resolves against the DB fingerprint and finds `Next` -- so the vault serves
    // normally while every online admin op is refused for a key mismatch, which is
    // the worst shape for diagnosis: healthy reads, dead writes, and an error naming
    // keys rather than rotation. Proven in resolver.rs by
    // `a_crashed_rotation_makes_resolve_and_resolve_for_db_disagree`.
    let key_id = match credentials_core::key::KeyId::from_hex(&key_id_hex) {
        Some(k) => k,
        None => return RouteCommit::Refused("module returned a malformed key_id".into()),
    };
    let key = match resolver::resolve_for_db(config, key_id) {
        Ok(k) => k,
        Err(e) => {
            return RouteCommit::Refused(format!(
                "cannot resolve the master key to authorize the op: {e}"
            ))
        }
    };
    let mac_key = AdminMacKey::derive(&key);
    let tag = mac_key.sign(&TranscriptParts {
        vault_id,
        key_id,
        nonce: &nonce,
        op_body: op_bytes,
    });

    // admin.op: send the exact op bytes + tag. After THIS send, a lost response is
    // indeterminate (the op may have committed).
    admin_op(
        &mut stream,
        route_channel,
        route_epoch,
        op_bytes,
        &hex(&tag),
    )
    .await
}

enum RpcFail {
    Refused(String),
    Transport(String),
}

async fn challenge(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
) -> Result<([u8; ADMIN_NONCE_LEN], String, String), RpcFail> {
    let frame = route_client::route_request(
        route_channel,
        route_epoch,
        100,
        json!({ "method": "admin.challenge" }),
    );
    if let Err(e) = write_frame(stream, &frame).await {
        return Err(RpcFail::Transport(format!("write admin.challenge: {e}")));
    }
    let resp = route_client::read_route_response(stream, 100)
        .await
        .map_err(RpcFail::Transport)?;
    if resp.header.ty == FrameType::Error {
        return Err(RpcFail::Refused(route_client::error_reason(&resp.body)));
    }
    let value: Value = serde_json::from_slice(&resp.body)
        .map_err(|e| RpcFail::Transport(format!("decode challenge: {e}")))?;
    let result = &value["result"];
    let nonce_hex = result["nonce_hex"].as_str().unwrap_or_default();
    let nonce_vec =
        decode_hex(nonce_hex).ok_or_else(|| RpcFail::Transport("bad nonce hex".into()))?;
    let nonce: [u8; ADMIN_NONCE_LEN] = nonce_vec
        .as_slice()
        .try_into()
        .map_err(|_| RpcFail::Transport("nonce wrong length".into()))?;
    let key_id_hex = result["key_id_hex"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let vault_id_hex = result["vault_id_hex"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Ok((nonce, key_id_hex, vault_id_hex))
}

async fn admin_op(
    stream: &mut TcpStream,
    route_channel: u16,
    route_epoch: u32,
    op_bytes: &[u8],
    tag_hex: &str,
) -> RouteCommit {
    // The op body rides as a STRING so the exact MAC'd bytes survive the outer
    // envelope verbatim (no JSON re-encoding of the authenticated bytes).
    let op_body_str = match std::str::from_utf8(op_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => return RouteCommit::Refused("op body is not valid utf-8".into()),
    };
    let frame = route_client::route_request(
        route_channel,
        route_epoch,
        101,
        json!({
            "method": "admin.op",
            "params": { "op_body": op_body_str, "tag_hex": tag_hex },
        }),
    );
    if let Err(e) = write_frame(stream, &frame).await {
        // Failed BEFORE the bytes left us: safe to treat as not-dispatched.
        return RouteCommit::NoLiveModule(format!("write admin.op: {e}"));
    }
    match route_client::read_route_response(stream, 101).await {
        Ok(resp) if resp.header.ty == FrameType::Error => {
            RouteCommit::Refused(route_client::error_reason(&resp.body))
        }
        Ok(resp) => match serde_json::from_slice::<Value>(&resp.body) {
            Ok(v) => RouteCommit::Committed(v["result"].clone()),
            Err(e) => RouteCommit::Indeterminate(format!(
                "op was sent but its response did not decode ({e}); verify with `list`/`verify-audit`"
            )),
        },
        // The op was already on the wire; a missing reply is INDETERMINATE.
        Err(e) => RouteCommit::Indeterminate(format!(
            "op was sent but no response arrived ({e}); it may have committed — verify with `list`/`verify-audit` before retrying"
        )),
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

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
