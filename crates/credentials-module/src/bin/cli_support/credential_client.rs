use std::{fmt, path::Path};

use serde_json::{json, Value};
use subc_protocol::FrameType;
use subc_transport::write_frame;

use crate::route_client;

pub struct ServedCredential {
    pub payload: Vec<u8>,
    pub record_version: u64,
    pub expires_at_ms: Option<i64>,
}

impl fmt::Debug for ServedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServedCredential")
            .field(
                "payload",
                &format_args!("<{} bytes redacted>", self.payload.len()),
            )
            .field("record_version", &self.record_version)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialReadError {
    NeedsReauth,
    NotFound,
    RefreshUnsupported,
    RefreshFailed,
    VaultLocked,
    Corrupt,
    TtlUnsatisfiable,
    Refused,
    Transport,
}

impl fmt::Display for CredentialReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NeedsReauth => "credential needs reauthentication",
            Self::NotFound => "credential capability was not found",
            Self::RefreshUnsupported => "credential refresh is unsupported",
            Self::RefreshFailed => "credential refresh failed",
            Self::VaultLocked => "credential vault is unavailable",
            Self::Corrupt => "credential record is corrupt",
            Self::TtlUnsatisfiable => "credential cannot meet the requested lifetime",
            Self::Refused => "credential read was refused",
            Self::Transport => "credential route is unavailable",
        };
        f.write_str(message)
    }
}

impl std::error::Error for CredentialReadError {}

pub fn get_online(
    connection_file: &Path,
    project_root: &Path,
    handle: &str,
) -> Result<ServedCredential, CredentialReadError> {
    std::env::remove_var("SUBC_MODULE_ID");
    std::env::remove_var("SUBC_LAUNCH_NONCE");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CredentialReadError::Transport)?;
    runtime.block_on(get_online_async(connection_file, project_root, handle))
}

async fn get_online_async(
    connection_file: &Path,
    project_root: &Path,
    handle: &str,
) -> Result<ServedCredential, CredentialReadError> {
    let stream = route_client::connect(connection_file)
        .await
        .map_err(|_| CredentialReadError::Transport)?;
    let mut route = route_client::open_route(stream, project_root, "ck-auth", "opencode-read")
        .await
        .map_err(|_| CredentialReadError::Transport)?;
    let frame = route_client::route_request(
        route.channel,
        route.epoch,
        10,
        json!({
            "method": "credential.get",
            "params": { "handle": handle, "force_refresh": false, "min_ttl_ms": 0 },
        }),
    );
    write_frame(&mut route.stream, &frame)
        .await
        .map_err(|_| CredentialReadError::Transport)?;
    let response = route_client::read_route_response(&mut route.stream, 10)
        .await
        .map_err(|_| CredentialReadError::Transport)?;
    if response.header.ty == FrameType::Error {
        return Err(CredentialReadError::Refused);
    }
    decode_response(&response.body)
}

fn decode_response(body: &[u8]) -> Result<ServedCredential, CredentialReadError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| CredentialReadError::Transport)?;
    let result = value.get("result").ok_or(CredentialReadError::Transport)?;
    if let Some(error) = result.get("error") {
        return Err(map_error(error));
    }
    let payload = result
        .get("payload")
        .and_then(Value::as_array)
        .ok_or(CredentialReadError::Transport)?
        .iter()
        .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect::<Option<Vec<_>>>()
        .ok_or(CredentialReadError::Transport)?;
    let record_version = result
        .get("record_version")
        .and_then(Value::as_u64)
        .ok_or(CredentialReadError::Transport)?;
    let expires_at_ms = match result.get("expires_at_ms") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_i64().ok_or(CredentialReadError::Transport)?),
    };
    Ok(ServedCredential {
        payload,
        record_version,
        expires_at_ms,
    })
}

fn map_error(error: &Value) -> CredentialReadError {
    match (
        error.get("class").and_then(Value::as_str),
        error.get("code").and_then(Value::as_str),
    ) {
        (Some("auth_required"), Some("needs_reauth")) => CredentialReadError::NeedsReauth,
        (_, Some("not_found")) => CredentialReadError::NotFound,
        (_, Some("refresh_unsupported")) => CredentialReadError::RefreshUnsupported,
        (_, Some("refresh_failed")) => CredentialReadError::RefreshFailed,
        (_, Some("vault_locked")) => CredentialReadError::VaultLocked,
        (_, Some("corrupt")) => CredentialReadError::Corrupt,
        (_, Some("ttl_unsatisfiable")) => CredentialReadError::TtlUnsatisfiable,
        _ => CredentialReadError::Refused,
    }
}
