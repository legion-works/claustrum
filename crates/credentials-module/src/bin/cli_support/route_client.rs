use std::{path::Path, time::Duration};

use credentials_core::MODULE_ID;
use serde_json::{json, Value};
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RPC_TIMEOUT: Duration = Duration::from_secs(15);

pub struct OpenRoute {
    pub stream: TcpStream,
    pub channel: u16,
    pub epoch: u32,
}

pub async fn connect(connection_file_path: &Path) -> Result<TcpStream, String> {
    let conn = connection_file::read_for_client(connection_file_path)
        .map_err(|e| format!("no subc connection file: {e}"))?;
    let endpoint = conn
        .endpoints
        .first()
        .ok_or_else(|| "connection file has no endpoint".to_string())?;
    let mut stream = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(format!("connect: {e}")),
        Err(_) => return Err("connect timed out".into()),
    };
    authenticate_client(&mut stream, &conn, CONNECT_TIMEOUT)
        .await
        .map_err(|e| format!("client handshake: {e}"))?;
    Ok(stream)
}

pub async fn catalog_has_module(stream: &mut TcpStream) -> Result<bool, String> {
    let frame = control_request(1, json!({ "op": "catalog.list" }));
    write_frame(stream, &frame)
        .await
        .map_err(|e| format!("write catalog.list: {e}"))?;
    let response = read_control_response(stream, 1).await?;
    let value: Value = serde_json::from_slice(&response.body).map_err(|e| e.to_string())?;
    Ok(value["modules"]
        .as_array()
        .map(|modules| {
            modules
                .iter()
                .any(|module| module["module_id"] == MODULE_ID)
        })
        .unwrap_or(false))
}

pub async fn open_route(
    stream: TcpStream,
    project_root: &Path,
    harness: &str,
    session: &str,
) -> Result<OpenRoute, String> {
    let mut stream = stream;
    let target = RouteTarget::ManagementSurface {
        module_id: MODULE_ID.to_string(),
    };
    let identity = BindIdentity {
        project_root: project_root.to_path_buf(),
        harness: harness.to_string(),
        session: session.to_string(),
    };
    let frame = control_request(
        2,
        json!({ "op": "route.open", "target": target, "identity": identity }),
    );
    write_frame(&mut stream, &frame)
        .await
        .map_err(|e| format!("write route.open: {e}"))?;
    let response = read_control_response(&mut stream, 2).await?;
    if response.header.ty == FrameType::Error {
        return Err(error_reason(&response.body));
    }
    let value: Value = serde_json::from_slice(&response.body).map_err(|e| e.to_string())?;
    let channel = value["route_channel"]
        .as_u64()
        .and_then(|channel| u16::try_from(channel).ok())
        .ok_or_else(|| "route.open returned no route_channel".to_string())?;
    let epoch = value["route_epoch"]
        .as_u64()
        .and_then(|epoch| u32::try_from(epoch).ok())
        .ok_or_else(|| "route.open returned no route_epoch".to_string())?;
    Ok(OpenRoute {
        stream,
        channel,
        epoch,
    })
}

pub fn control_request(corr: u64, body: Value) -> Frame {
    Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        corr,
        serde_json::to_vec(&body).expect("JSON control request"),
    )
    .expect("valid control frame")
}

pub fn route_request(channel: u16, epoch: u32, corr: u64, body: Value) -> Frame {
    Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&body).expect("JSON route request"),
    )
    .expect("valid route frame")
}

pub async fn read_control_response(stream: &mut TcpStream, corr: u64) -> Result<Frame, String> {
    read_matching(stream, Some(0), corr).await
}

pub async fn read_route_response(stream: &mut TcpStream, corr: u64) -> Result<Frame, String> {
    read_matching(stream, None, corr).await
}

async fn read_matching(
    stream: &mut TcpStream,
    required_channel: Option<u16>,
    corr: u64,
) -> Result<Frame, String> {
    tokio::time::timeout(RPC_TIMEOUT, async {
        loop {
            let frame = read_frame(stream)
                .await
                .map_err(|e| format!("read: {e}"))?
                .ok_or_else(|| "connection closed".to_string())?;
            if required_channel.is_none_or(|channel| frame.header.channel == channel)
                && frame.header.corr == corr
                && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
            {
                return Ok(frame);
            }
        }
    })
    .await
    .map_err(|_| "response timed out".to_string())?
}

pub fn error_reason(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .or_else(|| value.get("detail"))
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| "module refused the operation".to_string())
}
