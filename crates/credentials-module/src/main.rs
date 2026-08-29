#![forbid(unsafe_code)]

//! The claustrum subc module daemon (the credential vault).
//!
//! Connects out to the subc daemon, authenticates over loopback TCP, and registers
//! a reserved `ManagementSurface` — echoing the `SUBC_LAUNCH_NONCE` the supervisor
//! injected so only the spawned process can claim the `claustrum` id
//! (closing the vault-impersonation hole). It serves the capability-handle read
//! surface plus principal-scoped `credential.get_scoped`, `credential.sign`, and
//! `credential.public_key` route operations.
//! There is deliberately NO unauthenticated write op on this channel — writes live in
//! the admin surface, gated by master-key possession + the single-writer lease.
//!
//! The subc registration handshake is a `HELLO` frame the module sends (carrying
//! its manifest and the launch nonce) and a `HELLO_ACK` the daemon returns
//! (carrying the resolved storage descriptor); the rest is a frame loop of route
//! requests. This mirrors the proven ai-provider-quota module.
//!
//! Boot sequence is a gate: resolve the master key → open + migrate the encrypted
//! store → reconcile any dangling refresh intents → ONLY THEN accept reads. A `get`
//! is never served while a crash-left refresh intent is unresolved.

mod admin_surface;
mod limiter;
mod read_surface;

use std::path::PathBuf;
use std::sync::Arc;

use cortexkit_store::{open_sqlite, StorageDescriptor};
use credentials_core::engine::RefreshEngine;
use credentials_core::http::ReqwestTransport;
use credentials_core::refresh_adapters::{
    anthropic::AnthropicAdapter, antigravity::AntigravityAdapter, cursor::CursorAdapter,
    devin::DevinAdapter, digitalocean::DigitalOceanAdapter, github_app::GithubAppAdapter,
    github_copilot::GithubCopilotAdapter, google::GoogleAdapter, kimi::KimiAdapter,
    openai::OpenAiAdapter, snowflake::SnowflakeAdapter, xai::XaiAdapter, RefreshAdapter,
};
use credentials_core::resolver::{self, KeySource, ResolverConfig};
use credentials_core::store::EncryptedStore;
use serde::Deserialize;
use serde_json::json;
use subc_protocol::manifest::Concurrency;
use subc_protocol::manifest::ManifestProvenance;
use subc_protocol::{
    manifest::{
        Bindings, IdentityBinding, ManagementOperation, ManagementOperationKind, ModuleManifest,
        ProviderRole, StorageBinding, StorageKind, StorageScope, TrustTier,
    },
    session::{
        HealthStatus, ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
    },
    ErrorBody, Flags, Frame, FrameType, ModuleHelloAckBody, ModuleHelloBody, Priority,
    PROTOCOL_VERSION, SUBC_LAUNCH_NONCE_ENV, SUBC_MODULE_ID_ENV, SUBC_PROTOCOL_CRATE_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter},
    net::TcpStream,
    sync::mpsc,
};

use limiter::{Caps, FetchLimiter};
use read_surface::{
    GetManyParams, GetParams, GetScopedParams, PublicKeyParams, ReadSurface,
    ReportAuthFailureParams, StatusParams,
};

// The vault's module id — re-exported from the single cross-binary definition site
// so the daemon and CLI cannot drift. The env var (SUBC_MODULE_ID) still overrides
// it at launch; this is the fallback for a dev run without a supervisor.
const DEFAULT_MODULE_ID: &str = credentials_core::contract::MODULE_ID;
const HELLO_CORR: u64 = 1;
// The data-plane (route response) egress buffer. Route responses can burst, so this is
// generous — but a hostile/slow consumer filling it must NOT be able to stall the health
// reply, which is why control frames ride a SEPARATE lane below.
const EGRESS_BUFFER: usize = 64;
// The control-plane (channel-0) egress buffer: HELLO, pongs, route-bind-acks, and the
// health.check reply. Kept on its own small channel, drained with priority, so a full
// route-response queue can never block a control frame's `send().await` — the health
// reply must reach the supervisor within the prober deadline regardless of data-plane
// load (subc-health spec §2). Only rare, tiny control frames use it, so it stays near-
// empty and a control send never waits behind route traffic.
const CONTROL_EGRESS_BUFFER: usize = 16;

// How often the background refresher recomputes the cached health snapshot. Well
// under the prober's cadence so the served snapshot is never more than one tick
// stale, and each tick is a cheap no-decrypt scan that runs OFF the probe path.
const HEALTH_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

// Capability-handle read-surface operations plus the separate principal-scoped read.
const OP_GET: &str = "credential.get";
const OP_GET_SCOPED: &str = "credential.get_scoped";
const OP_GET_MANY: &str = "credential.get_many";
const OP_STATUS: &str = "credential.status";
const OP_REPORT_AUTH_FAILURE: &str = "credential.report_auth_failure";
const OP_SIGN: &str = "credential.sign";
const OP_PUBLIC_KEY: &str = "credential.public_key";
/// Admin ops on the running module (authenticated: direct principal + master-key
/// challenge-response). `admin.challenge` issues a nonce; `admin.op` carries the
/// authenticated op body + tag.
const OP_ADMIN_CHALLENGE: &str = "admin.challenge";
const OP_ADMIN_OP: &str = "admin.op";

#[tokio::main]
async fn main() -> Result<(), ModuleError> {
    // Answered BEFORE the --subc gate, so it works on a binary that is not being
    // supervised. Without this the only way to ask a deployed daemon what it is was to
    // start it, which needs a connection file and a live supervisor -- an identity
    // check that requires the thing being identified to already be running correctly.
    if std::env::args_os().skip(1).any(|a| a == "--version") {
        println!(
            "ck-claustrum {} ({})",
            env!("CARGO_PKG_VERSION"),
            credentials_core::contract::BUILD_REV
        );
        return Ok(());
    }
    let config = ModuleConfig::from_env()?;
    run(config).await
}

struct ModuleConfig {
    connection_file_path: PathBuf,
    module_id: String,
    /// The one-time launch nonce for a reserved module (echoed in HELLO). `None`
    /// for a non-reserved launch (the daemon would then reject a reserved id, but a
    /// dev run without a supervisor simply omits it).
    launch_nonce: Option<String>,
}

impl ModuleConfig {
    fn from_env() -> Result<Self, ModuleError> {
        let connection_file_path = parse_subc_arg(std::env::args_os().skip(1))?;
        let module_id = std::env::var(SUBC_MODULE_ID_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
        let launch_nonce = std::env::var(SUBC_LAUNCH_NONCE_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty());
        Ok(Self {
            connection_file_path,
            module_id,
            launch_nonce,
        })
    }
}

/// The two egress lanes to the supervisor. Control-plane frames (HELLO, pong, route-bind
/// ack, and the health.check reply) ride `control`; data-plane route responses ride
/// `route`. Two separate channels, drained control-first (see [`drain_writer`]), so a
/// hostile or slow route consumer that fills the route lane can never delay the health
/// reply past the prober deadline (subc-health spec §2). Cheap to clone (two `Sender`s).
#[derive(Clone)]
struct Egress {
    control: mpsc::Sender<Frame>,
    route: mpsc::Sender<Frame>,
}

/// Module-side route map: channel → binding epoch (wire v2, spec §3.3 layer 2).
///
/// The daemon's relay validation alone is insufficient (forwarding is not atomic
/// with its table lookup), so every endpoint keeps its own `channel → epoch` map:
/// installed when a `route.bind` is accepted, removed on an epoch-valid Goodbye,
/// and checked against every nonzero-channel ingress frame BEFORE dispatch or any
/// lifecycle effect. A mismatched or unknown slot is a silent drop — never an
/// Error frame (only the daemon's relay emits `unknown_channel`), because erroring
/// would inject into the slot's NEW binding's corr space.
#[derive(Default)]
struct RouteEpochs(
    std::sync::Mutex<std::collections::HashMap<u16, u32>>,
    /// `(channel, epoch)` pairs already reported as dropped, so a repeat is bounded by
    /// its absence from the log rather than adding another line.
    std::sync::Mutex<std::collections::HashSet<(u16, u32)>>,
);

impl RouteEpochs {
    fn install(&self, channel: u16, epoch: u32) {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(channel, epoch);
    }

    /// Whether `channel` is a live binding at exactly `epoch`.
    fn matches(&self, channel: u16, epoch: u32) -> bool {
        let map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&channel) == Some(&epoch)
    }

    /// The epoch this module holds for `channel`, for naming what a drop expected.
    fn expected(&self, channel: u16) -> Option<u32> {
        let map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&channel).copied()
    }

    /// Record a dropped frame ONCE per `(channel, epoch)`, returning whether this was
    /// the first — so a drop can be named without letting a looping sender drive
    /// unbounded log volume on the ingress path.
    ///
    /// SILENT ON THE WIRE IS A SECURITY PROPERTY; SILENT IN MY OWN DIAGNOSTICS WAS JUST
    /// A HOLE. The wire silence is settled and correct — a module-emitted Error would
    /// inject into the corr space of the slot's next tenant. But this check also wrote
    /// nothing ANYWHERE, so when a consumer hung for 30+ minutes across the 2026-08-25
    /// restart and the supervisor seat asked for the `(channel, epoch)` of the frames I
    /// had dropped, I COULD NOT ANSWER: I had never written them down. The comparison
    /// that would have decided the incident — dropped epoch against the live census —
    /// was unavailable because of this gap, not because of the silence.
    ///
    /// Third instance of one shape in a week (an unlogged drain happy-path, this, and an
    /// announcement with no join to its wire): ABSENCE OF A RECORD READ AS ABSENCE OF AN
    /// EVENT. The vault's `auth_events` emptiness is honest because every refusal path
    /// there provably writes. This emptiness was not.
    ///
    /// WHAT A CLEAN DROP RECORD DOES NOT PROVE, learned by over-reading one on
    /// 2026-08-26 and worth stating before someone repeats it: it does NOT mean no
    /// consumer held a stale binding. It means no stale frame REACHED THIS CHECK.
    ///
    /// The daemon relay sits below this code and refuses a frame for a channel it no
    /// longer holds with a class-less `unknown_channel`. Those frames never arrive here,
    /// so this record stays empty while a stale-binding outage is in progress one layer
    /// down. During a fleet speech outage I read an empty record and concluded "the
    /// stale-binding hypothesis is dead"; the cause was a stale binding, refused by the
    /// relay after a restart of this module. The operational answer (not custody, not
    /// this wire) was right and the mechanical one was wrong.
    ///
    /// So this instrument answers exactly one question: did a frame reach MY endpoint
    /// carrying an epoch I do not hold. A consumer-visible stall with a clean record
    /// here points DOWN to the relay, not away from stale bindings.
    fn note_drop(&self, channel: u16, epoch: u32) -> bool {
        let mut seen = self.1.lock().unwrap_or_else(|p| p.into_inner());
        seen.insert((channel, epoch))
    }

    fn remove(&self, channel: u16) {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(&channel);
    }
}

async fn run(config: ModuleConfig) -> Result<(), ModuleError> {
    let stream = connect_to_subc(&config.connection_file_path).await?;
    let (mut read_half, write_half) = tokio::io::split(stream);
    let (control_tx, control_rx) = mpsc::channel::<Frame>(CONTROL_EGRESS_BUFFER);
    let (route_tx, route_rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    let writer = tokio::spawn(drain_writer(write_half, control_rx, route_rx));
    let egress = Egress {
        control: control_tx,
        route: route_tx,
    };

    // The HELLO_ACK carries the resolved storage descriptor; the surface is built
    // AFTER the handshake (it needs the descriptor) and the boot gate runs before
    // any request is served. module_loop owns `egress` and drops it on return, closing
    // both lanes so the writer task finishes.
    let loop_result = module_loop(&mut read_half, egress, &config).await;

    let writer_result = writer
        .await
        .map_err(|e| ModuleError::Message(e.to_string()));
    match (loop_result, writer_result) {
        (Err(loop_err), _) => Err(loop_err),
        (Ok(()), Ok(Ok(()))) => Ok(()),
        (Ok(()), Ok(Err(writer_err))) => Err(ModuleError::Message(writer_err.to_string())),
        (Ok(()), Err(join_err)) => Err(join_err),
    }
}

async fn connect_to_subc(connection_file_path: &PathBuf) -> Result<TcpStream, ModuleError> {
    let conn = connection_file::read(connection_file_path)
        .map_err(|e| ModuleError::Message(format!("reading connection file: {e}")))?;
    let endpoint = conn
        .endpoints
        .first()
        .ok_or_else(|| ModuleError::Message("connection file has no endpoints".into()))?;
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| ModuleError::Message(format!("connect {addr}: {e}")))?;
    authenticate_client(&mut stream, &conn, std::time::Duration::from_secs(2))
        .await
        .map_err(|e| ModuleError::Message(format!("authenticate: {e}")))?;
    Ok(stream)
}

async fn module_loop<R>(
    read_half: &mut R,
    egress: Egress,
    config: &ModuleConfig,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    // HELLO is a channel-0 control frame — send it on the control lane.
    send_hello(&egress.control, config).await?;
    let ack = expect_hello_ack(read_half).await?;

    // Boot gate: build the vault from the resolved descriptor, then reconcile any
    // dangling refresh intents BEFORE accepting any request.
    let (surface, admin) = build_surface(&ack).await?;
    let surface = Arc::new(surface);
    let admin = Arc::new(admin);
    // Wire v2: the module-side channel → epoch map (spec §3.3 layer 2).
    let routes = Arc::new(RouteEpochs::default());

    // Keep the cached health snapshot current OFF the probe path. The health.check
    // reply must be cheap/in-memory (spec §2), so the live store scan runs here on a
    // cadence, never on the channel-0 dispatch. Aborted on loop exit via the guard.
    let health_refresher = spawn_health_refresher(Arc::clone(&surface));
    let _refresher_guard = AbortOnDrop(health_refresher);

    // NO READ TIMEOUT HERE, AND THAT IS DELIBERATE -- but it rests on the supervisor,
    // so the dependency is named rather than left for someone to rediscover.
    //
    // An error propagates and a clean EOF returns, both ending this loop and dropping
    // the connection for the supervisor to respawn against. The uncovered case is a
    // SILENTLY HALF-OPEN connection where no bytes and no error ever arrive: this
    // blocks in `read_frame` forever, holding a corpse it cannot notice. That is the
    // vault's exact profile -- long-lived, low-traffic, idle for hours -- and it is the
    // shape that took a sibling module's credential leg dark in August.
    //
    // THIS DAEMON HAS NO SELF-LIVENESS. Detection is entirely the supervisor's prober,
    // verified at source in subconscious (supervise.rs): a timed-out probe counts into
    // consecutive_failures and at the threshold calls health_restart_child on an
    // UNCONDITIONAL path -- no action config is consulted, so `on_degraded` cannot
    // suppress it. That lane fires only for a module that does not ANSWER; the
    // configurable actions gate the other lane, where a module answers with a degraded
    // status. A deaf daemon rides the unconditional one.
    //
    // The numbers, all compiled defaults this module's config does not override:
    // cadence 30s, deadline 5s, failure_threshold 3, drain 30s. So the dark window is
    // ~90s to Unresponsive plus up to 30s drain before SIGKILL. Acceptable because a
    // read failing for two minutes is a `transient` refusal every consumer retries.
    //
    // THE BUDGET IS THE REAL FAILURE MODE, not the window: DEFAULT_MAX_RESTARTS is 3,
    // lifetime. A RECURRING silent death does not converge on a self-healing loop, it
    // converges on a PARKED MODULE -- every credential in the fleet unreachable until
    // an operator revives it. "The supervisor restarts us" is true three times.
    //
    // Do NOT add a redundant liveness probe here on the strength of the paragraph
    // above; the supervisor's already fires and a second one would only add a way to
    // disagree. What WOULD justify revisiting: this daemon acquiring an outbound
    // request that awaits a reply. Today it is purely reactive after HELLO, which is
    // why the reused-dead-connection class cannot occur here at all -- there is no
    // requester object for the defect to live on. That immunity is a property of the
    // current role shape and ends silently the day the role changes, with nothing in
    // the diff looking like a connection-lifecycle edit.
    loop {
        let Some(frame) = read_frame(read_half)
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?
        else {
            return Ok(()); // clean EOF: subc closed the connection.
        };
        if !handle_frame(frame, &egress, &surface, &admin, &routes).await? {
            return Ok(());
        }
    }
}

/// Spawn the background task that keeps the cached health snapshot current. It
/// ticks on [`HEALTH_REFRESH_INTERVAL`] and recomputes off the probe path, so the
/// channel-0 `health.check` reply is always a cheap in-memory read of the last
/// computed snapshot (spec §2: the reply must not do live store work).
fn spawn_health_refresher(surface: Arc<ReadSurface>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEALTH_REFRESH_INTERVAL);
        // Skip missed ticks rather than bursting to catch up if a scan ran long.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            surface.refresh_health();
        }
    })
}

/// Aborts the wrapped task when dropped, so the health refresher stops when the
/// serve loop returns (clean EOF or error) instead of outliving the connection.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Build the read surface from the HELLO_ACK's storage descriptor: resolve the
/// master key, open + migrate the encrypted store, build the refresh engine with
/// the registered adapters, then reconcile persisted refresh state before exposing reads.
async fn build_surface(
    ack: &ModuleHelloAckBody,
) -> Result<(ReadSurface, admin_surface::AdminSurface), ModuleError> {
    let descriptor_value = ack
        .storage
        .as_ref()
        .ok_or_else(|| ModuleError::Message("HELLO_ACK carried no storage descriptor".into()))?;
    let descriptor: StorageDescriptor = serde_json::from_value(descriptor_value.clone())
        .map_err(|e| ModuleError::Message(format!("decoding storage descriptor: {e}")))?;

    let data_dir = sqlite_data_dir(&descriptor)?;
    // Derive the vault identity before the data_dir is moved into the resolver config;
    // it binds the admin-op transcript to THIS vault.
    let vault_id = credentials_core::vault_id_for(&data_dir)
        .ok_or_else(|| ModuleError::Message("cannot derive vault id from data dir".into()))?;
    let kimi_device_id = credentials_core::refresh_adapters::kimi::read_device_id_or_unknown(
        &data_dir.join("kimi-device-id"),
    );
    let resolver_config = resolver_config_from_env(data_dir);

    // Open + migrate the store first, then read the database's plaintext key
    // fingerprint and resolve the master key crash-safely: pick whichever key-store
    // slot matches the database (so a rotation that crashed mid-handover still
    // opens). A locked keychain / no matching key is a clean fail-closed exit.
    let store =
        open_sqlite(&descriptor).map_err(|e| ModuleError::Message(format!("open store: {e}")))?;
    EncryptedStore::migrate(&store).map_err(|e| ModuleError::Message(format!("migrate: {e}")))?;
    let key = match EncryptedStore::read_db_key_id(&store)
        .map_err(|e| ModuleError::Message(format!("read db key id: {e}")))?
    {
        Some(db_key_id) => resolver::resolve_for_db(&resolver_config, db_key_id),
        // Brand-new vault (no audit-key row yet): the current slot is the only key.
        None => resolver::resolve(&resolver_config, None),
    }
    .map_err(|e| ModuleError::Message(format!("master key: {e}")))?;

    // Derive the admin-op authority material from the master key BEFORE it is moved
    // into the store: the MAC key (Gate 2's authority root) and this key's non-secret
    // fingerprint (returned in a challenge so the CLI resolves the same key without
    // opening the DB).
    let admin_mac_key = credentials_core::admin_auth::AdminMacKey::derive(&key);
    let admin_key_id = key.key_id();

    let store = EncryptedStore::open(store, key)
        .map_err(|e| ModuleError::Message(format!("open vault: {e}")))?;
    let store = Arc::new(store);

    let http =
        Arc::new(ReqwestTransport::new().map_err(|e| ModuleError::Message(format!("http: {e}")))?);
    let adapters: Vec<Arc<dyn RefreshAdapter>> = vec![
        Arc::new(AnthropicAdapter::new()),
        Arc::new(CursorAdapter::new()),
        Arc::new(DevinAdapter::new()),
        Arc::new(DigitalOceanAdapter::new()),
        Arc::new(OpenAiAdapter::new()),
        // Google defaults to the public gemini-cli client (id + secret) that opencode
        // mints against; CK_GOOGLE_OAUTH_CLIENT_ID / _SECRET override it. No prod env
        // is required for the common case.
        Arc::new(GoogleAdapter::new()),
        Arc::new(SnowflakeAdapter::new()),
        Arc::new(XaiAdapter::new()),
        Arc::new(GithubCopilotAdapter::new()),
        Arc::new(GithubAppAdapter::new()),
        Arc::new(KimiAdapter::new(kimi_device_id)),
        // Antigravity (Google Code-Assist OAuth) — its own public client, distinct
        // from the gemini-cli client the google adapter uses.
        Arc::new(AntigravityAdapter::new()),
    ];
    let engine = Arc::new(RefreshEngine::new(store, adapters, http));

    // THE BOOT GATE: resolve every dangling intent before serving any read.
    //
    // Each outcome names WHY a credential was forced to needs_reauth, and that reason
    // is otherwise unrecoverable: the store's audit entry for these is a generic
    // `invalidate` from actor `vault`, identical whether the adapter had no validity
    // check, ran one and it failed, or the record could not be read. Only the
    // corruption-guard arm writes a distinguishing alarm. So an operator asking why a
    // credential needed re-login after a crash gets no answer unless the reason is
    // recorded here.
    //
    // Written to `auth_events` rather than the chain: the chain already holds the
    // authoritative invalidate, and this is the explanation, which is exactly the
    // split that table exists for. Best-effort -- a diagnostics write must never fail
    // the boot gate, whose job is to resolve intents before serving reads.
    let outcomes = engine
        .reconcile()
        .await
        .map_err(|e| ModuleError::Message(format!("boot reconciliation: {e}")))?;
    record_reconciliation_reasons(&engine, &outcomes);

    // The admin surface shares the engine (same store + per-credential single-flight
    // locks), so a route-driven admin write and a refresh for one credential are
    // serialized by the same lock.
    let admin = admin_surface::AdminSurface::new(
        Arc::clone(&engine),
        admin_mac_key,
        vault_id,
        admin_key_id,
    );
    Ok((
        ReadSurface::new(engine, FetchLimiter::new(Caps::default())),
        admin,
    ))
}

/// Record WHY boot reconciliation forced any credential to `needs_reauth`.
///
/// A free function rather than an inline loop so the boot gate and its test call the
/// SAME code. Written inline first, which made the test pass with the boot gate's copy
/// deleted -- it was exercising its own duplicate, not the daemon's path.
///
/// Best-effort: a diagnostics write must never fail the boot gate, whose job is to
/// resolve dangling intents before any read is served.
fn record_reconciliation_reasons(
    engine: &RefreshEngine,
    outcomes: &[credentials_core::engine::Reconciliation],
) {
    for outcome in outcomes {
        if let credentials_core::engine::Reconciliation::NeedsReauth {
            credential_id,
            reason,
        } = outcome
        {
            let _ = engine.store().record_auth_event(
                credential_id,
                credentials_core::store::AuthObservation {
                    kind: "reconcile_needs_reauth",
                    provider_status: None,
                    detail: Some(reason.as_str()),
                },
                None,
            );
        }
    }
}

/// Drain both egress lanes to the wire, CONTROL-FIRST. On every wakeup, all currently-
/// queued control frames are flushed before any route frame, and `select!` biases toward
/// the control lane — so a health.check reply can never sit behind a backlog of route
/// responses (the liveness guarantee: control egress is not starvable by data traffic).
/// Returns when BOTH lanes are closed (the serve loop dropped its `Egress`).
async fn drain_writer<W>(
    write_half: W,
    mut control_rx: mpsc::Receiver<Frame>,
    mut route_rx: mpsc::Receiver<Frame>,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(write_half);
    let mut control_open = true;
    let mut route_open = true;

    // Write every frame currently queued on a lane without awaiting new arrivals.
    macro_rules! drain_ready {
        ($rx:expr) => {
            while let Ok(frame) = $rx.try_recv() {
                write_frame(&mut writer, &frame)
                    .await
                    .map_err(|e| ModuleError::Message(e.to_string()))?;
            }
        };
    }

    while control_open || route_open {
        // Bias to control: `select!`'s first-listed branch is polled first, and after any
        // wakeup we flush ALL pending control frames before touching the route lane.
        tokio::select! {
            biased;
            maybe = control_rx.recv(), if control_open => match maybe {
                Some(frame) => {
                    write_frame(&mut writer, &frame)
                        .await
                        .map_err(|e| ModuleError::Message(e.to_string()))?;
                    drain_ready!(control_rx);
                }
                None => control_open = false,
            },
            maybe = route_rx.recv(), if route_open => match maybe {
                Some(frame) => {
                    // Control frames that arrived meanwhile jump ahead of this route frame.
                    drain_ready!(control_rx);
                    write_frame(&mut writer, &frame)
                        .await
                        .map_err(|e| ModuleError::Message(e.to_string()))?;
                    // Deliberately NO route-lane drain here: emit ONE route frame per
                    // iteration, then fall back to the biased select so the control
                    // lane is re-polled between every route frame. Draining all ready
                    // route frames in a loop would let a producer that keeps the route
                    // queue non-empty starve control indefinitely — the exact
                    // liveness hole the two-lane split exists to close.
                }
                None => route_open = false,
            },
        }
        writer
            .flush()
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
    }
    writer
        .flush()
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    Ok(())
}

async fn send_hello(
    writer: &mpsc::Sender<Frame>,
    config: &ModuleConfig,
) -> Result<(), ModuleError> {
    let body = serde_json::to_vec(&ModuleHelloBody {
        manifest: manifest(&config.module_id),
        protocol_ver: PROTOCOL_VERSION,
        // Advertise health.check so the daemon actively probes us (capability-
        // gated: unadvertised = health "unknown", never probed). We answer L2
        // through the same channel-0 dispatch and report L3 domain health from a
        // cheap no-decrypt metadata scan.
        control_ops: Some(vec![MODULE_CONTROL_OP_HEALTH_CHECK.to_string()]),
        // Echo the supervisor's launch nonce. This is the module half of the
        // reserved-id ceremony: it proves this process was spawned by the
        // supervisor rather than merely able to complete the handshake.
        //
        // Whether the supervisor ENFORCES that is a property of its config, not of
        // this code -- an id it does not treat as reserved authorizes any HELLO,
        // and the echo is then a key for a lock nobody installed. This module
        // cannot observe which case it is in and must send the nonce either way,
        // so nothing here should be read as evidence that the check happens.
        launch_nonce: config.launch_nonce.clone(),
    })
    .map_err(ModuleError::Json)?;
    // Channel-0 control frames carry the reserved epoch 0 (wire v2 §3.1).
    let frame = Frame::build(FrameType::Hello, control_flags(), 0, 0, HELLO_CORR, body)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn expect_hello_ack<R>(reader: &mut R) -> Result<ModuleHelloAckBody, ModuleError>
where
    R: AsyncRead + Unpin,
{
    let frame = read_frame(reader)
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?
        .ok_or_else(|| ModuleError::Message("connection closed before HELLO_ACK".into()))?;
    match frame.header.ty {
        FrameType::HelloAck => serde_json::from_slice(&frame.body).map_err(ModuleError::Json),
        FrameType::Error => {
            let body =
                serde_json::from_slice::<ErrorBody>(&frame.body).map_err(ModuleError::Json)?;
            Err(ModuleError::Message(format!(
                "subc rejected HELLO: {} — {}",
                body.code, body.message
            )))
        }
        ty => Err(ModuleError::Message(format!(
            "unexpected frame {ty:?} awaiting HELLO_ACK"
        ))),
    }
}

/// Returns `Ok(false)` to stop the loop (graceful goodbye / EOF). Channel-0 control
/// frames (ping/pong, route-bind, health.check) egress on the priority control lane;
/// data-plane route responses egress on the route lane, so control liveness is never
/// starved by route traffic.
async fn handle_frame(
    frame: Frame,
    egress: &Egress,
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    routes: &Arc<RouteEpochs>,
) -> Result<bool, ModuleError> {
    // Wire v2 layer-2 validation (spec §3.3): every nonzero-channel ingress frame
    // is checked against the local route map BEFORE dispatch or any lifecycle
    // effect — Request, Cancel, and Goodbye alike. Epoch mismatch or unknown slot
    // is a SILENT drop (never an Error frame: only the daemon's relay emits
    // unknown_channel; a module-emitted Error would inject into the corr space of
    // the slot's next tenant, the exact confusion the epoch exists to prevent).
    if frame.header.channel != 0 && !routes.matches(frame.header.channel, frame.header.epoch) {
        // Loud here, silent on the wire. First occurrence per (channel, epoch) only: a
        // stale sender loops, and an unbounded write on the ingress path is a lever.
        if routes.note_drop(frame.header.channel, frame.header.epoch) {
            let expected = routes
                .expected(frame.header.channel)
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown-slot".to_string());
            eprintln!(
                "route-epoch drop: channel={} arrived_epoch={} expected={} \
                 (frames for a binding this module does not hold; compare with the \
                 supervisor's live route census -- equal to the live epoch means the \
                 census moved under this check, lower means the sender predates its \
                 own re-bind)",
                frame.header.channel, frame.header.epoch, expected,
            );
        }
        return Ok(true);
    }
    match frame.header.ty {
        FrameType::Ping if frame.header.channel == 0 => {
            let pong = Frame::build_with_version(
                frame.header.ver,
                FrameType::Pong,
                frame.header.flags,
                0,
                0,
                frame.header.corr,
                Vec::new(),
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            send(&egress.control, pong).await?;
            Ok(true)
        }
        FrameType::Goodbye if frame.header.channel == 0 => Ok(false),
        FrameType::Goodbye => {
            // An epoch-valid route goodbye: forget the binding, that connection's
            // limiter state, AND its admin bind state (principal + nonce).
            routes.remove(frame.header.channel);
            surface.drop_connection(frame.header.channel as u64).await;
            admin.drop_bind(frame.header.channel);
            Ok(true)
        }
        FrameType::Request if frame.header.channel == 0 => {
            handle_control_request(frame, &egress.control, surface, admin, routes).await?;
            Ok(true)
        }
        FrameType::Request => {
            // Data-plane request on a route channel: a read op or an admin op. Spawn
            // so a slow refresh/commit never head-of-line-blocks another route. Its
            // response egresses on the route lane, never the control lane.
            let route = egress.route.clone();
            let surface = Arc::clone(surface);
            let admin = Arc::clone(admin);
            // The epoch check above accepted this frame under the current bind. Snapshot
            // that bind's principal before spawning so a later route reuse cannot lend
            // its new principal to an already-accepted request.
            let principal = admin.principal(frame.header.channel);
            tokio::spawn(async move {
                let _ = handle_read_request(frame, &route, &surface, &admin, principal).await;
            });
            Ok(true)
        }
        _ => Ok(true),
    }
}

async fn handle_control_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    routes: &Arc<RouteEpochs>,
) -> Result<(), ModuleError> {
    let request =
        serde_json::from_slice::<ModuleControlRequest>(&frame.body).map_err(ModuleError::Json)?;
    let response_body = match request {
        ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            principal,
            ..
        } => {
            // Wire v2: install the (channel → epoch) binding in the local route map.
            // Installed here — when the accepted ack is being queued — so no route
            // traffic can pass layer-2 validation before the bind is acknowledged
            // (§3.2: module traffic legally begins only after the RouteBind ack).
            routes.install(route_channel, epoch);
            // Record the bind's daemon-stamped principal (Gate 1 provenance) against
            // the route channel, with a fresh generation. An absent principal stamp
            // records as `Unverified` — never `direct` — so admin ops fail closed on
            // an older daemon. Reads remain anonymous/handle-scoped regardless.
            let principal = principal.unwrap_or(subc_protocol::Principal::Unverified);
            admin.record_bind(route_channel, principal);
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // L3 domain health: a cheap no-decrypt metadata scan. `Failing` only
            // when the store is unreadable (real serving inability); a credential
            // needing re-auth is `degraded` detail, never `failing`, so a healthy
            // vault is never restart-flapped.
            health_report(&surface.health_snapshot())
        }
    };
    let body = serde_json::to_vec(&response_body).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        frame.header.ver,
        FrameType::Response,
        control_flags(),
        0,
        0,
        frame.header.corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

/// Map the wire-agnostic core [`VaultHealth`] onto the subc health-report wire
/// shape. Status is the only field subc acts on; `detail`/`metrics` are opaque.
fn health_report(health: &credentials_core::health::VaultHealth) -> ModuleControlResponse {
    use credentials_core::health::VaultHealthStatus;
    let status = match health.status {
        VaultHealthStatus::Ok => HealthStatus::Ok,
        VaultHealthStatus::Degraded => HealthStatus::Degraded,
        VaultHealthStatus::Failing => HealthStatus::Failing,
    };
    let detail = if health.refresher_stalled {
        Some(
            "health refresher stalled: the background snapshot task stopped updating \
             (wedged or panicked); serving a possibly-stale snapshot, restart the daemon"
                .to_string(),
        )
    } else if health.fenced_out {
        Some(
            "fenced out by a newer writer: this daemon lost the single-writer lease \
             (find the other writer)"
                .to_string(),
        )
    } else if !health.store_readable {
        Some("store unreadable: cannot serve any credential (check disk / lease)".to_string())
    } else if health.needs_reauth > 0 || health.corrupt > 0 {
        // Name the affected credentials (ids are non-secret) so the alert is an
        // action, not a lookup. The ids are capped in the snapshot; the counts
        // above remain the true totals.
        let mut affected: Vec<&str> = health.needs_reauth_ids.iter().map(String::as_str).collect();
        affected.extend(health.corrupt_ids.iter().map(String::as_str));
        Some(format!(
            "{} of {} credentials need operator action ({} needs_reauth, {} corrupt); \
             {} serving [{}]",
            health.needs_reauth + health.corrupt,
            health.credentials_total,
            health.needs_reauth,
            health.corrupt,
            health.active,
            affected.join(", "),
        ))
    } else {
        None
    };
    // The counts are OMITTED when the store could not be read, rather than reported as
    // zero.
    //
    // Zero is what an empty vault reports, so a consumer plotting `active` cannot tell
    // "no credentials" from "could not count credentials" and draws a clean line either
    // way. The provenance is available -- `storeReadable` is false in the same object,
    // and `detail` names the reason -- but that requires the consumer to correlate two
    // fields, and nothing makes it. Omission does: a field that is absent cannot be
    // plotted as a value, so the bad reading becomes impossible instead of merely
    // avoidable.
    //
    // The flags stay present in both cases, because they are measurements about the
    // daemon rather than about the store, and they remain true when the store is
    // unreadable.
    let mut metrics = json!({
        "storeReadable": health.store_readable,
        "fencedOut": health.fenced_out,
        "refresherStalled": health.refresher_stalled,
    });
    if health.store_readable {
        let counted = json!({
            "credentialsTotal": health.credentials_total,
            "active": health.active,
            "needsReauth": health.needs_reauth,
            "retired": health.retired,
            "corrupt": health.corrupt,
            "needsReauthIds": health.needs_reauth_ids,
            "retiredIds": health.retired_ids,
            "corruptIds": health.corrupt_ids,
            "openIntents": health.open_intents,
        });
        if let (Some(target), Some(source)) = (metrics.as_object_mut(), counted.as_object()) {
            for (k, v) in source {
                target.insert(k.clone(), v.clone());
            }
        }
        // The witness needs the sequence and the row MAC as one atomic observation.
        // Omitting either half would let a sequence-only comparison miss a truncated
        // tail that was replaced by fresh legitimate appends at the same sequence.
        if let (Some(seq), Some(entry_mac)) = (&health.audit_seq, &health.audit_tip_mac) {
            if let Some(target) = metrics.as_object_mut() {
                target.insert("auditSeq".to_string(), json!(seq));
                target.insert("auditTipMac".to_string(), json!(entry_mac));
            }
        }
    }
    ModuleControlResponse::HealthCheck {
        status,
        detail,
        metrics: Some(metrics),
    }
}

/// A read-surface request body: `{ "method": "...", "params": { ... } }`.
#[derive(Debug, Deserialize)]
struct ReadRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// The `admin.op` request params: the EXACT authenticated op-body bytes (as a JSON
/// string, so the byte string the caller MAC'd survives the outer envelope verbatim)
/// plus the caller's transcript MAC.
#[derive(Debug, Deserialize)]
struct AdminOpParams {
    /// The op body EXACTLY as MAC'd, carried as a string so no JSON re-encoding on
    /// the outer envelope can perturb the authenticated bytes.
    op_body: String,
    tag_hex: String,
}

async fn handle_read_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    surface: &Arc<ReadSurface>,
    admin: &Arc<admin_surface::AdminSurface>,
    principal: Option<subc_protocol::Principal>,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    // Echo the validated ingress epoch on every frame of this route (wire v2:
    // a response must carry the epoch of the binding it answers for).
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;
    let connection_id = channel as u64;

    let request: ReadRequest = match serde_json::from_slice(&frame.body) {
        Ok(r) => r,
        Err(e) => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "invalid_request",
                &format!("request body not decodable: {e}"),
            )
            .await;
        }
    };

    let result = match request.method.as_str() {
        OP_GET => match serde_json::from_value::<GetParams>(request.params) {
            Ok(p) => json!({ "result": surface.get(connection_id, &p).await }),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_GET_SCOPED => match serde_json::from_value::<GetScopedParams>(request.params) {
            Ok(p) => json!({ "result": surface.get_scoped(principal.as_ref(), &p).await }),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_GET_MANY => match serde_json::from_value::<GetManyParams>(request.params) {
            Ok(p) => json!({ "results": surface.get_many(connection_id, &p).await }),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_SIGN => match serde_json::from_value::<read_surface::SignParams>(request.params) {
            Ok(p) if p.has_exactly_one_authorization() => {
                match surface.sign(connection_id, principal.as_ref(), &p).await {
                    Ok(r) => json!({ "result": r }),
                    // Same { code, class } shape every other op uses, so a consumer
                    // branches on the produced class here too.
                    Err(code) => json!({
                        "result": { "error": read_surface::ErrorBody { code, class: code.class() } }
                    }),
                }
            }
            Ok(_) => {
                return invalid_params(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "credential.sign requires exactly one of handle or credential_id",
                )
                .await
            }
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_PUBLIC_KEY => match serde_json::from_value::<PublicKeyParams>(request.params) {
            Ok(p) if p.has_exactly_one_authorization() => {
                match surface
                    .public_key(connection_id, principal.as_ref(), &p)
                    .await
                {
                    Ok(r) => json!({ "result": r }),
                    Err(code) => json!({
                        "result": { "error": read_surface::ErrorBody { code, class: code.class() } }
                    }),
                }
            }
            Ok(_) => {
                return invalid_params(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "credential.public_key requires exactly one of handle or credential_id",
                )
                .await
            }
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_STATUS => match serde_json::from_value::<StatusParams>(request.params) {
            Ok(p) => json!({ "result": surface.status(connection_id, &p).await }),
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        OP_REPORT_AUTH_FAILURE => {
            match serde_json::from_value::<ReportAuthFailureParams>(request.params) {
                Ok(p) => match surface.report_auth_failure(connection_id, &p).await {
                    Ok(()) => json!({ "result": { "accepted": true } }),
                    // Carry the produced error CLASS alongside the code (error-class
                    // contract), the same { code, class } shape get/get_many use, so a
                    // consumer branches on the class here too rather than on the code.
                    Err(code) => json!({
                        "result": {
                            "accepted": false,
                            "error": read_surface::ErrorBody { code, class: code.class() }
                        }
                    }),
                },
                Err(e) => {
                    return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
                }
            }
        }
        OP_ADMIN_CHALLENGE => match admin.challenge(channel) {
            admin_surface::AdminOutcome::Challenge {
                nonce_hex,
                vault_id_hex,
                key_id_hex,
            } => json!({ "result": {
                "nonce_hex": nonce_hex,
                "vault_id_hex": vault_id_hex,
                "key_id_hex": key_id_hex,
            }}),
            admin_surface::AdminOutcome::Refused(reason) => {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "admin_refused",
                    &reason,
                )
                .await;
            }
            // challenge() only ever returns Challenge or Refused.
            admin_surface::AdminOutcome::Ok(_) => unreachable!("challenge returns Challenge"),
        },
        OP_ADMIN_OP => match serde_json::from_value::<AdminOpParams>(request.params) {
            Ok(p) => match admin
                .execute(channel, p.op_body.as_bytes(), &p.tag_hex)
                .await
            {
                admin_surface::AdminOutcome::Ok(v) => json!({ "result": v }),
                admin_surface::AdminOutcome::Refused(reason) => {
                    return send_route_error(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        "admin_refused",
                        &reason,
                    )
                    .await;
                }
                admin_surface::AdminOutcome::Challenge { .. } => {
                    unreachable!("execute never returns Challenge")
                }
            },
            Err(e) => {
                return invalid_params(writer, ver, channel, epoch, corr, &e.to_string()).await
            }
        },
        other => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "unknown_method",
                &format!("unknown method '{other}'"),
            )
            .await;
        }
    };

    let body = serde_json::to_vec(&result).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        ver,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

async fn invalid_params(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    detail: &str,
) -> Result<(), ModuleError> {
    send_route_error(
        writer,
        ver,
        channel,
        epoch,
        corr,
        "invalid_params",
        &format!("params not decodable: {detail}"),
    )
    .await
}

async fn send_route_error(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    code: &str,
    message: &str,
) -> Result<(), ModuleError> {
    // ErrorBody::new rather than a struct literal: detail is None here deliberately,
    // and the constructor keeps a future required field from silently defaulting.
    //
    // NO DETAIL ON THIS PATH, and that is a decision rather than an omission. These
    // are transport-level refusals (malformed frame, unknown operation), whose remedy
    // is fully carried by the code. The vault's READ-surface errors are the ones a
    // consumer branches on, and they already carry their machine-parsable half as the
    // `class` field inside the result body per the fleet error-class contract --
    // moving that into `detail` would fork one contract across two wire locations.
    //
    // If a refusal here ever needs more than a code, it must not carry secrets:
    // handle values, credential payloads and key material are all out of bounds, and
    // an error body is exactly where they would look harmless.
    let body = serde_json::to_vec(&ErrorBody::new(code, message)).map_err(ModuleError::Json)?;
    let frame = Frame::build_with_version(
        ver,
        FrameType::Error,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn send(writer: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), ModuleError> {
    writer
        .send(frame)
        .await
        .map_err(|_| ModuleError::Message("egress channel closed".into()))
}

fn control_flags() -> Flags {
    Flags::new(false, Priority::Passive, false)
}

/// The data directory the vault lives in (the parent of the sqlite store path), so
/// the master-key resolver can enforce the operator key path is outside it.
fn sqlite_data_dir(descriptor: &StorageDescriptor) -> Result<PathBuf, ModuleError> {
    use cortexkit_store::StorageBackend;
    match &descriptor.backend {
        StorageBackend::Sqlite { path } => Ok(PathBuf::from(path)
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))),
        other => Err(ModuleError::Message(format!(
            "credential vault requires a sqlite backend, got {}",
            other.label()
        ))),
    }
}

/// Resolve the master-key source from the environment: an operator key path
/// (`CK_MASTER_KEY_PATH`, headless) takes precedence; otherwise the macOS keychain
/// (the desktop default) with fixed service/account strings.
fn resolver_config_from_env(data_dir: PathBuf) -> ResolverConfig {
    let source = if let Some(path) = std::env::var_os("CK_MASTER_KEY_PATH") {
        KeySource::OperatorPath {
            path: PathBuf::from(path),
        }
    } else {
        // Fieldless: the keychain item is scoped per-vault by the data dir inside the
        // backend (contract::keychain_service_for), identical to the CLI's derivation.
        KeySource::Keychain
    };
    ResolverConfig { data_dir, source }
}

/// The module's capability manifest: a ManagementSurface exposing its read
/// operations. Storage is `owns_schema: true` (the vault owns its schema). The
/// `reserved: true` binding lives in the daemon's subc.jsonc config, not here; the
/// module proves its reserved identity by echoing the launch nonce in HELLO.
fn manifest(module_id: &str) -> ModuleManifest {
    // `capabilities: None` is DELIBERATE, not an unfilled field.
    //
    // The protocol defines it as `Option<CapabilityDeclarations>` and states that
    // omitting the block preserves the manifest contract used before capability
    // grammar existed. A present block is static discovery metadata the daemon
    // validates before accepting a HELLO, so declaring one is an opt-in that changes
    // what the supervisor checks about this module. That should be a decision, not a
    // field filled in to clear a compile error.
    //
    // WHAT WOULD MAKE IT WORTH DECLARING: a consumer that must discover this vault's
    // route surface statically, before binding, instead of learning it from a refusal.
    // Nothing does today. Every consumer here is configured with the credential ids or
    // handles it needs, and the read surface is deliberately anonymous, so a discovery
    // block would publish a menu no caller asked for.
    ModuleManifest {
        module_id: module_id.to_string(),
        module_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_ver: PROTOCOL_VERSION,
        trust_tier: TrustTier::FirstParty,
        capabilities: None,
        // `provenance` carries the ONE fact this build actually knows about itself.
        //
        // The protocol's four fields are build_git_sha, build_lock_digest,
        // wire_crate_version and store_schema_version, each optional, validated for shape
        // only (non-empty, <=128 bytes, printable ASCII). So the constraint on filling
        // them is honesty rather than syntax, and a value invented to look complete is
        // worse than an absent one: a supervisor comparing provenance across a fleet
        // treats a present field as a claim.
        //
        // WHAT IS DECLARED:
        //   build_git_sha        from the same `BUILD_REV` that `--version` reports.
        //                        `scripts/release-build.sh` stamps CK_BUILD_REV from a
        //                        clean tree; an unstamped development build reports
        //                        "unknown", and the block is omitted rather than publish
        //                        a placeholder wearing the shape of a sha.
        //   wire_crate_version   `SUBC_PROTOCOL_CRATE_VERSION`, which subc-protocol bakes
        //                        in from its own `env!("CARGO_PKG_VERSION")`
        //                        (subc-protocol/src/lib.rs:133). It names the wire crate
        //                        compiled INTO this binary, so unlike a hand-copied string
        //                        it cannot drift from what it names. Distinct from
        //                        `module_version` above, which is this module's own
        //                        version and says nothing about the wire it speaks.
        //
        // WHAT IS NOT, and why each is absent rather than forgotten:
        //   build_lock_digest    nothing hashes Cargo.lock at build time today. Adding
        //                        it is a release-script change, not a manifest one.
        //   store_schema_version the contract asks for the newest MIGRATION version
        //                        (manifest.rs: "any module with a migration list can state
        //                        its newest migration as fact"), and `MIGRATIONS` is
        //                        private to credentials-core with no public accessor.
        //                        `RECORD_SCHEMA_VERSION` IS public and tempting, but it
        //                        names the encrypted record BODY schema -- a different
        //                        domain that currently reads 1 while the newest migration
        //                        is 6. Filling the field from it would be a WELL-FORMED
        //                        value from the WRONG DOMAIN: shape validation cannot
        //                        catch it, and it is worse than absence because a present
        //                        field stops the reader asking.
        provenance: {
            let rev = credentials_core::contract::BUILD_REV;
            (rev != "unknown").then(|| ManifestProvenance {
                build_git_sha: Some(rev.to_string()),
                build_lock_digest: None,
                wire_crate_version: Some(SUBC_PROTOCOL_CRATE_VERSION.to_string()),
                store_schema_version: None,
            })
        },
        provides: vec![ProviderRole::ManagementSurface {
            // ModuleManaged, and this is a claim about observed behaviour rather than
            // the value that compiles. All three would.
            //
            // NOT Serial: one in-flight call at a time would be a lie and an
            // expensive one. A `get` that triggers an OAuth refresh blocks on a
            // provider's token endpoint for hundreds of milliseconds, and every other
            // consumer's read of an unrelated credential would queue behind it.
            //
            // NOT StatelessParallel: this surface has ordering-sensitive state.
            // Credential-scoped admin mutations serialize under
            // RefreshEngine::with_admin_lock so they cannot interleave with a refresh
            // of the same credential, and concurrent gets on one credential are
            // coalesced by the engine's per-credential single-flight lock rather than
            // each firing its own token exchange.
            //
            // ModuleManaged says exactly what is true: calls may arrive concurrently
            // across channels, and THIS MODULE decides what may overlap -- which it
            // does per credential id, not per connection.
            //
            // BOTH HALVES OF THE CLAIM REST ON TESTS RATHER THAN ON THIS COMMENT,
            // in credentials-core/src/engine_tests.rs:
            //
            //   `concurrent_gets_single_flight_one_upstream_call` -- the module
            //   schedules internally: concurrent gets on ONE credential produce
            //   exactly ONE upstream token exchange. Delete the coalescing and each
            //   caller fires its own refresh, so the module schedules nothing.
            //
            //   `refreshes_on_different_credentials_overlap_rather_than_serialising`
            //   -- calls may overlap ACROSS credentials. Key the single-flight map
            //   globally instead of per credential and this surface is secretly
            //   Serial; the first test still passes, because it never touches a
            //   second credential.
            //
            // The second test was missing until 2026-08-16, so half of this
            // declaration was decoration. Both are proofs by construction: one counts
            // upstream calls, the other blocks each refresh on a two-party barrier so
            // a serialising engine HANGS rather than passing slowly.
            //
            // DECLARING IT EXPLICITLY CHANGES NOTHING ON THE WIRE TODAY, and that is
            // worth knowing before someone treats a protocol bump as deploy pressure.
            // `ManagementSurface.concurrency` carries `#[serde(default)]` upstream and
            // `Default for Concurrency` is `ModuleManaged`, so a daemon built before the
            // field existed registers with the same value this line states. Checked at
            // source 2026-08-16 against subc-protocol 0.12 (ToolProvider has NO default
            // -- new roles must declare it; only the pre-existing shape is defaulted).
            //
            // So an older deployed vault is safe across a supervisor upgrade: it neither
            // fails to register nor gets a different concurrency contract. The value of
            // saying it out loud is that the manifest stops depending on an upstream
            // default staying what it is.
            concurrency: Concurrency::ModuleManaged,
            operations: vec![
                ManagementOperation {
                    name: OP_GET.to_string(),
                    description: Some("Serve a credential's secret bytes to the holder of a capability handle. Refuses signing keys.".to_string()),
                    kind: ManagementOperationKind::Query,
                },
                ManagementOperation {
                    name: OP_GET_SCOPED.to_string(),
                    description: Some("Serve a credential's secret bytes by id to a reserved principal holding a read grant. Refuses signing keys.".to_string()),
                    kind: ManagementOperationKind::Query,
                },
                ManagementOperation {
                    name: OP_GET_MANY.to_string(),
                    description: Some("Serve a capped batch of handle-addressed credentials, refusing the whole batch past the cap.".to_string()),
                    kind: ManagementOperationKind::Query,
                },
                ManagementOperation {
                    name: OP_STATUS.to_string(),
                    description: Some("Report a credential's non-secret readiness and record version. Never returns bytes.".to_string()),
                    kind: ManagementOperationKind::Query,
                },
                // Query rather than Mutation: signing reads a stored key and returns a
                // derived value, changing NO vault state -- no version bump, no audit
                // mutation, nothing to reconcile after a crash. The authority it
                // exercises is real, but authority and mutation are different axes and
                // the manifest kind describes the second.
                ManagementOperation {
                    name: OP_SIGN.to_string(),
                    description: Some("Sign caller-supplied bytes with a stored signing key. The key never leaves the vault.".to_string()),
                    kind: ManagementOperationKind::Query,
                },
                // Query rather than Mutation for the same reason as `credential.sign`:
                // this derives public bytes from a stored key without writing a record
                // or appending to the audit chain, so callers may publish on demand.
                ManagementOperation {
                    name: OP_PUBLIC_KEY.to_string(),
                    description: Some("Return a signing key's public half. Never returns private material.".to_string()),
                    kind: ManagementOperationKind::Query,
                },
                ManagementOperation {
                    name: OP_REPORT_AUTH_FAILURE.to_string(),
                    description: Some("Accept a consumer's report that a served token was refused, at the version it was served.".to_string()),
                    kind: ManagementOperationKind::Mutate,
                },
            ],
            config_schema: json!({ "type": "object" }),
            observability: Vec::new(),
            identity_scope: Vec::new(),
        }],
        consumes: Vec::new(),
        bindings: Bindings {
            storage: StorageBinding {
                kind: StorageKind::Sqlite,
                scope: StorageScope::Project,
                owns_schema: true,
            },
            vault_grants: Vec::new(),
            identity: IdentityBinding {
                requires: Vec::new(),
                optional: Vec::new(),
            },
        },
    }
}

fn parse_subc_arg(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, ModuleError> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--subc" {
            let value = args
                .next()
                .ok_or_else(|| ModuleError::Message("--subc requires a value".into()))?;
            return Ok(PathBuf::from(value));
        }
        if let Some(raw) = arg.to_str().and_then(|a| a.strip_prefix("--subc=")) {
            if raw.is_empty() {
                return Err(ModuleError::Message("--subc= requires a value".into()));
            }
            return Ok(PathBuf::from(raw));
        }
    }
    Err(ModuleError::Message(
        "--subc <connection-file> is required".into(),
    ))
}

#[derive(Debug)]
enum ModuleError {
    Message(String),
    Json(serde_json::Error),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(m) => write!(f, "{m}"),
            Self::Json(e) => write!(f, "json: {e}"),
        }
    }
}

impl std::error::Error for ModuleError {}

#[cfg(test)]
mod tests {
    /// This daemon declares NO consumer role, and that is a security property rather
    /// than an empty field nobody filled in.
    ///
    /// `consumes: Vec::new()` is the machine-checkable half of a boundary held with
    /// cerebellum: nothing pushes plaintext into their context, because this module
    /// never initiates an outbound call at all. It is also why this seat is immune to
    /// the retained-dead-connection class the supervisor censused in August — with no
    /// requester role there is no reply-deadline to expire and no connection object to
    /// retain past one.
    ///
    /// THE GUARANTEE ENDS SILENTLY THE DAY THIS DAEMON GAINS ITS FIRST OUTBOUND CALL,
    /// with nothing in the diff looking like a boundary change: a consumer role added
    /// for an unrelated feature would quietly falsify both properties at once. The
    /// capability grammar cannot assert this yet, so the pin lives here until it can.
    ///
    /// If you are adding a consumer role deliberately: this test failing is the
    /// intended alarm. Read the two properties above, decide whether they still hold,
    /// and tell the cerebellum and supervisor seats before changing the expectation.
    #[test]
    fn the_manifest_declares_no_consumer_role_because_nothing_may_be_pushed_outward() {
        let manifest = super::manifest("claustrum");
        assert!(
            manifest.consumes.is_empty(),
            "claustrum must consume no roles: an outbound call would break both the \
             no-plaintext-outward boundary with cerebellum and the immune-by-role-shape \
             property the supervisor's connection census depends on. Found: {:?}",
            manifest.consumes
        );
    }

    use super::*;
    use cortexkit_store::{Isolation, StorageBackend};
    use credentials_core::audit::{AuditCtx, AuditOp, AuditRecord};
    use credentials_core::key::{MasterKey, MASTER_KEY_LEN};
    use credentials_core::oauth::OAuthCredential;
    use credentials_core::record::{CredentialKind, VaultRecord};
    use credentials_core::store::{GrantOperation, RecordState};
    use read_surface::ReadSurface;

    fn tmp_surface(seed: u8) -> Arc<ReadSurface> {
        tmp_surface_with_store(seed).0
    }

    /// Boot reconciliation's REASON survives as a durable row.
    ///
    /// The engine already returns why each dangling intent forced `needs_reauth`, and
    /// its own tests assert that. What was missing is that the module DISCARDED the
    /// value: the store's audit entry for these is a generic `invalidate` from actor
    /// `vault`, identical across every cause, so after a crash an operator could see
    /// that a credential needed re-login and never why.
    ///
    /// This drives the boot-gate sequence and asserts the reason lands. Written
    /// against the same call the daemon makes, because the defect was never in the
    /// engine -- it was at the call site.
    #[tokio::test]
    async fn boot_reconciliation_records_why_a_credential_needs_reauth() {
        let (_, store, _) = tmp_surface_with_store(71);
        let record = VaultRecord::new_oauth(
            "test",
            "stub",
            credentials_core::oauth::OAuthCredential {
                access_token: "at".into(),
                refresh_token: "rt".into(),
                expires_at_ms: Some(0),
                token_url: "https://example.invalid/token".into(),
                client_id: None,
                scopes: Vec::new(),
            },
            b"payload".to_vec(),
        );
        store.create("apikey:crashed", &record).expect("create");
        let hash = credentials_core::store::refresh_token_hash("rt");
        store
            .open_intent("apikey:crashed", 1, &hash)
            .expect("open intent");

        let http = Arc::new(ReqwestTransport::new().expect("http"));
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));

        // The daemon's own boot-gate sequence: reconcile, then record. Calls the same
        // function `build_surface` calls -- an inline copy here would pass with the
        // daemon's recording deleted, which is exactly what it did before this was
        // extracted.
        let outcomes = engine.reconcile().await.expect("reconcile");
        record_reconciliation_reasons(&engine, &outcomes);

        let events = store.recent_auth_events(10).expect("read events");
        assert_eq!(events.len(), 1, "the reconciliation must leave a row");
        assert_eq!(events[0].credential_id, "apikey:crashed");
        assert_eq!(events[0].kind, "reconcile_needs_reauth");
        assert_eq!(
            events[0].detail.as_deref(),
            Some("no_validity_check"),
            "the row must carry WHY, which is the whole point -- the audit chain's \
             entry for this is a generic invalidate that cannot distinguish causes"
        );
    }

    /// A test AdminSurface over the same engine/store shape as tmp_surface, with a
    /// known master key (seed) so tests can derive the same MAC key caller-side.
    fn tmp_admin(seed: u8) -> (Arc<admin_surface::AdminSurface>, Arc<EncryptedStore>) {
        let (_, store, db_path) = tmp_surface_with_store(seed);
        let http = Arc::new(ReqwestTransport::new().expect("http"));
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        let mac_key = credentials_core::admin_auth::AdminMacKey::derive(&key);
        let vault_id =
            credentials_core::vault_id_for(db_path.parent().expect("db dir")).expect("vault id");
        let admin = Arc::new(admin_surface::AdminSurface::new(
            engine,
            mac_key,
            vault_id,
            key.key_id(),
        ));
        (admin, store)
    }

    fn tmp_surface_with_store(
        seed: u8,
    ) -> (Arc<ReadSurface>, Arc<EncryptedStore>, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ck-cred-health-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("mkdir");
        let db_path = root.join("store.db");
        let descriptor = StorageDescriptor {
            module_id: "cortexkit-credentials".into(),
            storage_namespace: "default".into(),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: db_path.to_string_lossy().into_owned(),
            },
        };
        let store = open_sqlite(&descriptor).expect("open");
        EncryptedStore::migrate(&store).expect("migrate");
        let store = EncryptedStore::open(store, MasterKey::from_bytes([seed; MASTER_KEY_LEN]))
            .expect("open vault");
        // Seed one active + one needs_reauth so health is Degraded (never Failing).
        store
            .create(
                "apikey:active",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create active");
        store
            .create(
                "apikey:dead",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create dead");
        store.invalidate("apikey:dead").expect("invalidate");

        let store = Arc::new(store);
        let http = Arc::new(ReqwestTransport::new().expect("http"));
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
        let surface = Arc::new(ReadSurface::new(engine, FetchLimiter::new(Caps::default())));
        (surface, store, db_path)
    }

    /// A deterministic refresh adapter for minimum-TTL read tests. Its counter proves
    /// the read path performed one exchange, not merely that a stored version changed.
    struct TtlFixtureAdapter {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        fresh_ttl_ms: i64,
    }

    #[async_trait::async_trait]
    impl credentials_core::refresh_adapters::RefreshAdapter for TtlFixtureAdapter {
        fn name(&self) -> &str {
            "ttl-fixture"
        }

        async fn refresh(
            &self,
            credential: &credentials_core::oauth::OAuthCredential,
            _http: &dyn credentials_core::refresh_adapters::HttpTransport,
        ) -> Result<
            credentials_core::refresh_adapters::RefreshedTokens,
            credentials_core::refresh_adapters::RefreshError,
        > {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(credentials_core::refresh_adapters::RefreshedTokens {
                access_token: "fresh-after-ttl-check".into(),
                refresh_token: credential.refresh_token.clone(),
                expires_at_ms: Some(test_now_ms().saturating_add(self.fresh_ttl_ms)),
                github_app_permissions: None,
            })
        }
    }

    fn test_now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }

    fn ttl_surface(
        seed: u8,
        fresh_ttl_ms: i64,
    ) -> (
        Arc<ReadSurface>,
        Arc<EncryptedStore>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let (_unused_surface, store, _db_path) = tmp_surface_with_store(seed);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let adapter = TtlFixtureAdapter {
            calls: Arc::clone(&calls),
            fresh_ttl_ms,
        };
        let http = Arc::new(ReqwestTransport::new().expect("http"));
        let engine = Arc::new(RefreshEngine::new(
            Arc::clone(&store),
            vec![Arc::new(adapter)],
            http,
        ));
        let surface = Arc::new(ReadSurface::new(engine, FetchLimiter::new(Caps::default())));
        (surface, store, calls)
    }

    fn seed_ttl_refreshable(
        store: &EncryptedStore,
        credential_id: &str,
        initial_ttl_ms: i64,
    ) -> String {
        store
            .create(
                credential_id,
                &VaultRecord::new_oauth(
                    "test",
                    "ttl-fixture",
                    credentials_core::oauth::OAuthCredential {
                        access_token: "stored-before-refresh".into(),
                        refresh_token: "refresh-token".into(),
                        expires_at_ms: Some(test_now_ms().saturating_add(initial_ttl_ms)),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        scopes: Vec::new(),
                    },
                    b"stored-before-refresh".to_vec(),
                ),
            )
            .expect("seed refreshable credential");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");
        handle.raw
    }

    fn seed_ttl_static(store: &EncryptedStore, credential_id: &str) -> String {
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    b"static-before-refresh".to_vec(),
                    Some(test_now_ms().saturating_add(10 * 60 * 1000)),
                ),
            )
            .expect("seed static credential");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");
        handle.raw
    }

    /// A post-refresh lifetime that still misses the caller's demand is a request bound,
    /// not a dead credential. The counter makes a second exchange observable: a retry loop
    /// would return the same refusal but increment it twice.
    #[tokio::test]
    async fn impossible_min_ttl_refuses_after_one_exchange_with_paired_wire_error() {
        const INITIAL_TTL_MS: i64 = 10 * 60 * 1000;
        const FRESH_TTL_MS: i64 = 60 * 60 * 1000;
        const DEMAND_MS: i64 = 2 * 60 * 60 * 1000;

        let (surface, store, calls) = ttl_surface(91, FRESH_TTL_MS);
        let handle = seed_ttl_refreshable(&store, "oauth:ttl-unsatisfiable", INITIAL_TTL_MS);
        let outcome = surface
            .get(
                91,
                &GetParams {
                    handle,
                    min_ttl_ms: Some(DEMAND_MS),
                    force_refresh: false,
                },
            )
            .await;

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an unsatisfiable demand must make exactly one upstream exchange"
        );
        assert_eq!(
            serde_json::to_value(&outcome).expect("serialize refusal"),
            serde_json::json!({
                "error": {
                    "code": "ttl_unsatisfiable",
                    "class": "context_overflow",
                }
            }),
            "the wire must carry the refusal detail and class together"
        );
        let read_surface::GetOutcome::Err { error } = outcome else {
            panic!("a fresh token shorter than the demand must refuse");
        };
        assert_eq!(error.code, read_surface::ReadError::TtlUnsatisfiable);
        assert_eq!(error.class, read_surface::ErrorClass::ContextOverflow);
    }

    /// A missing `min_ttl_ms` states no requirement. This is intentionally the same
    /// credential shape as the refusal test so a default floor cannot hide behind a
    /// different record type or expiry.
    #[tokio::test]
    async fn absent_min_ttl_does_not_apply_a_default_floor() {
        let (surface, store, calls) = ttl_surface(92, 60 * 60 * 1000);
        let handle = seed_ttl_refreshable(&store, "oauth:ttl-absent", 10 * 60 * 1000);
        let outcome = surface
            .get(
                92,
                &GetParams {
                    handle,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;

        let read_surface::GetOutcome::Ok(result) = outcome else {
            panic!("a request without a demand must serve the stored token");
        };
        assert_eq!(result.payload, b"stored-before-refresh");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an absent demand must not supply an implicit refresh floor"
        );
    }

    #[tokio::test]
    async fn satisfiable_min_ttl_serves_the_fresh_token() {
        let (surface, store, calls) = ttl_surface(93, 60 * 60 * 1000);
        let handle = seed_ttl_refreshable(&store, "oauth:ttl-satisfiable", 10 * 60 * 1000);
        let outcome = surface
            .get(
                93,
                &GetParams {
                    handle,
                    min_ttl_ms: Some(30 * 60 * 1000),
                    force_refresh: false,
                },
            )
            .await;

        let read_surface::GetOutcome::Ok(result) = outcome else {
            panic!("a fresh token that meets the demand must be served");
        };
        assert_eq!(result.payload, b"fresh-after-ttl-check");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the caller's minimum-TTL demand must trigger one refresh"
        );
    }

    /// A static record cannot produce the required fresh-token proof. Even a huge demand
    /// must therefore retain the read surface's existing serve-as-stored behavior.
    #[tokio::test]
    async fn static_credential_with_oversized_min_ttl_is_served_without_a_refusal() {
        let (surface, store, calls) = ttl_surface(94, 60 * 60 * 1000);
        let handle = seed_ttl_static(&store, "apikey:ttl-static");
        let outcome = surface
            .get(
                94,
                &GetParams {
                    handle,
                    min_ttl_ms: Some(2 * 60 * 60 * 1000),
                    force_refresh: false,
                },
            )
            .await;

        let read_surface::GetOutcome::Ok(result) = outcome else {
            panic!("a static credential must not refuse without an exchange");
        };
        assert_eq!(result.payload, b"static-before-refresh");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a static credential has no exchange path to prove the demand impossible"
        );
    }

    #[tokio::test]
    async fn get_many_keeps_a_ttl_refusal_in_its_item_position() {
        let (surface, store, calls) = ttl_surface(95, 60 * 60 * 1000);
        let short_lived = seed_ttl_refreshable(&store, "oauth:ttl-batch", 10 * 60 * 1000);
        let ordinary = seed_ttl_static(&store, "apikey:ttl-batch");
        let outcomes = surface
            .get_many(
                95,
                &GetManyParams {
                    items: vec![
                        GetParams {
                            handle: short_lived,
                            min_ttl_ms: Some(2 * 60 * 60 * 1000),
                            force_refresh: false,
                        },
                        GetParams {
                            handle: ordinary,
                            min_ttl_ms: None,
                            force_refresh: false,
                        },
                    ],
                },
            )
            .await;

        assert_eq!(
            outcomes.len(),
            2,
            "one item refusal must not collapse the batch"
        );
        let read_surface::GetOutcome::Err { error } = &outcomes[0] else {
            panic!("the first item must retain its TTL refusal");
        };
        assert_eq!(error.code, read_surface::ReadError::TtlUnsatisfiable);
        assert_eq!(error.class, read_surface::ErrorClass::ContextOverflow);
        let read_surface::GetOutcome::Ok(result) = &outcomes[1] else {
            panic!("the later ordinary item must keep its position and serve");
        };
        assert_eq!(result.payload, b"static-before-refresh");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "only the short-lived batch item may exchange"
        );
    }

    /// Build a scoped-read rig whose route-bind registry and read surface share one
    /// store. The route helper below drives the real request dispatcher rather than
    /// calling `get_scoped` directly, so the principal snapshot is part of the proof.
    fn scoped_rig(
        seed: u8,
    ) -> (
        Arc<ReadSurface>,
        Arc<admin_surface::AdminSurface>,
        Arc<EncryptedStore>,
    ) {
        let (surface, store, db_path) = tmp_surface_with_store(seed);
        let http = Arc::new(ReqwestTransport::new().expect("http"));
        let engine = Arc::new(RefreshEngine::new(Arc::clone(&store), Vec::new(), http));
        let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
        let mac_key = credentials_core::admin_auth::AdminMacKey::derive(&key);
        let vault_id =
            credentials_core::vault_id_for(db_path.parent().expect("db dir")).expect("vault id");
        let admin = Arc::new(admin_surface::AdminSurface::new(
            engine,
            mac_key,
            vault_id,
            key.key_id(),
        ));
        (surface, admin, store)
    }

    async fn scoped_route_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        method: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        let (writer, mut responses) = mpsc::channel(1);
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            1,
            1,
            serde_json::to_vec(&json!({
                "method": method,
                "params": params,
            }))
            .expect("encode request"),
        )
        .expect("build request");
        let principal = admin.principal(channel);
        handle_read_request(frame, &writer, surface, admin, principal)
            .await
            .expect("serve request");
        let response = responses.recv().await.expect("route response");
        serde_json::from_slice(&response.body).expect("decode response")
    }

    async fn scoped_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        credential_id: &str,
    ) -> serde_json::Value {
        scoped_route_request(
            surface,
            admin,
            channel,
            OP_GET_SCOPED,
            json!({ "credential_id": credential_id }),
        )
        .await
    }

    async fn scoped_sign_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        credential_id: &str,
        payload_b64: &str,
    ) -> serde_json::Value {
        scoped_route_request(
            surface,
            admin,
            channel,
            OP_SIGN,
            json!({ "credential_id": credential_id, "payload_b64": payload_b64 }),
        )
        .await
    }

    async fn scoped_public_key_request(
        surface: &Arc<ReadSurface>,
        admin: &Arc<admin_surface::AdminSurface>,
        channel: u16,
        credential_id: &str,
    ) -> serde_json::Value {
        scoped_route_request(
            surface,
            admin,
            channel,
            OP_PUBLIC_KEY,
            json!({ "credential_id": credential_id }),
        )
        .await
    }

    fn assert_scoped_not_found(body: &serde_json::Value) {
        assert_eq!(body["result"]["error"]["code"], "not_found");
        assert_eq!(body["result"]["error"]["class"], "permanent");
    }

    #[tokio::test]
    async fn scoped_get_serves_a_covered_credential_and_does_not_audit_the_read() {
        let (surface, admin, store) = scoped_rig(72);
        store
            .create(
                "github_app:fleet-a",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "github_app:fleet-a",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store handle");
        admin.record_bind(
            41,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let normal = serde_json::to_value(
            surface
                .get(
                    42,
                    &GetParams {
                        handle: handle.raw,
                        min_ttl_ms: None,
                        force_refresh: false,
                    },
                )
                .await,
        )
        .expect("encode normal result");
        let audits_before_read = store.read_audit(None).expect("read audit");
        let scoped = scoped_request(&surface, &admin, 41, "github_app:fleet-a").await;
        assert_eq!(
            scoped["result"], normal,
            "credential.get_scoped must return the exact credential.get result body"
        );
        assert_eq!(
            store.read_audit(None).expect("read audit").len(),
            audits_before_read.len(),
            "a grant-authorized read must not append to the untrimmable audit chain"
        );

        store
            .revoke_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantRevoke),
            )
            .expect("revoke grant");
        let grant_ops: Vec<String> = store
            .read_audit(None)
            .expect("read audit")
            .into_iter()
            .filter(|entry| matches!(entry.op.as_str(), "grant_create" | "grant_revoke"))
            .map(|entry| entry.op)
            .collect();
        assert_eq!(grant_ops, ["grant_create", "grant_revoke"]);
    }

    #[tokio::test]
    async fn scoped_get_refuses_both_wrong_principal_kind_and_wrong_reserved_id() {
        let (surface, admin, store) = scoped_rig(73);
        store
            .create(
                "github_app:fleet-a",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");

        admin.record_bind(43, subc_protocol::Principal::Direct);
        let direct = scoped_request(&surface, &admin, 43, "github_app:fleet-a").await;
        assert_scoped_not_found(&direct);

        admin.record_bind(
            44,
            subc_protocol::Principal::Reserved {
                module_id: "other-module".into(),
            },
        );
        let other_reserved = scoped_request(&surface, &admin, 44, "github_app:fleet-a").await;
        assert_scoped_not_found(&other_reserved);
    }

    #[tokio::test]
    async fn scoped_get_uncovered_and_unknown_ids_have_identical_wire_bodies() {
        let (surface, admin, store) = scoped_rig(74);
        store
            .create(
                "apikey:uncovered",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create uncovered credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");
        admin.record_bind(
            45,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let uncovered = scoped_request(&surface, &admin, 45, "apikey:uncovered").await;
        let unknown = scoped_request(&surface, &admin, 45, "github_app:missing").await;
        assert_eq!(
            uncovered, unknown,
            "an uncovered stored credential and an unknown credential must be indistinguishable"
        );
    }

    #[tokio::test]
    async fn scoped_get_refusals_record_discriminated_auth_events_behind_uniform_wire_bodies() {
        let (surface, admin, store) = scoped_rig(75);
        store
            .create(
                "apikey:uncovered",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create uncovered credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");
        admin.record_bind(
            46,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let no_grant = scoped_request(&surface, &admin, 46, "apikey:uncovered").await;
        let not_found = scoped_request(&surface, &admin, 46, "github_app:missing").await;
        assert_eq!(
            no_grant, not_found,
            "the operator-only distinction must not change the refused wire body"
        );
        let events = store.recent_auth_events(10).expect("read events");
        assert_eq!(
            events.len(),
            2,
            "each refused scoped read needs a diagnostic row"
        );
        assert_eq!(events[0].credential_id, "github_app:missing");
        assert_eq!(events[0].detail.as_deref(), Some("not_found"));
        assert_eq!(events[1].credential_id, "apikey:uncovered");
        assert_eq!(events[1].detail.as_deref(), Some("no_grant"));
        for event in events {
            assert_eq!(event.kind, "scoped_read_refusal");
            assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
            assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
        }
    }

    #[tokio::test]
    async fn scoped_get_store_lookup_failure_is_uniform_on_wire_and_explicit_in_events() {
        let (surface, admin, store) = scoped_rig(77);
        store
            .create(
                "github_app:fleet-a",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "github_app:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");

        admin.record_bind(47, subc_protocol::Principal::Direct);
        let ordinary_refusal = scoped_request(&surface, &admin, 47, "github_app:fleet-a").await;
        admin.record_bind(
            48,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );
        // There is no public way to make an open store fail one read query. This cfg(test)
        // one-shot keeps the production surface unchanged while exercising the real route's
        // Result error arm after it has performed the normal lookup.
        surface.force_scoped_grant_lookup_error_for_test();
        let store_refusal = scoped_request(&surface, &admin, 48, "github_app:fleet-a").await;

        assert_eq!(
            store_refusal, ordinary_refusal,
            "a grant lookup failure must not make the wire distinguish vault storage from no grant"
        );
        let events = store.recent_auth_events(10).expect("read events");
        assert_eq!(events[0].detail.as_deref(), Some("store_error"));
        assert_eq!(events[0].principal_kind.as_deref(), Some("reserved"));
        assert_eq!(events[0].principal_id.as_deref(), Some("prefrontal-core"));
        assert_eq!(events[1].detail.as_deref(), Some("no_grant"));
    }

    #[test]
    fn admin_status_lists_sorted_grants_with_their_sorted_covered_credentials() {
        let (_surface, _admin, store) = scoped_rig(76);
        for id in ["github_app:z", "github_app:a"] {
            store
                .create(
                    id,
                    &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
                )
                .expect("create credential");
        }
        for prefix in ["github_app:", "apikey:"] {
            credentials_core::admin_ops::apply(
                &store,
                credentials_core::admin_ops::AdminOpBody::GrantCreate {
                    v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V1,
                    principal_id: "prefrontal-core".into(),
                    credential_prefix: prefix.into(),
                    operation: GrantOperation::Read,
                },
                "test",
            )
            .expect("create grant");
        }
        credentials_core::admin_ops::apply(
            &store,
            credentials_core::admin_ops::AdminOpBody::GrantCreate {
                v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V1,
                principal_id: "prefrontal-core".into(),
                credential_prefix: "github_app:".into(),
                operation: GrantOperation::Sign,
            },
            "test",
        )
        .expect("create sign grant");
        credentials_core::admin_ops::apply(
            &store,
            credentials_core::admin_ops::AdminOpBody::GrantCreate {
                v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V1,
                principal_id: "prefrontal-core".into(),
                credential_prefix: "apikey:".into(),
                operation: GrantOperation::Sign,
            },
            "test",
        )
        .expect("create apikey sign grant");
        let status = credentials_core::admin_ops::apply(
            &store,
            credentials_core::admin_ops::AdminOpBody::Status {
                v: credentials_core::admin_ops::ADMIN_OP_SCHEMA_V1,
            },
            "test",
        )
        .expect("status");
        let mut grants = status["read_grants"]
            .as_array()
            .expect("grant array")
            .clone();
        for grant in &mut grants {
            let created_at_ms = grant
                .as_object_mut()
                .expect("grant object")
                .remove("created_at_ms")
                .expect("grant timestamp");
            assert!(
                created_at_ms.as_i64().is_some(),
                "grant timestamp must be an integer"
            );
        }
        let expected = json!([
            {
                "principal_kind": "reserved",
                "principal_id": "prefrontal-core",
                "credential_prefix": "apikey:",
                "operation": "read",
                "covered_credential_ids": ["apikey:active", "apikey:dead"],
            },
            {
                "principal_kind": "reserved",
                "principal_id": "prefrontal-core",
                "credential_prefix": "apikey:",
                "operation": "sign",
                "covered_credential_ids": ["apikey:active", "apikey:dead"],
            },
            {
                "principal_kind": "reserved",
                "principal_id": "prefrontal-core",
                "credential_prefix": "github_app:",
                "operation": "read",
                "covered_credential_ids": ["github_app:a", "github_app:z"],
            },
            {
                "principal_kind": "reserved",
                "principal_id": "prefrontal-core",
                "credential_prefix": "github_app:",
                "operation": "sign",
                "covered_credential_ids": ["github_app:a", "github_app:z"],
            },
        ]);
        assert_eq!(
            grants,
            expected.as_array().expect("expected grant array").clone(),
            "status must make every grant's current reach diffable"
        );
    }

    /// Bump the fence epoch above the holder on a vault's db, via a fresh raw sqlite
    /// connection (the module crate cannot reach core's test-only with_raw_conn). This
    /// simulates a newer writer claiming the single-writer lease, so the store's next
    /// fenced write is rejected and latches fenced_out — the lease-handover race.
    fn bump_fence_epoch(db_path: &std::path::Path) {
        let conn = rusqlite::Connection::open(db_path).expect("open raw db");
        conn.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", [])
            .expect("bump fence epoch");
    }

    /// A route producer that keeps the route lane non-empty must NOT starve the
    /// control lane. This drives the REAL `drain_writer` with a saturating route
    /// producer, then sends one control frame and asserts it reaches the wire
    /// within a small bounded number of frames. With an unbounded route drain
    /// (a `drain_ready!(route_rx)` loop after each route write), the producer
    /// refills the queue during every write await and the control frame never
    /// gets scheduled — this test fails against that implementation (verified),
    /// so it discriminates the exact starvation hole, not just the bias.
    #[tokio::test]
    async fn control_frame_is_not_starved_by_a_saturating_route_producer() {
        let (control_tx, control_rx) = mpsc::channel::<Frame>(CONTROL_EGRESS_BUFFER);
        let (route_tx, route_rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
        // A SMALL duplex buffer so only a handful of frames fit in flight: frames
        // already written before the control send are not starvation evidence, so
        // the wire window must be tight for the frames-until-control count to
        // measure the writer's scheduling rather than buffered backlog.
        let (client, mut server) = tokio::io::duplex(256);

        let writer_task = tokio::spawn(async move {
            let _ = drain_writer(client, control_rx, route_rx).await;
        });

        fn frame(channel: u16, corr: u64) -> Frame {
            Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                channel,
                0,
                corr,
                vec![0u8; 32],
            )
            .unwrap()
        }

        // Saturating producer: keeps the route lane non-empty for the whole test.
        let producer = tokio::spawn(async move {
            loop {
                if route_tx.send(frame(5, 1)).await.is_err() {
                    break;
                }
            }
        });

        // Let the producer fill the queue and the writer start draining.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        control_tx.send(frame(0, 99)).await.expect("control send");

        // The control frame must appear within a small bounded number of frames.
        let mut frames_until_control = 0usize;
        loop {
            let got = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                subc_core::read_frame(&mut server),
            )
            .await
            .expect("wire stalled: control frame never arrived (starved)")
            .expect("read frame")
            .expect("stream closed before the control frame arrived");
            if got.header.channel == 0 && got.header.corr == 99 {
                break;
            }
            frames_until_control += 1;
            assert!(
                frames_until_control < 64,
                "control frame starved behind {frames_until_control}+ route frames"
            );
        }

        producer.abort();
        drop(control_tx);
        writer_task.abort();
    }

    /// Drive the REAL channel-0 control handler with a `health.check` Request and
    /// assert it answers with a well-formed `HealthCheck` Response carrying the
    /// domain metrics. Exercises the actual arm + surface + mapper, not a mock.
    /// The health wire key set is a CONTRACT, pinned so a rename cannot reach a
    /// consumer silently.
    ///
    /// This exists because one did. The audit-tip pair shipped on 2026-08-25 with its
    /// mac keyed `entryMac`, while the consumer-impact announcement I sent the
    /// supervisor seat said `auditTipMac`. Both artifacts were authored carefully and
    /// neither was checked against the other, because THERE IS NO MECHANICAL JOIN
    /// BETWEEN AN ANNOUNCEMENT AND THE BYTES IT DESCRIBES. Their own absent-arm check
    /// caught it on the first post-deploy read -- a good outcome, one deploy late.
    ///
    /// The keys here are HAND-TYPED STRING LITERALS with no compiler relationship to
    /// the Rust field names, which is exactly why the divergence was invisible:
    /// renaming the struct field does not touch the wire, and renaming the literal does
    /// not touch the field. Nothing but this test observes the wire.
    ///
    /// Its failure means a consumer's decoder is about to break. Announce the delta,
    /// then update this list -- and if a key disagrees with what was announced, THE
    /// ANNOUNCEMENT IS THE CONTRACT.
    ///
    /// `auditSeq` is unprefixed where `auditTipMac` is not, which looks careless and is
    /// deliberate: there is exactly one audit sequence so `auditSeq` cannot be misread,
    /// while `entryMac` never said WHICH entry and the chain holds thousands.
    /// A dropped frame names itself ONCE per (channel, epoch), and a repeat is quiet.
    ///
    /// Both halves matter and they pull opposite ways. Without the first, a stale
    /// binding is invisible and the incident that produced this code is undiagnosable
    /// from my side. Without the second, a looping sender turns the ingress path into a
    /// log-volume lever -- the same "granted party misbehaving" shape the fetch limiter
    /// answers with alarm-once rather than refuse.
    #[test]
    fn an_epoch_drop_is_recorded_once_per_pair_and_a_repeat_is_quiet() {
        let routes = RouteEpochs::default();
        routes.install(7, 3);

        assert!(!routes.matches(7, 2), "a stale epoch must not match");
        assert!(
            routes.note_drop(7, 2),
            "the first drop of a (channel, epoch) must be reportable"
        );
        assert!(
            !routes.note_drop(7, 2),
            "a repeat of the SAME pair must be quiet, or a looping sender drives \
             unbounded writes on the ingress path"
        );
        assert!(
            routes.note_drop(7, 1),
            "a DIFFERENT stale epoch on the same channel is a different event"
        );
        assert_eq!(
            routes.expected(7),
            Some(3),
            "the drop record must be able to name what this module actually holds"
        );
        assert_eq!(
            routes.expected(9),
            None,
            "an unheld channel reports no expectation rather than a stale one"
        );
    }

    /// Provenance never publishes a placeholder as a build fact.
    ///
    /// `BUILD_REV` is "unknown" on any build the release script did not stamp, and the
    /// protocol validates provenance for SHAPE ONLY -- non-empty, <=128 bytes, printable
    /// -- so "unknown" would sail through as a perfectly well-formed claim. A supervisor
    /// comparing provenance across a fleet treats a present field as an assertion about
    /// the binary, and a placeholder shaped like a sha is worse than an absent field:
    /// absence says "this build does not know", while "unknown" says "this build's sha
    /// is the string unknown".
    ///
    /// This test holds under BOTH build modes, which is what makes it worth having: on a
    /// dev build it asserts the block is absent, and on a stamped release build it
    /// asserts the sha is real. A future change that fills the field unconditionally
    /// fails here rather than in a fleet provenance comparison.
    #[test]
    fn provenance_never_publishes_a_placeholder_as_a_build_fact() {
        let m = manifest("claustrum");
        match &m.provenance {
            None => assert_eq!(
                credentials_core::contract::BUILD_REV,
                "unknown",
                "provenance is only omitted when this build genuinely has no stamped \
                 revision; a stamped build must publish it"
            ),
            Some(p) => {
                let sha = p
                    .build_git_sha
                    .as_deref()
                    .expect("a present provenance block declares the one fact it has");
                assert_ne!(
                    sha, "unknown",
                    "a placeholder must never be published as a build fact: the protocol \
                     validates shape only, so `unknown` is a well-formed lie"
                );
                assert_eq!(
                    sha,
                    credentials_core::contract::BUILD_REV,
                    "the manifest must report the same revision as --version, or two \
                     surfaces disagree about which binary this is"
                );
            }
        }
        assert!(
            m.provenance.as_ref().is_none_or(|p| p.validate().is_ok()),
            "whatever is declared must satisfy the protocol's own validator"
        );
    }

    #[test]
    fn the_health_wire_key_set_is_a_contract_and_a_rename_obliges_an_announcement() {
        let health = credentials_core::health::VaultHealth {
            audit_seq: Some(7),
            audit_tip_mac: Some("deadbeef".to_string()),
            ..credentials_core::health::VaultHealth::summarize(&[], 0, false)
        };
        let ModuleControlResponse::HealthCheck { metrics, .. } = health_report(&health) else {
            panic!("health_report must produce a HealthCheck");
        };
        let metrics = metrics.expect("metrics present");
        let metrics = metrics.as_object().expect("metrics object");

        let mut keys: Vec<&str> = metrics.keys().map(String::as_str).collect();
        keys.sort_unstable();

        let mut expected = vec![
            "active",
            "auditSeq",
            "auditTipMac",
            "corrupt",
            "corruptIds",
            "credentialsTotal",
            "fencedOut",
            "needsReauth",
            "needsReauthIds",
            "openIntents",
            "retired",
            "retiredIds",
            "refresherStalled",
            "storeReadable",
        ];
        expected.sort_unstable();

        assert_eq!(
            keys, expected,
            "the health metrics key set changed. Consumers decode these BY NAME, so this \
             is a consumer-impact change rather than a refactor: announce the delta to \
             the supervisor seat, then update this list."
        );
    }

    #[tokio::test]
    async fn health_check_control_request_returns_domain_report() {
        let surface = tmp_surface(7);
        let (tx, mut rx) = mpsc::channel::<Frame>(4);

        let request = ModuleControlRequest::HealthCheck {};
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            control_flags(),
            0,
            0,
            42,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();

        let (admin, _admin_store) = tmp_admin(7);
        let routes = Arc::new(RouteEpochs::default());
        handle_control_request(frame, &tx, &surface, &admin, &routes)
            .await
            .unwrap();

        let response = rx.try_recv().expect("a response frame was sent");
        assert_eq!(response.header.ty, FrameType::Response);
        assert_eq!(response.header.channel, 0);
        assert_eq!(response.header.corr, 42);

        let body: ModuleControlResponse = serde_json::from_slice(&response.body).unwrap();
        let ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } = body
        else {
            panic!("expected a HealthCheck response");
        };
        // One active + one needs_reauth ⇒ Degraded, never Failing (the store is
        // readable, so the vault is serving; a dead credential is detail only).
        assert_eq!(status, HealthStatus::Degraded);
        let metrics = metrics.expect("health report carries metrics");
        let obj = metrics.as_object().expect("metrics is a JSON object");
        assert_eq!(obj["credentialsTotal"], 2);
        assert_eq!(obj["active"], 1);
        assert_eq!(obj["needsReauth"], 1);
        assert_eq!(obj["storeReadable"], true);
        // The report NAMES the credential needing action (the seeded dead id).
        assert_eq!(obj["needsReauthIds"], serde_json::json!(["apikey:dead"]));
    }

    /// The first cached snapshot must expose exactly the same tip pair as the store.
    /// This proves the health path emits the current entry MAC rather than only a
    /// convenient sequence count.
    #[tokio::test]
    async fn health_snapshot_audit_tip_matches_store_tip_pair() {
        let (surface, store, _db) = tmp_surface_with_store(10);
        let (expected_seq, expected_mac) = store
            .audit_tip()
            .expect("read audit tip")
            .expect("seeded store has an audit tip");
        let snapshot = surface.health_snapshot();

        assert_eq!(snapshot.audit_seq, Some(expected_seq));
        assert_eq!(
            snapshot.audit_tip_mac.as_deref(),
            Some(expected_mac.as_str())
        );
    }

    /// A refresh after an audit append must replace both cached halves of the tip.
    /// Keeping the original pair would make the health witness miss a legitimate row
    /// change even though the store itself has advanced.
    #[tokio::test]
    async fn health_refresh_recomputes_audit_tip_after_append() {
        let (surface, store, _db) = tmp_surface_with_store(12);
        let before = surface.health_snapshot();
        store
            .append_audit(&AuditRecord {
                op: AuditOp::FetchAnomaly,
                credential_id: None,
                payload_hash: None,
                actor: "health-test".into(),
                alarm: None,
            })
            .expect("append audit entry");

        surface.refresh_health();
        let after = surface.health_snapshot();

        assert_eq!(
            after.audit_seq,
            before.audit_seq.map(|seq| seq + 1),
            "refresh must move the sequence tip"
        );
        assert_ne!(
            after.audit_tip_mac, before.audit_tip_mac,
            "refresh must move the MAC paired with the new sequence"
        );
    }

    /// The load-bearing property of the cached-snapshot fix: the probe reply is
    /// served from the in-memory snapshot and does NOT do a live store read. Prove
    /// it non-vacuously — mutate the store AFTER construction and assert the probe
    /// still returns the pre-mutation snapshot until `refresh_health` runs (the
    /// off-path recompute). A live-reading probe would reflect the mutation
    /// immediately; the cached one must not.
    #[tokio::test]
    async fn health_probe_serves_cached_snapshot_not_a_live_read() {
        let (surface, store, _db) = tmp_surface_with_store(11);

        // Initial snapshot (computed at construction): 1 active + 1 needs_reauth.
        let before = surface.health_snapshot();
        assert_eq!(before.credentials_total, 2);
        assert_eq!(before.needs_reauth, 1);

        // Mutate the store directly, off any refresh: add a third credential.
        store
            .create(
                "apikey:new",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create new");

        // The probe MUST still see the cached (stale) snapshot — proving it did not
        // read the store. A live read would already report 3.
        let still_cached = surface.health_snapshot();
        assert_eq!(
            still_cached.credentials_total, 2,
            "probe must serve the cached snapshot, not a live store scan"
        );

        // Only the off-path refresh picks up the mutation.
        surface.refresh_health();
        let after = surface.health_snapshot();
        assert_eq!(
            after.credentials_total, 3,
            "refresh recomputes from the store"
        );
    }

    /// A wedged/dead refresher must fail the probe CLOSED: if no refresh has completed
    /// within the stale limit, the probe reports Failing (refresher_stalled) instead of
    /// serving the last snapshot as healthy — turning a silent refresher death into an
    /// alert. Non-vacuous: the store is healthy (would be Ok/Degraded), so only the
    /// staleness gate can drive it to Failing here.
    #[tokio::test]
    async fn a_stalled_refresher_fails_the_probe_closed() {
        let surface = tmp_surface(13);
        // Fresh snapshot: healthy store, refresher just ran → not Failing.
        let fresh = surface.health_snapshot();
        assert_ne!(
            fresh.status,
            credentials_core::health::VaultHealthStatus::Failing
        );
        assert!(!fresh.refresher_stalled);

        // Backdate the last-refresh clock past the stale limit (refresher wedged/died).
        surface.force_stale_refresher_for_test();

        let stale = surface.health_snapshot();
        assert!(
            stale.refresher_stalled,
            "the probe must flag a stalled refresher live at read time"
        );
        assert_eq!(
            stale.status,
            credentials_core::health::VaultHealthStatus::Failing,
            "a stalled refresher fails the probe closed"
        );
        // And the control handler surfaces it as Failing on the wire.
        let report = health_report(&stale);
        let ModuleControlResponse::HealthCheck { status, .. } = report else {
            panic!("expected HealthCheck");
        };
        assert_eq!(status, HealthStatus::Failing);
    }

    /// A non-Ok health report ALWAYS names a reason. A degraded or failing status with an
    /// empty detail forces every observer to open an investigation just to discover whether
    /// one is needed, which is the most expensive possible way to say "something is wrong".
    ///
    /// The arms in `health_report` happen to cover today's status inputs one-for-one, so
    /// this holds by coincidence maintained by hand rather than by construction: a new
    /// input added to the ladder in `health.rs` without a matching arm here would flip the
    /// status while leaving the reason empty, and every existing test would still pass.
    /// This drives every non-Ok snapshot the ladder can produce through the wire mapping
    /// and requires a non-empty reason from each, so that omission fails here instead of
    /// arriving as an unexplained degraded state on a supervisor dashboard.
    #[test]
    fn unreadable_store_omits_counts_rather_than_reporting_zero() {
        use credentials_core::health::VaultHealth;

        // The counted fields. Each is a measurement OF THE STORE, so none of them has a
        // meaning when the store could not be read.
        const COUNTED: [&str; 9] = [
            "credentialsTotal",
            "active",
            "needsReauth",
            "retired",
            "corrupt",
            "needsReauthIds",
            "retiredIds",
            "corruptIds",
            "openIntents",
        ];
        const AUDIT_TIP: [&str; 2] = ["auditSeq", "entryMac"];

        let unreadable = health_report(&VaultHealth::unreadable());
        let ModuleControlResponse::HealthCheck { metrics, .. } = unreadable else {
            panic!("expected HealthCheck");
        };
        let metrics = metrics.expect("an unreadable report still carries metrics");

        for field in COUNTED {
            assert!(
                metrics.get(field).is_none(),
                "{field} must be ABSENT when the store is unreadable: reporting 0 is what an \
                 empty vault reports, so a consumer plotting it cannot tell 'none' from \
                 'could not count'"
            );
        }
        for field in AUDIT_TIP {
            assert!(
                metrics.get(field).is_none(),
                "{field} must be ABSENT when the store is unreadable: a zero or stale audit \
                 tip would be false witness data"
            );
        }
        // The flags describe the daemon rather than the store, so they survive.
        assert_eq!(
            metrics.get("storeReadable").and_then(|v| v.as_bool()),
            Some(false),
            "the reason the counts are missing must still be readable"
        );

        // THE DISAMBIGUATOR. Without this, an implementation that omitted the counts
        // unconditionally -- or emitted no metrics at all -- would satisfy every
        // assertion above, and the omission would be indistinguishable from the field
        // never existing.
        let readable = health_report(&VaultHealth::summarize(&[], 0, false));
        let ModuleControlResponse::HealthCheck { metrics, .. } = readable else {
            panic!("expected HealthCheck");
        };
        let metrics = metrics.expect("a healthy report carries metrics");
        for field in COUNTED {
            assert!(
                metrics.get(field).is_some(),
                "{field} must be PRESENT when the store was read, including when the count \
                 is genuinely zero -- that is the case the absent form has to be \
                 distinguishable from"
            );
        }
        assert_eq!(
            metrics.get("active").and_then(|v| v.as_u64()),
            Some(0),
            "an empty but readable vault reports a real zero"
        );
        // An empty readable chain has no tip, so both optional fields remain absent.
        for field in AUDIT_TIP {
            assert!(
                metrics.get(field).is_none(),
                "{field} must be absent when the audit chain is empty"
            );
        }

        // A non-empty readable chain emits both halves of the witness observation.
        let mut with_tip = VaultHealth::summarize(&[], 0, false);
        with_tip.audit_seq = Some(7);
        with_tip.audit_tip_mac = Some("mac-7".to_string());
        let ModuleControlResponse::HealthCheck { metrics, .. } = health_report(&with_tip) else {
            panic!("expected HealthCheck");
        };
        let metrics = metrics.expect("health report carries metrics");
        assert_eq!(metrics.get("auditSeq").and_then(|v| v.as_i64()), Some(7));
        assert_eq!(
            metrics.get("auditTipMac").and_then(|v| v.as_str()),
            Some("mac-7")
        );
    }

    #[test]
    fn every_non_ok_health_report_carries_a_reason() {
        use credentials_core::health::{VaultHealth, VaultHealthStatus};
        use credentials_core::store::{RecordMeta, RecordState};

        fn scan_row(id: &str, state: RecordState) -> (String, RecordMeta) {
            (
                id.to_string(),
                RecordMeta {
                    record_version: 1,
                    key_id_hex: "00".repeat(8),
                    state,
                    stale_pending: false,
                },
            )
        }

        // One snapshot per way the ladder can leave Ok, built through the same
        // constructors the daemon uses rather than by hand-setting `status` -- a
        // hand-built struct would prove the mapping handles values that cannot occur.
        let mut stalled = VaultHealth::summarize(&[], 0, false);
        stalled.mark_refresher_stalled();

        let fenced = VaultHealth::summarize(&[], 0, true);

        let unreadable = VaultHealth::unreadable();

        let needs_reauth = VaultHealth::summarize(
            &[scan_row("oauth:anthropic", RecordState::NeedsReauth)],
            0,
            false,
        );
        let corrupt =
            VaultHealth::summarize(&[scan_row("apikey:exa", RecordState::Corrupt)], 0, false);

        for (name, health) in [
            ("refresher_stalled", stalled),
            ("fenced_out", fenced),
            ("store_unreadable", unreadable),
            ("needs_reauth", needs_reauth),
            ("corrupt", corrupt),
        ] {
            assert_ne!(
                health.status,
                VaultHealthStatus::Ok,
                "{name}: this case must leave Ok, or it is not testing what it claims"
            );
            let ModuleControlResponse::HealthCheck { status, detail, .. } = health_report(&health)
            else {
                panic!("expected HealthCheck");
            };
            assert_ne!(
                status,
                HealthStatus::Ok,
                "{name}: wire status must be non-Ok"
            );
            let reason = detail.unwrap_or_default();
            assert!(
                !reason.trim().is_empty(),
                "{name}: a non-Ok report must name its reason, got an empty detail"
            );
        }

        // The positive control: a healthy vault needs no reason, so this proves the
        // assertion above is about non-Ok reports rather than about detail being
        // unconditionally present.
        let healthy =
            VaultHealth::summarize(&[scan_row("apikey:exa", RecordState::Active)], 0, false);
        assert_eq!(healthy.status, VaultHealthStatus::Ok);
        let ModuleControlResponse::HealthCheck { status, detail, .. } = health_report(&healthy)
        else {
            panic!("expected HealthCheck");
        };
        assert_eq!(status, HealthStatus::Ok);
        assert!(detail.is_none(), "a healthy report carries no reason");
    }

    /// A fenced-out daemon reports `ready=false`/`lease_held=false` from status, agreeing
    /// with the health probe instead of always claiming a healthy lease. Non-vacuous:
    /// before fencing, an Active credential is ready with the lease held; after fencing,
    /// the same probe flips both.
    #[tokio::test]
    async fn status_reflects_fenced_out_lease_loss() {
        let (surface, store, db_path) = tmp_surface_with_store(14);
        // Mint a handle for the active credential so a per-handle status has a target.
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let params = StatusParams {
            handle: Some(handle.raw.clone()),
        };
        let before = surface.status(1, &params).await;
        assert!(before.ready, "an active credential is ready before fencing");
        assert!(before.lease_held, "the lease is held before fencing");

        // A newer writer claims the db at a higher fence epoch; the next fenced write on
        // this store is rejected and latches fenced_out (the lease-handover race).
        bump_fence_epoch(&db_path);
        let _ = store.invalidate("apikey:active"); // trigger the fenced write to latch

        let after = surface.status(1, &params).await;
        assert!(
            !after.lease_held,
            "a fenced-out daemon does not hold the lease"
        );
        assert!(
            !after.ready,
            "a fenced-out daemon is not ready even for an Active row"
        );

        // The overall (no-handle) status also reflects the loss.
        let overall = surface.status(1, &StatusParams { handle: None }).await;
        assert!(!overall.ready);
        assert!(!overall.lease_held);
    }

    /// A status handle-probe runs the per-connection limiter BEFORE resolution, so a
    /// status-based enumeration sweep of unknown handles trips the same durable anomaly
    /// alarm as a get sweep — not a bypass. Proven by reading the audit log for the alarm.
    /// `status` must report each record state DISTINCTLY: a needs_reauth credential is
    /// not ready and names NeedsReauth, a corrupt one names Corrupt, and an active one
    /// names nothing.
    ///
    /// Both sibling status tests probe the ACTIVE row only — one for the fenced-out
    /// latch, one for the limiter — so neither can tell this mapping apart from a status
    /// that always answers `last_error_code: None`. Consumers branch on that field to
    /// decide whether a re-login is needed, so a collapsed mapping would present a dead
    /// credential as healthy.
    #[tokio::test]
    async fn status_names_the_state_of_each_credential() {
        let (surface, store, _db) = tmp_surface_with_store(16);

        // The rig seeds apikey:active (Active) and apikey:dead (NeedsReauth). Add a
        // corrupt row so all three arms of the mapping are exercised in one run.
        store
            .create(
                "apikey:broken",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create broken");
        store.quarantine("apikey:broken").expect("quarantine");

        let mint_for = |id: &str| {
            let handle = credentials_core::store::mint_handle().expect("mint handle");
            store
                .put_handle_hash(&handle.hash, id, AuditCtx::admin(AuditOp::MintHandle))
                .expect("put handle");
            handle.raw
        };
        let active = mint_for("apikey:active");
        let dead = mint_for("apikey:dead");
        let broken = mint_for("apikey:broken");

        // POSITIVE ARM: without it, a status reporting every credential as broken would
        // satisfy both negative assertions below.
        let ok = surface
            .status(
                2,
                &StatusParams {
                    handle: Some(active),
                },
            )
            .await;
        assert!(ok.ready, "an active credential is ready");
        assert_eq!(
            ok.last_error_code, None,
            "an active credential names no error"
        );

        let reauth = surface
            .status(2, &StatusParams { handle: Some(dead) })
            .await;
        assert!(!reauth.ready, "a needs_reauth credential is not ready");
        assert_eq!(
            reauth.last_error_code,
            Some(read_surface::ReadError::NeedsReauth),
            "needs_reauth must be named, not collapsed into a generic failure"
        );

        let corrupt = surface
            .status(
                2,
                &StatusParams {
                    handle: Some(broken),
                },
            )
            .await;
        assert!(!corrupt.ready, "a corrupt credential is not ready");
        assert_eq!(
            corrupt.last_error_code,
            Some(read_surface::ReadError::Corrupt),
            "corrupt is a DIFFERENT state from needs_reauth: one needs a re-login, the \
             other needs the record replaced"
        );

        // An unresolvable handle is uniformly not_found, so a probe cannot distinguish
        // a revoked handle from one that never existed.
        let unknown = surface
            .status(
                2,
                &StatusParams {
                    handle: Some("ckh_not_a_real_handle".to_string()),
                },
            )
            .await;
        assert!(!unknown.ready);
        assert_eq!(
            unknown.last_error_code,
            Some(read_surface::ReadError::NotFound)
        );
    }

    /// A real Ed25519 PKCS#8 PEM, generated per call.
    ///
    /// Generated rather than pasted as a literal so the test material comes from the
    /// same production path a deposit would: a hand-written fixture agrees with
    /// whatever its author expected, which is how this repo shipped a parser demanding
    /// PKCS#8 at a world that issues PKCS#1.
    fn test_ed25519_pem() -> String {
        use base64::Engine;
        use ring::rand::SystemRandom;
        use ring::signature::Ed25519KeyPair;
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate");
        let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----");
        pem
    }

    /// A capability handle authorizes signing and public-key publication for a signing
    /// key, but must never serve the private PKCS#8 payload through any read operation.
    #[tokio::test]
    async fn signing_key_handle_cannot_get_but_can_sign_and_publish() {
        use base64::Engine as _;

        let (surface, admin, store) = scoped_rig(81);
        let pem = test_ed25519_pem();
        let credential_id = "signing:agent-assertion:handle";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("create signing key");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store handle");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "signing:agent-assertion:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            81,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let get = serde_json::to_value(
            surface
                .get(
                    81,
                    &GetParams {
                        handle: handle.raw.clone(),
                        min_ttl_ms: None,
                        force_refresh: false,
                    },
                )
                .await,
        )
        .expect("encode get outcome");
        assert_eq!(get["error"]["code"], "not_found");
        assert_eq!(get["error"]["class"], "permanent");

        let many = serde_json::to_value(
            surface
                .get_many(
                    81,
                    &GetManyParams {
                        items: vec![GetParams {
                            handle: handle.raw.clone(),
                            min_ttl_ms: None,
                            force_refresh: false,
                        }],
                    },
                )
                .await,
        )
        .expect("encode get_many outcomes");
        assert_eq!(many[0]["error"]["code"], "not_found");
        assert_eq!(many[0]["error"]["class"], "permanent");

        let scoped = scoped_request(&surface, &admin, 81, credential_id).await;
        assert_scoped_not_found(&scoped);

        let public = surface
            .public_key(
                81,
                None,
                &read_surface::PublicKeyParams {
                    handle: Some(handle.raw.clone()),
                    credential_id: None,
                },
            )
            .await
            .expect("the same handle must publish the public half");
        assert_eq!(public.algorithm, "ed25519");
        let signature = surface
            .sign(
                81,
                None,
                &read_surface::SignParams {
                    handle: Some(handle.raw),
                    credential_id: None,
                    payload_b64: base64::engine::general_purpose::STANDARD
                        .encode(b"handle-authorized bytes"),
                },
            )
            .await
            .expect("the same handle must still sign");
        assert!(!signature.signature_b64.is_empty());
        assert_eq!(signature.key_id, public.key_id);
    }

    /// `get_many` currently delegates every item to `get`; this pins that structural
    /// property so a future batch-query optimization cannot reopen signing-key payload
    /// reads while a refusal-only test still passes by rejecting the entire batch.
    #[tokio::test]
    async fn get_many_delegates_signing_key_refusal_without_blocking_other_items() {
        let (surface, store, _db) = tmp_surface_with_store(85);
        let pem = test_ed25519_pem();
        store
            .create(
                "signing:batch:private",
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    pem.into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create(
                "apikey:batch:ordinary",
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    b"ordinary payload".to_vec(),
                    None,
                ),
            )
            .expect("create ordinary credential");
        let signing_handle = credentials_core::store::mint_handle().expect("mint signing handle");
        store
            .put_handle_hash(
                &signing_handle.hash,
                "signing:batch:private",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store signing handle");
        let ordinary_handle = credentials_core::store::mint_handle().expect("mint ordinary handle");
        store
            .put_handle_hash(
                &ordinary_handle.hash,
                "apikey:batch:ordinary",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store ordinary handle");

        let outcomes = surface
            .get_many(
                85,
                &GetManyParams {
                    items: vec![
                        GetParams {
                            handle: signing_handle.raw,
                            min_ttl_ms: None,
                            force_refresh: false,
                        },
                        GetParams {
                            handle: ordinary_handle.raw,
                            min_ttl_ms: None,
                            force_refresh: false,
                        },
                    ],
                },
            )
            .await;
        let read_surface::GetOutcome::Err { error } = &outcomes[0] else {
            panic!("a SigningKey batch item must refuse");
        };
        assert_eq!(error.code, read_surface::ReadError::NotFound);
        assert_eq!(error.class, read_surface::ErrorClass::Permanent);
        let read_surface::GetOutcome::Ok(result) = &outcomes[1] else {
            panic!("a non-signing batch item must still serve");
        };
        assert_eq!(result.payload, b"ordinary payload");
    }

    #[tokio::test]
    async fn read_grant_does_not_authorize_scoped_signing() {
        use base64::Engine as _;

        let (surface, admin, store) = scoped_rig(82);
        let credential_id = "signing:operations:read-only";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "signing:operations:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            82,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refused = scoped_sign_request(
            &surface,
            &admin,
            82,
            credential_id,
            &base64::engine::general_purpose::STANDARD.encode(b"must not sign"),
        )
        .await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.kind, "scoped_read_refusal");
        assert_eq!(event.detail.as_deref(), Some("no_grant"));
    }

    #[tokio::test]
    async fn sign_grant_does_not_authorize_scoped_get() {
        let (surface, admin, store) = scoped_rig(83);
        let credential_id = "apikey:operations:sign-only";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
            )
            .expect("create api key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "apikey:operations:",
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create sign grant");
        admin.record_bind(
            83,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refused = scoped_request(&surface, &admin, 83, credential_id).await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.kind, "scoped_read_refusal");
        assert_eq!(event.detail.as_deref(), Some("no_grant"));
    }

    #[tokio::test]
    async fn sign_grant_signs_signing_keys_but_not_other_kinds() {
        use base64::Engine as _;

        let (surface, admin, store) = scoped_rig(84);
        let pem = test_ed25519_pem();
        store
            .create(
                "signing:operations:real",
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create(
                "signing:operations:impostor",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", pem.into_bytes(), None),
            )
            .expect("create non-signing credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "signing:operations:",
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create sign grant");
        admin.record_bind(
            84,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );
        let payload = base64::engine::general_purpose::STANDARD.encode(b"granted bytes");

        let signed =
            scoped_sign_request(&surface, &admin, 84, "signing:operations:real", &payload).await;
        assert!(
            signed["result"]["signature_b64"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "a sign grant must authorize a SigningKey record"
        );

        let refused = scoped_sign_request(
            &surface,
            &admin,
            84,
            "signing:operations:impostor",
            &payload,
        )
        .await;
        assert_eq!(refused["result"]["error"]["code"], "kind_not_signable");
        assert_eq!(refused["result"]["error"]["class"], "permanent");
    }

    #[tokio::test]
    async fn read_grant_authorizes_scoped_public_key() {
        let (surface, admin, store) = scoped_rig(86);
        let credential_id = "signing:public-key:read-granted";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "signing:public-key:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            86,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let published = scoped_public_key_request(&surface, &admin, 86, credential_id).await;
        assert_eq!(published["result"]["algorithm"], "ed25519");
        assert!(
            published["result"]["public_key_hex"]
                .as_str()
                .is_some_and(|key| !key.is_empty()),
            "a read grant must publish the signing key's public material"
        );
        assert!(
            store
                .recent_auth_events(10)
                .expect("read auth events")
                .is_empty(),
            "a grant-authorized public-key request must not record a refusal"
        );
    }

    #[tokio::test]
    async fn sign_grant_does_not_authorize_scoped_public_key() {
        let (surface, admin, store) = scoped_rig(87);
        let credential_id = "signing:public-key:sign-only";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "signing:public-key:",
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create sign grant");
        admin.record_bind(
            87,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refused = scoped_public_key_request(&surface, &admin, 87, credential_id).await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.credential_id, credential_id);
        assert_eq!(event.detail.as_deref(), Some("no_grant"));
    }

    #[tokio::test]
    async fn public_key_handle_authorization_remains_available() {
        let (surface, admin, store) = scoped_rig(88);
        let credential_id = "signing:public-key:handle";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                credential_id,
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store handle");

        let published = scoped_route_request(
            &surface,
            &admin,
            88,
            OP_PUBLIC_KEY,
            json!({ "handle": handle.raw }),
        )
        .await;
        assert_eq!(published["result"]["algorithm"], "ed25519");
        assert!(
            published["result"]["key_id"]
                .as_str()
                .is_some_and(|key_id| !key_id.is_empty()),
            "the existing handle form must still publish public key material"
        );
    }

    #[tokio::test]
    async fn scoped_public_key_fences_non_signing_records() {
        let (surface, admin, store) = scoped_rig(89);
        let credential_id = "apikey:public-key:impostor";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create non-signing credential");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "apikey:public-key:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            89,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let refused = scoped_public_key_request(&surface, &admin, 89, credential_id).await;
        assert_eq!(refused["result"]["error"]["code"], "kind_not_signable");
        assert_eq!(refused["result"]["error"]["class"], "permanent");
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.credential_id, credential_id);
        assert_eq!(event.detail.as_deref(), Some("wrong_kind"));
        assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
        assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
    }

    #[tokio::test]
    async fn scoped_public_key_refusals_record_auth_events_behind_uniform_wire_bodies() {
        let (surface, admin, store) = scoped_rig(90);
        let uncovered_id = "apikey:public-key:uncovered";
        let unknown_id = "signing:public-key:missing";
        store
            .create(
                uncovered_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create uncovered signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "signing:public-key:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            90,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        let no_grant = scoped_public_key_request(&surface, &admin, 90, uncovered_id).await;
        let not_found = scoped_public_key_request(&surface, &admin, 90, unknown_id).await;
        assert_eq!(
            no_grant, not_found,
            "an uncovered credential and an absent credential must have the same wire body"
        );
        let events = store.recent_auth_events(10).expect("read auth events");
        assert_eq!(
            events.len(),
            2,
            "each refused public-key request needs a row"
        );
        assert_eq!(events[0].credential_id, unknown_id);
        assert_eq!(events[0].detail.as_deref(), Some("not_found"));
        assert_eq!(events[1].credential_id, uncovered_id);
        assert_eq!(events[1].detail.as_deref(), Some("no_grant"));
        for event in events {
            assert_eq!(event.kind, "scoped_read_refusal");
            assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
            assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
        }
    }

    #[tokio::test]
    async fn scoped_public_key_grant_lookup_failure_records_store_error() {
        let (surface, admin, store) = scoped_rig(91);
        let credential_id = "signing:public-key:store-error";
        store
            .create(
                credential_id,
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    test_ed25519_pem().into_bytes(),
                    None,
                ),
            )
            .expect("create signing key");
        store
            .create_read_grant_audited(
                "reserved",
                "prefrontal-core",
                "signing:public-key:",
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create read grant");
        admin.record_bind(
            91,
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        );

        surface.force_scoped_grant_lookup_error_for_test();
        let refused = scoped_public_key_request(&surface, &admin, 91, credential_id).await;
        assert_scoped_not_found(&refused);
        let event = store
            .recent_auth_events(1)
            .expect("read auth events")
            .remove(0);
        assert_eq!(event.credential_id, credential_id);
        assert_eq!(event.detail.as_deref(), Some("store_error"));
        assert_eq!(event.principal_kind.as_deref(), Some("reserved"));
        assert_eq!(event.principal_id.as_deref(), Some("prefrontal-core"));
    }

    /// The signing fence: a signing-key credential signs, and EVERY other kind is
    /// refused with a permanent `kind_not_signable`.
    ///
    /// Both arms in one test because the fence is only meaningful as a pair. A test
    /// that only proves signing works would stay green if the kind check were deleted,
    /// and that deletion is precisely what turns this module into a general signing
    /// oracle: a handle for any stored secret could then produce signatures under it.
    ///
    /// The negative uses an API-KEY record holding VALID PEM, so the refusal cannot be
    /// mistaken for a parse failure. If the fence were removed, those bytes would sign
    /// happily -- which is the whole hazard, and a negative built from garbage bytes
    /// would refuse for the wrong reason and prove nothing.
    #[tokio::test]
    async fn signing_is_fenced_to_signing_key_records() {
        use credentials_core::record::CredentialKind;
        let (surface, store, _db) = tmp_surface_with_store(31);

        // One PEM, deposited twice under different kinds. Same bytes, so the ONLY
        // difference between the two arms is the kind.
        let pem = test_ed25519_pem();

        let signer = VaultRecord::new_static(
            CredentialKind::SigningKey,
            "test",
            pem.as_bytes().to_vec(),
            None,
        );
        store.create("sign:root", &signer).expect("create signer");
        let not_signer = VaultRecord::new_static(
            CredentialKind::ApiKey,
            "test",
            pem.as_bytes().to_vec(),
            None,
        );
        store
            .create("apikey:impostor", &not_signer)
            .expect("create impostor");

        let h_sign = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &h_sign.hash,
                "sign:root",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");
        let h_api = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &h_api.hash,
                "apikey:impostor",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        use base64::Engine as _;
        let payload = base64::engine::general_purpose::STANDARD.encode(b"manifest bytes");

        // POSITIVE: the signing-key record signs, and names the key that did it.
        let ok = surface
            .sign(
                1,
                None,
                &read_surface::SignParams {
                    handle: Some(h_sign.raw.clone()),
                    credential_id: None,
                    payload_b64: payload.clone(),
                },
            )
            .await
            .expect("a SigningKey record must sign");
        assert!(!ok.signature_b64.is_empty(), "a signature must come back");
        assert_eq!(ok.key_id.len(), 16, "key_id is 8 bytes of hex");

        // NEGATIVE: identical bytes under ApiKey are refused, permanently.
        let err = surface
            .sign(
                1,
                None,
                &read_surface::SignParams {
                    handle: Some(h_api.raw.clone()),
                    credential_id: None,
                    payload_b64: payload,
                },
            )
            .await
            .expect_err("an ApiKey record must NOT sign even holding valid PEM");
        assert_eq!(
            err,
            read_surface::ReadError::KindNotSignable,
            "the refusal must name the fence, not a parse failure"
        );
        assert!(
            matches!(err.class(), read_surface::ErrorClass::Permanent),
            "no retry turns an api key into a signing key"
        );
    }

    /// Public material must verify signatures from the same handle while excluding the
    /// private PEM that ordinary `credential.get` would expose.
    ///
    /// The non-signing negative uses valid PEM under `ApiKey`, so deleting the kind
    /// fence makes this test fail by publishing a real key instead of refusing for an
    /// unrelated parse error.
    #[tokio::test]
    async fn public_key_matches_signatures_without_serializing_private_material() {
        use base64::Engine as _;
        use ring::signature::{UnparsedPublicKey, ED25519};

        // A private payload might be serialized as a JSON string or as a byte array;
        // inspect both shapes so a future `Vec<u8>` field cannot bypass the PEM-text
        // check merely because JSON escaped or number-encoded the same bytes.
        fn json_contains_byte_sequence(value: &serde_json::Value, needle: &[u8]) -> bool {
            match value {
                serde_json::Value::String(text) => text
                    .as_bytes()
                    .windows(needle.len())
                    .any(|window| window == needle),
                serde_json::Value::Array(values) => {
                    let encoded_bytes: Option<Vec<u8>> = values
                        .iter()
                        .map(|value| value.as_u64().and_then(|n| u8::try_from(n).ok()))
                        .collect();
                    encoded_bytes.is_some_and(|bytes| {
                        bytes.windows(needle.len()).any(|window| window == needle)
                    }) || values
                        .iter()
                        .any(|value| json_contains_byte_sequence(value, needle))
                }
                serde_json::Value::Object(fields) => fields
                    .values()
                    .any(|value| json_contains_byte_sequence(value, needle)),
                serde_json::Value::Null
                | serde_json::Value::Bool(_)
                | serde_json::Value::Number(_) => false,
            }
        }

        let (surface, store, _db) = tmp_surface_with_store(32);
        let pem = test_ed25519_pem();
        store
            .create(
                "signing:agent-assertion:7",
                &VaultRecord::new_static(
                    CredentialKind::SigningKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("create signer");
        store
            .create(
                "apikey:valid-pem",
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "test",
                    pem.as_bytes().to_vec(),
                    None,
                ),
            )
            .expect("create non-signer");

        let signer_handle = credentials_core::store::mint_handle().expect("mint signer handle");
        store
            .put_handle_hash(
                &signer_handle.hash,
                "signing:agent-assertion:7",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store signer handle");
        let non_signer_handle =
            credentials_core::store::mint_handle().expect("mint non-signer handle");
        store
            .put_handle_hash(
                &non_signer_handle.hash,
                "apikey:valid-pem",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("store non-signer handle");

        let public = surface
            .public_key(
                1,
                None,
                &read_surface::PublicKeyParams {
                    handle: Some(signer_handle.raw.clone()),
                    credential_id: None,
                },
            )
            .await
            .expect("a signing key must publish its public half");
        assert_eq!(public.algorithm, "ed25519");

        // The outer route body is what a consumer receives. It must contain neither
        // the PEM armour nor the payload bytes, because returning either turns this
        // public-material route into the private `credential.get` disclosure path.
        let serialized =
            serde_json::to_vec(&json!({ "result": &public })).expect("serialize route body");
        let serialized_value: serde_json::Value =
            serde_json::from_slice(&serialized).expect("decode serialized route body");
        assert!(
            !json_contains_byte_sequence(&serialized_value, pem.as_bytes()),
            "the serialized public-key response must not contain private key bytes"
        );
        assert!(
            !String::from_utf8_lossy(&serialized).contains("BEGIN PRIVATE KEY"),
            "the serialized public-key response must not contain PEM armour"
        );

        let payload = b"canonical manifest bytes";
        let signature = surface
            .sign(
                1,
                None,
                &read_surface::SignParams {
                    handle: Some(signer_handle.raw),
                    credential_id: None,
                    payload_b64: base64::engine::general_purpose::STANDARD.encode(payload),
                },
            )
            .await
            .expect("credential.sign must use the same stored key");
        let public_bytes: Vec<u8> = (0..public.public_key_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&public.public_key_hex[i..i + 2], 16).expect("hex"))
            .collect();
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature.signature_b64)
            .expect("signature base64");
        UnparsedPublicKey::new(&ED25519, &public_bytes)
            .verify(payload, &signature_bytes)
            .expect("the published public half must verify credential.sign output");
        assert_eq!(public.key_id, signature.key_id);

        let err = surface
            .public_key(
                1,
                None,
                &read_surface::PublicKeyParams {
                    handle: Some(non_signer_handle.raw),
                    credential_id: None,
                },
            )
            .await
            .expect_err("a non-signing credential must not publish parsed material");
        assert_eq!(err, read_surface::ReadError::KindNotSignable);
    }

    /// A reactivate-based repair moves `ready` and NOT `record_version`.
    ///
    /// Pins the pair, because the two fields answer different questions and a consumer
    /// told "the version is the change cursor" would build on the wrong one. `reactivate`
    /// clears a wrong needs_reauth verdict without touching the stored material, so a
    /// credential goes unusable-to-usable with the version unchanged -- a poller watching
    /// only the version keeps a repaired credential marked dead indefinitely.
    ///
    /// The version CANNOT move here: it is bound into the envelope's AAD, so bumping it
    /// means re-sealing, and a re-seal on the repair path would put decrypt-and-encrypt
    /// on the one route that recovers from a wrong verdict. So this asserts the version
    /// is STABLE as well as that `ready` flipped -- an implementation that "helpfully"
    /// bumped it would be writing a record it can no longer open.
    #[tokio::test]
    async fn a_reactivate_repair_moves_ready_and_leaves_the_version_alone() {
        let (surface, store, _db) = tmp_surface_with_store(29);
        let record = VaultRecord::new_static(
            credentials_core::record::CredentialKind::ApiKey,
            "test",
            b"payload".to_vec(),
            None,
        );
        store.create("apikey:repair", &record).expect("create");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:repair",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let params = crate::read_surface::StatusParams {
            handle: Some(handle.raw.clone()),
        };
        let before = surface.status(1, &params).await;
        assert!(before.ready, "seeded credential must start ready");
        let version_before = before
            .record_version
            .expect("a resolved handle has a version");

        store
            .invalidate_and_revoke_all_audited(
                "apikey:repair",
                AuditCtx::admin(AuditOp::Invalidate),
            )
            .expect("invalidate");

        store
            .reactivate_audited("apikey:repair", AuditCtx::admin(AuditOp::Reactivate))
            .expect("reactivate");

        // The handle was revoked by the invalidate, so ask by credential id via meta:
        // the point is the VERSION, and the surface's own view is checked below.
        let meta = store.meta("apikey:repair").expect("meta");
        assert_eq!(
            meta.record_version, version_before,
            "reactivate must NOT bump the version: it is AAD-bound, so moving it without \
             re-sealing writes a record the vault can no longer open"
        );
        assert!(
            matches!(meta.state, credentials_core::store::RecordState::Active),
            "the repair must have landed, or this test proves nothing about the pair"
        );
    }

    /// `status` must NOT consult the refresh path, which is the only reason the version
    /// cursor lives here rather than on `get`.
    ///
    /// THIS FENCES A JUSTIFICATION, NOT A BEHAVIOUR. The cursor exists so a consumer can
    /// poll for a credential coming back WITHOUT buying an upstream token exchange each
    /// time -- `get` mints on a stale record, so polling through it would charge a
    /// provider call per check and a consumer avoiding that cost would notice the repair
    /// late. Every other test here asserts what the field CONTAINS; none asserted what
    /// reading it COSTS, and a plausible consistency refactor routing status through the
    /// engine would keep them all green while silently making repair-polling expensive.
    ///
    /// Discriminated without a network: the record is a STALE OAuth credential and NO
    /// adapter is registered, so anything that reaches the refresh path fails outright.
    /// Metadata-only status answers normally.
    #[tokio::test]
    async fn status_does_not_consult_the_refresh_path() {
        let (surface, store, _db) = tmp_surface_with_store(23);
        // Stale: an OAuth record whose access token expired long ago. Reaching the
        // refresh path with no adapter registered cannot succeed.
        let oauth = credentials_core::oauth::OAuthCredential {
            access_token: "expired".to_string(),
            refresh_token: "rt".to_string(),
            expires_at_ms: Some(1),
            token_url: String::new(),
            client_id: None,
            scopes: Vec::new(),
        };
        let record = VaultRecord::new_oauth("test", "no-such-adapter", oauth, Vec::new());
        store.create("oauth:stale", &record).expect("create");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:stale",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let result = surface
            .status(
                1,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                },
            )
            .await;

        assert!(
            result.ready,
            "status must report an Active record as ready from METADATA -- if this fails, \
             status is consulting the refresh path, which no adapter can satisfy here"
        );
        assert!(
            result.record_version.is_some(),
            "status must serve the cursor without a provider call"
        );
        assert!(
            result.last_error_code.is_none(),
            "a stale-but-active credential is not an error to status: staleness is the \
             refresh path's business, and status does not go there"
        );
    }

    /// `status` must carry the record version, because a consumer waiting for a
    /// credential to come back has no other cheap way to see that it did.
    ///
    /// THE VAULT CANNOT PUSH -- subc has no module-to-client relay by design -- so a
    /// consumer must ask. Before this, the only way to observe a change was
    /// `credential.get`, which MINTS on a stale record: polling for repair meant buying
    /// upstream token exchanges, and a consumer avoiding that cost would notice late.
    ///
    /// Asserted as a CURSOR rather than as a field being present: the version must MOVE
    /// across a replace, and must be ABSENT where there is nothing to version. A field
    /// that is always Some(1) would satisfy a presence check and be useless.
    #[tokio::test]
    async fn status_carries_a_record_version_that_moves_on_replace() {
        let (surface, store, _db) = tmp_surface_with_store(16);
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let before = surface
            .status(
                1,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                },
            )
            .await;
        let v_before = before
            .record_version
            .expect("a resolved handle must report its version");

        // A replace is the shape an operator re-auth takes, and the transition a waiting
        // consumer needs to notice.
        store
            .overwrite_unconditional_audited(
                "apikey:active",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k2".to_vec(), None),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("replace");

        let after = surface
            .status(
                1,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                },
            )
            .await;
        let v_after = after.record_version.expect("still resolves");
        assert!(
            v_after > v_before,
            "the version must MOVE on replace or it is not a cursor: {v_before} -> {v_after}"
        );

        // ABSENT where there is nothing to version. A sentinel here would compare as
        // older than everything, so a poller would read a dead handle as a pending
        // change forever.
        let overall = surface
            .status(1, &crate::read_surface::StatusParams { handle: None })
            .await;
        assert!(
            overall.record_version.is_none(),
            "overall readiness has no credential to version"
        );
        let unknown = surface
            .status(
                2,
                &crate::read_surface::StatusParams {
                    handle: Some("ckh_definitely-not-a-handle".to_string()),
                },
            )
            .await;
        assert!(
            unknown.record_version.is_none(),
            "an unresolvable handle must not report a version"
        );
    }

    /// The mark that predicts a SLOW get on a record every other field calls healthy.
    ///
    /// Pins the exact reading that was invisible before this field existed: `ready:
    /// true`, `last_error_code: null`, and the next `get` about to buy an upstream token
    /// exchange. A consumer sizing a startup bound cannot get that from `ready`, because
    /// `ready` is genuinely TRUE -- the mark exists so the next get refreshes rather than
    /// refusing.
    ///
    /// The fixture is `oauth:stub` -- refreshable per `default_refresh_adapter` -- and the
    /// mark is driven through the PUBLIC `report_auth_failure` route, the only call that
    /// can ever set the marker on a real handle. The previous version seeded
    /// `apikey:active` and called `store.mark_stale_if_version_reported` directly, which
    /// constructs a state (non-refreshable + Active + `stale_pending = 1`) the production
    /// path cannot produce: the public route branches on refreshability and the
    /// non-refreshable arm INVALIDATES rather than marks, so the test was passing against
    /// a hand-staged copy of the mark with no assertion behind it.
    #[tokio::test]
    async fn status_publishes_the_stale_mark_without_calling_the_credential_unhealthy() {
        let (surface, store, _db) = tmp_surface_with_store(16);
        store
            .create(
                "oauth:stub",
                &VaultRecord::new_oauth(
                    "test",
                    "stub",
                    OAuthCredential {
                        access_token: "locally-valid".into(),
                        refresh_token: "rt".into(),
                        expires_at_ms: Some(i64::MAX),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        scopes: Vec::new(),
                    },
                    b"locally-valid".to_vec(),
                ),
            )
            .expect("seed refreshable credential");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:stub",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        let clean = surface
            .status(
                1,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                },
            )
            .await;
        assert_eq!(
            clean.stale_pending,
            Some(false),
            "a resolved handle must report the mark explicitly, not by omission"
        );
        assert!(clean.ready, "precondition: the record starts healthy");

        // Exactly what a consumer's 401 report does: the public route sees a refreshable
        // id and chooses the stale arm, so the record stays Active and `stale_pending`
        // flips to 1. Going through `report_auth_failure` rather than the store method is
        // the point -- the version-gated invalidate arm on the non-refreshable path is the
        // shape that has to be bypassed for a hand-staged mark to be possible.
        surface
            .report_auth_failure(
                1,
                &read_surface::ReportAuthFailureParams {
                    handle: handle.raw.clone(),
                    provider_status: 401,
                    record_version: 1,
                },
            )
            .await
            .expect("report accepted");

        let marked = surface
            .status(
                1,
                &crate::read_surface::StatusParams {
                    handle: Some(handle.raw.clone()),
                },
            )
            .await;
        assert_eq!(
            marked.stale_pending,
            Some(true),
            "the mark must be visible WITHOUT calling get -- the whole point is to avoid \
             the call whose cost is in question"
        );
        // The load-bearing half. If this ever flips to false, the field has been folded
        // into health and a consumer will start treating a usable credential as broken.
        assert!(
            marked.ready,
            "a stale-marked record is still USABLE -- expensive is not unhealthy"
        );
        assert!(
            marked.last_error_code.is_none(),
            "a pending repair is not an error that has occurred"
        );

        // ABSENT, never defaulted false: claiming "no repair pending" for a record this
        // path could not read would be an assertion with no basis behind it.
        let overall = surface
            .status(1, &crate::read_surface::StatusParams { handle: None })
            .await;
        assert!(
            overall.stale_pending.is_none(),
            "overall readiness names no credential, so it can report no mark"
        );
        let unknown = surface
            .status(
                2,
                &crate::read_surface::StatusParams {
                    handle: Some("ckh_definitely-not-a-handle".to_string()),
                },
            )
            .await;
        assert!(
            unknown.stale_pending.is_none(),
            "an unresolvable handle must not assert anything about a record"
        );
    }

    /// The stale-pending mark must NOT advertise an upstream exchange on a record the
    /// next `get` will refuse out of hand.
    ///
    /// Pins the second half of the field's contract: it is a LATENCY PREDICTOR, not a
    /// claim that anything is happening. A consumer reading `stale_pending: true`
    /// concludes the next get is going to spend seconds on a token exchange -- the very
    /// reason this field exists -- and will SKIP the credential in a startup warm bound.
    /// Skipping is the only safe behaviour when the mark is true, because the alternative
    /// is paying the exchange that the mark warned about.
    ///
    /// The construction reproduces the live shape on this deployment every four hours,
    /// measured 2026-08-27: a consumer 401 marks a refreshable record stale, the forced
    /// refresh fails, the engine latches the record to `needs_reauth`, and `stale_pending`
    /// is left at 1 because none of the seven `UPDATE credentials SET state = ...` paths
    /// in `credentials-core::store` clear the column. The mark is then a five-minute lie:
    /// `stale_pending: true` says "next get pays seconds" while the next get fails fast
    /// with `needs_reauth` without touching the network.
    ///
    /// The state is constructed through the production paths (public `report_auth_failure`
    /// sets the mark, the same `store.invalidate` the engine uses after a failed refresh
    /// flips the state), so the test is a real reading of the buggy state rather than a
    /// hand-staged copy of it. A pure store-level construction would pass without ever
    /// proving the public route is part of the path that creates it.
    #[tokio::test]
    async fn status_does_not_publish_a_stale_pending_mark_on_a_non_active_record() {
        let (surface, store, _db) = tmp_surface_with_store(17);
        store
            .create(
                "oauth:needs_reauth_after_stale",
                &VaultRecord::new_oauth(
                    "test",
                    "stub",
                    OAuthCredential {
                        access_token: "locally-valid".into(),
                        refresh_token: "rt".into(),
                        expires_at_ms: Some(i64::MAX),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        scopes: Vec::new(),
                    },
                    b"locally-valid".to_vec(),
                ),
            )
            .expect("seed refreshable credential");
        let raw = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &raw.hash,
                "oauth:needs_reauth_after_stale",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        // Production step 1: a consumer reports a 401 on the served version. The public
        // route is refreshable, so it MARKS STALE rather than invalidating; the record
        // stays Active and `stale_pending` becomes 1.
        surface
            .report_auth_failure(
                11,
                &read_surface::ReportAuthFailureParams {
                    handle: raw.raw.clone(),
                    provider_status: 401,
                    record_version: 1,
                },
            )
            .await
            .expect("report accepted");

        // Production step 2: a forced refresh then fails and the engine latches the record
        // to `needs_reauth`. The store call below is exactly what the engine reaches for
        // at the failure site; the column `stale_pending` is deliberately not touched by
        // any of the seven state-update paths, which is the bug we are pinning here.
        store
            .invalidate("oauth:needs_reauth_after_stale")
            .expect("engine-style invalidate after failed refresh");

        // Precondition checks: the construction actually reproduced the live shape, so a
        // green fix can be trusted to mean the fix is real and not a different test
        // passing for a different reason.
        let meta = store.meta("oauth:needs_reauth_after_stale").expect("meta");
        assert_eq!(
            meta.state,
            RecordState::NeedsReauth,
            "precondition: the construction must leave the record latched"
        );
        assert!(
            meta.stale_pending,
            "precondition: the bug is exactly that stale_pending survives a state flip"
        );

        // The pin. Non-Active state => next get performs no upstream exchange, so the
        // field is FALSE regardless of the column. Absent is reserved for "this path
        // could not see the record" and must NOT be used here -- a defaulted false on a
        // known record would be a defensible reading, an absent one would be a missing
        // field that looks like a wire-drift to a consumer.
        let got = surface
            .status(
                11,
                &crate::read_surface::StatusParams {
                    handle: Some(raw.raw),
                },
            )
            .await;
        assert_eq!(
            got.stale_pending,
            Some(false),
            "non-Active state must publish the real (false) prediction, not the column's \
             stale value -- a consumer skipping the credential on stale_pending=true \
             would be skipping a credential whose next get refuses without an exchange"
        );
        assert!(
            !got.ready,
            "a latched record is not ready -- the rest of the contract is unchanged"
        );
        assert_eq!(
            got.last_error_code,
            Some(read_surface::ReadError::NeedsReauth),
            "a needs_reauth record must name the reason"
        );
    }

    #[tokio::test]
    async fn status_handle_probe_runs_the_limiter() {
        let (surface, store, _db) = tmp_surface_with_store(15);
        // Sweep more distinct unknown handles than the distinct ceiling (16) on ONE
        // connection, all via status (not get). None resolve — the probe itself is the
        // signal — so this must still trip the anomaly.
        for i in 0..20 {
            let params = StatusParams {
                handle: Some(format!("ckh_unknown_{i}")),
            };
            let _ = surface.status(77, &params).await;
        }
        let alarms = store
            .read_audit(None)
            .expect("read audit")
            .into_iter()
            .filter(|e| e.op == "fetch_anomaly")
            .count();
        assert!(
            alarms >= 1,
            "a status sweep of unknown handles must raise a durable fetch-anomaly alarm"
        );
    }

    /// Wire v2 layer-2 validation (spec §3.3): a route frame whose epoch does not
    /// match the locally-installed binding — or whose slot is unknown — is dropped
    /// silently BEFORE dispatch: no Response, no Error (an Error would inject into
    /// the corr space of the slot's next tenant), and no lifecycle effect (a stale
    /// Goodbye must not tear down the new binding's admin state). Non-vacuous: the
    /// same frame at the CORRECT epoch is answered, so the drop discriminates the
    /// epoch check, not a broken dispatch path.
    #[tokio::test]
    async fn stale_epoch_route_frames_are_dropped_before_dispatch() {
        let surface = tmp_surface(21);
        let (admin, _admin_store) = tmp_admin(21);
        let (control_tx, _control_rx) = mpsc::channel::<Frame>(8);
        let (route_tx, mut route_rx) = mpsc::channel::<Frame>(8);
        let egress = Egress {
            control: control_tx,
            route: route_tx,
        };
        let routes = Arc::new(RouteEpochs::default());
        // The binding for channel 9 is at epoch 2 (a rebind after epoch 1 released).
        routes.install(9, 2);

        fn status_request(channel: u16, epoch: u32, corr: u64) -> Frame {
            Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                channel,
                epoch,
                corr,
                serde_json::to_vec(&json!({ "method": "credential.status", "params": {} }))
                    .unwrap(),
            )
            .unwrap()
        }

        // (a) Stale epoch (1) on a live slot: dropped, no frame egresses.
        assert!(
            handle_frame(status_request(9, 1, 50), &egress, &surface, &admin, &routes)
                .await
                .unwrap()
        );
        // (b) Unknown slot entirely: dropped too.
        assert!(handle_frame(
            status_request(10, 1, 51),
            &egress,
            &surface,
            &admin,
            &routes
        )
        .await
        .unwrap());
        // (c) A stale-epoch Goodbye must NOT remove the live binding.
        let stale_goodbye = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Goodbye,
            Flags::new(false, Priority::Interactive, false),
            9,
            1,
            0,
            Vec::new(),
        )
        .unwrap();
        assert!(
            handle_frame(stale_goodbye, &egress, &surface, &admin, &routes)
                .await
                .unwrap()
        );
        assert!(
            routes.matches(9, 2),
            "a stale-epoch goodbye must not tear down the live binding"
        );

        // Nothing was dispatched for any of the three stale frames.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            route_rx.try_recv().is_err(),
            "stale frames must produce no response and no error"
        );

        // (d) The SAME request at the correct epoch is answered — the drops above
        // discriminate the epoch check, not a broken dispatch path.
        assert!(
            handle_frame(status_request(9, 2, 52), &egress, &surface, &admin, &routes)
                .await
                .unwrap()
        );
        let answered = tokio::time::timeout(std::time::Duration::from_secs(2), route_rx.recv())
            .await
            .expect("the valid-epoch request must be answered")
            .expect("route lane open");
        assert_eq!(answered.header.channel, 9);
        assert_eq!(
            answered.header.epoch, 2,
            "the response echoes the binding epoch"
        );
        assert_eq!(answered.header.corr, 52);
    }

    /// A cookie header is an opaque request artifact. The storage and read paths must
    /// preserve every byte rather than treating its separators or spaces as structure.
    #[tokio::test]
    async fn cookie_record_round_trips_byte_exact_through_seal_and_serve() {
        let (surface, store, _db) = tmp_surface_with_store(74);
        let payload = b" session=abc=123; preference=space value; ending=%".to_vec();
        store
            .create(
                "cookie:opencode.ai",
                &VaultRecord::new_cookie("operator", payload.clone()),
            )
            .expect("seal cookie record");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "cookie:opencode.ai",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        let outcome = surface
            .get(
                78,
                &read_surface::GetParams {
                    handle: handle.raw,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(result) = outcome else {
            panic!("a stored cookie must serve through credential.get");
        };
        assert_eq!(
            result.payload, payload,
            "cookie bytes must survive seal and serve"
        );
        assert_eq!(
            result.expires_at_ms, None,
            "cookies carry no declared expiry"
        );
        assert_eq!(result.account_id, None, "cookies do not disclose identity");
        assert_eq!(result.email, None, "cookies do not disclose identity");
        assert_eq!(result.org_name, None, "cookies do not disclose identity");
    }

    /// A legacy malformed row must never become a successful zero-byte credential.
    /// The fixture uses an OAuth-kind record with no refresh state so the current store
    /// can represent the historical bad row without bypassing the new static-write
    /// invariant; removing the read guard makes this test return `Ok([])`.
    #[tokio::test]
    async fn get_quarantines_an_empty_nonrefreshable_record() {
        use credentials_core::store::RecordState;

        let (surface, store, _db) = tmp_surface_with_store(20);
        let mut legacy = VaultRecord::new_oauth(
            "legacy-import",
            "legacy",
            credentials_core::oauth::OAuthCredential {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at_ms: None,
                token_url: String::new(),
                client_id: None,
                scopes: Vec::new(),
            },
            Vec::new(),
        );
        legacy.refresh_adapter = None;
        legacy.oauth = None;
        store
            .create("oauth:legacy-empty", &legacy)
            .expect("seed representable legacy record");
        let handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:legacy-empty",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        let got = surface
            .get(
                77,
                &read_surface::GetParams {
                    handle: handle.raw,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Err { error } = got else {
            panic!("empty legacy payload must not be returned as success");
        };
        assert_eq!(error.code, read_surface::ReadError::Corrupt);
        assert_eq!(error.class, read_surface::ErrorClass::Permanent);
        assert_eq!(
            store.meta("oauth:legacy-empty").expect("meta").state,
            RecordState::Corrupt,
            "the exact inspected version must be quarantined"
        );
    }

    /// A retired credential is not served, but it uses the same consumer-visible
    /// `auth_required` refusal as `needs_reauth`. The distinction is operational state
    /// for the admin surface, not a recovery branch for consumers.
    #[tokio::test]
    async fn retired_reads_use_the_same_auth_required_refusal_as_needs_reauth() {
        let (surface, store, _db) = tmp_surface_with_store(21);
        store
            .create(
                "apikey:retired",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None),
            )
            .expect("create retired credential");
        store
            .retire_and_revoke_all_audited("apikey:retired", AuditCtx::admin(AuditOp::Invalidate))
            .expect("retire credential");

        let mint_for = |id: &str| {
            let handle = credentials_core::store::mint_handle().expect("mint handle");
            store
                .put_handle_hash(&handle.hash, id, AuditCtx::admin(AuditOp::MintHandle))
                .expect("store handle");
            handle.raw
        };
        let needs_reauth_handle = mint_for("apikey:dead");
        let retired_handle = mint_for("apikey:retired");

        let needs_reauth = surface
            .get(
                51,
                &read_surface::GetParams {
                    handle: needs_reauth_handle,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Err {
            error: needs_reauth_error,
        } = needs_reauth
        else {
            panic!("needs_reauth credential must refuse reads");
        };

        let retired = surface
            .get(
                52,
                &read_surface::GetParams {
                    handle: retired_handle,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Err {
            error: retired_error,
        } = retired
        else {
            panic!("retired credential must refuse reads");
        };

        assert_eq!(
            needs_reauth_error.code,
            read_surface::ReadError::NeedsReauth
        );
        assert_eq!(
            needs_reauth_error.class,
            read_surface::ErrorClass::AuthRequired
        );
        assert_eq!(retired_error.code, needs_reauth_error.code);
        assert_eq!(retired_error.class, needs_reauth_error.class);
    }

    /// A static record keeps the terminal report-auth-failure behavior: it invalidates
    /// ONLY on 401/403, and ONLY at the record version the consumer was served.
    ///
    /// This is the one read-surface op that MUTATES, and each arm is load-bearing.
    /// Without the accepted arm, an implementation ignoring every report would pass;
    /// without the non-auth-status arm, one invalidating on any status would pass;
    /// without the stale-version arm, one ignoring the version and killing whatever is
    /// current would pass. The three wrong shapes are, respectively: a dead token served
    /// forever, a provider 500 nuking a healthy credential, and a slow consumer's stale
    /// 401 destroying a credential the vault has already repaired.
    #[tokio::test]
    async fn report_auth_failure_invalidates_only_on_auth_status_at_the_served_version() {
        use credentials_core::store::RecordState;

        let (surface, store, _db) = tmp_surface_with_store(31);
        let raw = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &raw.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");
        let handle = raw.raw;

        let state_of = |store: &EncryptedStore| {
            store
                .list_meta()
                .expect("list meta")
                .into_iter()
                .find(|(id, _)| id == "apikey:active")
                .expect("seeded credential is present")
                .1
                .state
        };
        let params = |status: u16, version: u64| read_surface::ReportAuthFailureParams {
            handle: handle.clone(),
            provider_status: status,
            record_version: version,
        };

        // A NON-AUTH status must not invalidate: a provider 500 is a hiccup, not a dead
        // credential.
        surface
            .report_auth_failure(7, &params(500, 1))
            .await
            .expect("a non-auth status is accepted");
        assert_eq!(
            state_of(&store),
            RecordState::Active,
            "a 500 must leave the credential serving"
        );

        // A STALE version must be a silent no-op. Bump the record past what our reporter
        // holds, exactly as a refresh would, then report the OLD version.
        store
            .overwrite_unconditional_audited(
                "apikey:active",
                &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k2".to_vec(), None),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("bump the record version");
        surface
            .report_auth_failure(7, &params(401, 1))
            .await
            .expect("a stale report is accepted, not errored");
        assert_eq!(
            state_of(&store),
            RecordState::Active,
            "a 401 for a version the vault has moved past must NOT invalidate: that \
             credential was already repaired"
        );

        // THE ACCEPTED ARM. Without it, an implementation that ignored every report
        // satisfies both assertions above.
        surface
            .report_auth_failure(7, &params(401, 2))
            .await
            .expect("a current-version 401 is accepted");
        assert_eq!(
            state_of(&store),
            RecordState::NeedsReauth,
            "a 401 at the served version must stop the vault serving that token"
        );
        assert!(
            !store.meta("apikey:active").expect("meta").stale_pending,
            "a non-refreshable record must latch rather than setting a useless stale marker"
        );
        let health = credentials_core::health::VaultHealth::summarize(
            &store.list_meta().expect("list reported credential"),
            0,
            false,
        );
        assert_eq!(
            health.status,
            credentials_core::health::VaultHealthStatus::Degraded,
            "a consumer-discovered failure must remain an alarm, not become retired"
        );
        let events = store.recent_auth_events(10).expect("events");
        assert_eq!(events[0].kind, "consumer_report_latch");
        assert!(
            events[0].applied,
            "the current static report must be recorded as applied"
        );

        // An unknown handle gets the same refusal as a revoked one, so a caller cannot
        // use this endpoint to discover which handles exist.
        let unknown = surface
            .report_auth_failure(
                7,
                &read_surface::ReportAuthFailureParams {
                    handle: "ckh_not_a_handle".to_string(),
                    provider_status: 401,
                    record_version: 1,
                },
            )
            .await;
        assert!(
            matches!(unknown, Err(read_surface::ReadError::NotFound)),
            "an unknown handle must be a uniform not_found, got {unknown:?}"
        );
    }

    /// A refreshable report keeps the credential active and schedules its existing
    /// refresh-on-read path instead of terminally latching it.
    #[tokio::test]
    async fn report_auth_failure_marks_a_refreshable_record_stale() {
        use credentials_core::oauth::OAuthCredential;
        use credentials_core::store::RecordState;

        let (surface, store, _db) = tmp_surface_with_store(85);
        store
            .create(
                "oauth:stub",
                &VaultRecord::new_oauth(
                    "stub",
                    "stub",
                    OAuthCredential {
                        access_token: "still-locally-valid".into(),
                        refresh_token: "refresh".into(),
                        expires_at_ms: Some(i64::MAX),
                        token_url: "https://example.invalid/token".into(),
                        client_id: None,
                        scopes: Vec::new(),
                    },
                    b"still-locally-valid".to_vec(),
                ),
            )
            .expect("create refreshable record");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:stub",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        surface
            .report_auth_failure(
                8,
                &read_surface::ReportAuthFailureParams {
                    handle: handle.raw,
                    provider_status: 401,
                    record_version: 1,
                },
            )
            .await
            .expect("report succeeds with its existing wire reply");

        let meta = store.meta("oauth:stub").expect("meta");
        assert_eq!(meta.state, RecordState::Active);
        assert!(
            meta.stale_pending,
            "the next get must be driven through refresh"
        );
        assert_eq!(
            meta.record_version, 1,
            "a local stale marker must not move the version"
        );
        let events = store.recent_auth_events(10).expect("events");
        assert_eq!(events[0].kind, "consumer_report_stale");
        assert!(
            events[0].applied,
            "the current refreshable report must apply"
        );
    }

    /// An `oauth:` spelling does not make a static record refreshable. The report first
    /// reaches the ID-derived stale arm, then the engine must use the opened record's
    /// authoritative predicate and terminally latch it rather than serving it again.
    #[tokio::test]
    async fn report_on_a_static_oauth_shaped_id_latches_on_the_next_get() {
        use credentials_core::store::RecordState;

        let (surface, store, _db) = tmp_surface_with_store(86);
        store
            .create(
                "oauth:anthropic",
                &VaultRecord::new_static(
                    CredentialKind::ApiKey,
                    "put",
                    b"static-key".to_vec(),
                    None,
                ),
            )
            .expect("put static record with oauth-shaped id");
        let handle = credentials_core::store::mint_handle().expect("mint handle");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:anthropic",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("bind handle");

        surface
            .report_auth_failure(
                9,
                &read_surface::ReportAuthFailureParams {
                    handle: handle.raw.clone(),
                    provider_status: 401,
                    record_version: 1,
                },
            )
            .await
            .expect("report succeeds");
        assert!(
            store.meta("oauth:anthropic").expect("meta").stale_pending,
            "the ID-derived report arm sets the marker before the engine opens the record"
        );

        let result = surface
            .get(
                9,
                &read_surface::GetParams {
                    handle: handle.raw,
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Err { error } = result else {
            panic!("a reported static record must not be served again");
        };
        assert_eq!(error.code, read_surface::ReadError::NeedsReauth);
        let meta = store.meta("oauth:anthropic").expect("meta");
        assert_eq!(meta.state, RecordState::NeedsReauth);
        let events = store.recent_auth_events(10).expect("events");
        assert_eq!(events[0].kind, "stale_nonrefreshable_latch");
        assert!(
            events[0].applied,
            "the engine backstop must make the terminal transition"
        );
    }

    /// `get_many` serves a batch at the cap and refuses one item past it, WHOLE rather
    /// than truncated. The at-cap arm is what gives the over-cap arm its meaning: a
    /// `get_many` that refused unconditionally would satisfy every over-cap assertion in
    /// this repo, since nothing else calls it with an accepted batch.
    #[tokio::test]
    async fn get_many_serves_at_the_cap_and_refuses_whole_past_it() {
        use crate::limiter::GET_MANY_MAX;

        let (surface, store, _db) = tmp_surface_with_store(24);
        let mut handles = Vec::new();
        for i in 0..GET_MANY_MAX {
            let id = format!("apikey:batch-{i}");
            let payload = format!("secret-{i}").into_bytes();
            store
                .create(
                    &id,
                    &VaultRecord::new_static(
                        credentials_core::record::CredentialKind::ApiKey,
                        "test",
                        payload,
                        None,
                    ),
                )
                .expect("seed batch record");
            let handle = credentials_core::store::mint_handle().expect("mint");
            store
                .put_handle_hash(&handle.hash, &id, AuditCtx::admin(AuditOp::MintHandle))
                .expect("put handle");
            handles.push(handle.raw);
        }
        let params = |raws: &[String]| read_surface::GetManyParams {
            items: raws
                .iter()
                .map(|raw| read_surface::GetParams {
                    handle: raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                })
                .collect(),
        };

        // AT the cap: every item is served, with its own payload — so the batch path
        // works and the refusal below is about the bound, not about get_many at all.
        //
        // WHAT THIS TEST CANNOT PROVE, stated so nobody reads it as covering more: it
        // seeds GET_MANY_MAX handles and asserts against GET_MANY_MAX, so both sides
        // move together and the cap's VALUE is invisible here — measured, widening it
        // to 1000 leaves this green. That is the correct scope for a unit test of the
        // batch path, but it means the value is pinned elsewhere: the e2e arm
        // `real_daemon_over_cap_get_many_is_rejected` sends a literal 9 items over the
        // wire and fails if the cap moves. Deleting that arm would leave the bound
        // unproven while this test stays green.
        let served = surface.get_many(81, &params(&handles)).await;
        assert_eq!(served.len(), GET_MANY_MAX, "a batch at the cap is served");
        for (i, outcome) in served.iter().enumerate() {
            let read_surface::GetOutcome::Ok(result) = outcome else {
                panic!("item {i} must serve at the cap, got {outcome:?}");
            };
            assert_eq!(result.payload, format!("secret-{i}").into_bytes());
        }

        // ONE past the cap: a single refusal for the whole call. A truncating
        // implementation would return GET_MANY_MAX outcomes here instead.
        let mut over = handles.clone();
        over.push(handles[0].clone());
        let refused = surface.get_many(81, &params(&over)).await;
        assert_eq!(refused.len(), 1, "over-cap is refused whole, not truncated");
        let read_surface::GetOutcome::Err { error } = &refused[0] else {
            panic!("over-cap must refuse");
        };
        assert_eq!(error.code, read_surface::ReadError::TooManyItems);
        assert_eq!(error.class, read_surface::ErrorClass::ContextOverflow);
    }

    /// End-to-end: `get` surfaces the provider account identity for a chatgpt:openai
    /// record, parsed LIVE from the served access token's claim, and returns None for a
    /// record whose provider has no account claim (here an api-key with no adapter). This
    /// is the vault leg of account-scoped routing: the consumer joins (handle,
    /// record_version) -> account_id on this field. Non-vacuous — a real seeded oauth
    /// record flows through the real ReadSurface::get path, and the negative arm proves
    /// the field is not unconditionally populated.
    #[tokio::test]
    async fn get_surfaces_account_id_for_chatgpt_openai_and_none_otherwise() {
        use credentials_core::oauth::OAuthCredential;

        let (surface, store, _db) = tmp_surface_with_store(21);

        // A faithful OpenAI access-token JWT carrying the nested claim path
        // "https://api.openai.com/auth"."chatgpt_account_id" = "acct-e2e-7". Unsigned
        // (claims decoding never verifies the signature; transport is the trust anchor).
        let access_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.\
             eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC1lMmUtNyJ9fQ.\
             sig";
        let oauth = OAuthCredential {
            access_token: access_jwt.to_string(),
            refresh_token: "ref".to_string(),
            // Far-future expiry so the record is not stale and `get` serves it as-is
            // (no refresh, no network) — isolating the account_id surfacing.
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://auth.openai.com/oauth/token".to_string(),
            client_id: Some("app_x".to_string()),
            scopes: Vec::new(),
        };
        let record =
            VaultRecord::new_oauth("login", "openai", oauth, access_jwt.as_bytes().to_vec());
        store
            .create("chatgpt:openai", &record)
            .expect("create chatgpt record");
        let oauth_handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &oauth_handle.hash,
                "chatgpt:openai",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put oauth handle");

        // A handle for the seeded api-key record (no adapter → no account claim).
        let apikey_handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &apikey_handle.hash,
                "apikey:active",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put apikey handle");

        let got = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: oauth_handle.raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(result) = got else {
            panic!("expected an Ok get for the chatgpt:openai handle");
        };
        assert_eq!(
            result.account_id.as_deref(),
            Some("acct-e2e-7"),
            "get must surface the ChatGPT account id parsed from the served access token"
        );

        let got_apikey = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: apikey_handle.raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(apikey_result) = got_apikey else {
            panic!("expected an Ok get for the api-key handle");
        };
        assert_eq!(
            apikey_result.account_id, None,
            "a record with no account-claim provider must not carry an account_id"
        );
    }

    /// End-to-end: `get` serves stored login-time identity (email + org_name +
    /// account_id fallback) for an opaque-token provider (anthropic), and serves NO
    /// identity fields for a pre-identity record (the additive-schema arm: old
    /// records decode with an empty identity and the wire omits the fields). This is
    /// the QTA display-label leg: email must ride WITH account_id, both from the
    /// stored identity, because an opaque access token has no live-parse path.
    #[tokio::test]
    async fn get_serves_stored_identity_for_anthropic_and_none_for_legacy_records() {
        use credentials_core::oauth::OAuthCredential;
        use credentials_core::record::RecordIdentity;

        let (surface, store, _db) = tmp_surface_with_store(22);

        let oauth = OAuthCredential {
            // Opaque (non-JWT) access token — the live claim parse yields nothing,
            // so any served identity provably comes from the stored RecordIdentity.
            access_token: "sk-ant-oat01-opaque".to_string(),
            refresh_token: "ref".to_string(),
            expires_at_ms: Some(4_102_444_800_000),
            token_url: "https://api.anthropic.com/v1/oauth/token".to_string(),
            client_id: Some("client".to_string()),
            scopes: Vec::new(),
        };
        let record = VaultRecord::new_oauth(
            "login",
            "anthropic",
            oauth.clone(),
            b"sk-ant-oat01-opaque".to_vec(),
        )
        .with_identity(RecordIdentity {
            account_id: Some("anthropic-acct-uuid".to_string()),
            email: Some("op@example.com".to_string()),
            org_name: Some("op@example.com's Organization".to_string()),
        });
        store
            .create("oauth:anthropic:work", &record)
            .expect("create labeled anthropic record");
        let handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &handle.hash,
                "oauth:anthropic:work",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put handle");

        // A legacy-shaped record with NO identity (pre-identity mint).
        let legacy = VaultRecord::new_oauth("login", "anthropic", oauth, b"tok".to_vec());
        store
            .create("oauth:anthropic", &legacy)
            .expect("create legacy record");
        let legacy_handle = credentials_core::store::mint_handle().expect("mint");
        store
            .put_handle_hash(
                &legacy_handle.hash,
                "oauth:anthropic",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .expect("put legacy handle");

        let got = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: handle.raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(result) = got else {
            panic!("expected an Ok get for the labeled anthropic handle");
        };
        assert_eq!(result.email.as_deref(), Some("op@example.com"));
        assert_eq!(
            result.org_name.as_deref(),
            Some("op@example.com's Organization")
        );
        assert_eq!(
            result.account_id.as_deref(),
            Some("anthropic-acct-uuid"),
            "account_id must fall back to stored identity for opaque tokens \
             (QTA invariant: email never ships without account_id)"
        );

        let got_legacy = surface
            .get(
                1,
                &read_surface::GetParams {
                    handle: legacy_handle.raw.clone(),
                    min_ttl_ms: None,
                    force_refresh: false,
                },
            )
            .await;
        let read_surface::GetOutcome::Ok(legacy_result) = got_legacy else {
            panic!("expected an Ok get for the legacy handle");
        };
        assert_eq!(legacy_result.email, None);
        assert_eq!(legacy_result.org_name, None);
        assert_eq!(legacy_result.account_id, None);
    }
}
