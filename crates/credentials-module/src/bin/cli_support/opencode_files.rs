use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
const AUTH_FILE_MAX_BYTES: u64 = 1024 * 1024;
const HANDLE_FILE_MAX_BYTES: u64 = 256 * 1024;
const MANIFEST_LOCK_TTL_MS: u64 = 30_000;
const MANIFEST_LOCK_RENEW_EVERY_MS: u64 = 10_000;
const MANIFEST_LOCK_OWNER_KEYS: [&str; 4] = ["tenant", "pid", "claimed_at_ms", "nonce"];
const MANIFEST_LOCK_STALE_TARGET_PATTERN: &str = r"^\.lock\.stale-\d+-[A-Za-z0-9_-]+$";
const OPENCODE_CLAUSTRUM_TENANT: &str = "opencode-claustrum";
type BeforeManifestRename = Arc<dyn Fn(&Path) + Send + Sync>;

#[cfg(test)]
static LEASE_LOST_WARNINGS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct ManifestLockOptions {
    ttl: Duration,
    renew_every: Duration,
    retry_min: Duration,
    retry_max: Duration,
    after_claim: Option<Arc<dyn Fn() + Send + Sync>>,
    before_evict: Option<Arc<dyn Fn() + Send + Sync>>,
    after_evict: Option<Arc<dyn Fn() + Send + Sync>>,
    before_manifest_rename: Option<BeforeManifestRename>,
}

impl Default for ManifestLockOptions {
    fn default() -> Self {
        Self {
            ttl: Duration::from_millis(MANIFEST_LOCK_TTL_MS),
            renew_every: Duration::from_millis(MANIFEST_LOCK_RENEW_EVERY_MS),
            retry_min: Duration::from_millis(25),
            retry_max: Duration::from_millis(75),
            after_claim: None,
            before_evict: None,
            after_evict: None,
            before_manifest_rename: None,
        }
    }
}

struct ManifestLease {
    lock: PathBuf,
    nonce: String,
    ttl: Duration,
    renewal_failed: Arc<AtomicBool>,
    stop_tx: Option<mpsc::Sender<()>>,
    renewal: Option<thread::JoinHandle<()>>,
}

impl ManifestLease {
    fn stop_renewal(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(renewal) = self.renewal.take() {
            let _ = renewal.join();
        }
    }

    fn commit(&mut self) -> Result<(), OpenCodeFilesError> {
        self.stop_renewal();
        let owner = read_lock_owner(&self.lock.join("owner")).ok();
        let ours_and_fresh = owner.is_some_and(|owner| {
            owner.nonce == self.nonce
                && current_time_ms().is_ok_and(|now| {
                    now.saturating_sub(owner.claimed_at_ms) < self.ttl.as_millis() as u64
                })
        });
        if self.renewal_failed.load(Ordering::SeqCst) || !ours_and_fresh {
            return Err(OpenCodeFilesError::Invalid(
                "manifest lock renewal failed; write aborted".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestLockOwner {
    tenant: String,
    pid: u32,
    claimed_at_ms: u64,
    nonce: String,
}

#[derive(Debug)]
pub enum OpenCodeFilesError {
    Io {
        action: &'static str,
        source: std::io::Error,
    },
    Json(serde_json::Error),
    InsecureParent {
        path: PathBuf,
        reason: &'static str,
    },
    Invalid(String),
}

impl fmt::Display for OpenCodeFilesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { action, source } => write!(f, "{action}: {source}"),
            Self::Json(source) => write!(f, "JSON: {source}"),
            Self::InsecureParent { path, reason } => {
                write!(
                    f,
                    "parent directory {} is insecure: {reason}",
                    path.display()
                )
            }
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for OpenCodeFilesError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstoneFixture {
    pub provider: String,
    pub entry: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstoneFixtures {
    pub api: TombstoneFixture,
    pub oauth: TombstoneFixture,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleFile {
    pub version: u64,
    pub providers: Vec<HandleProvider>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleProvider {
    pub provider: String,
    pub shape: HandleShape,
    #[serde(default)]
    pub serve: String,
    pub accounts: Vec<HandleAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandleShape {
    Api,
    Oauth,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAccount {
    pub label: String,
    pub handle: String,
    pub credential_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub superseded: Vec<String>,
}

impl fmt::Debug for HandleFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleFile")
            .field("version", &self.version)
            .field("providers", &self.providers)
            .finish()
    }
}

impl fmt::Debug for HandleProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleProvider")
            .field("provider", &self.provider)
            .field("shape", &self.shape)
            .field("serve", &self.serve)
            .field("accounts", &self.accounts)
            .finish()
    }
}

impl fmt::Debug for HandleAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleAccount")
            .field("label", &self.label)
            .field("handle", &"ckh_[redacted]")
            .field("credential_id", &self.credential_id)
            .field(
                "superseded",
                &format_args!("<{} ckh_[redacted]>", self.superseded.len()),
            )
            .finish()
    }
}

pub fn default_auth_path() -> PathBuf {
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/share"))
        })
        .unwrap_or_else(|| PathBuf::from(".local/share"));
    data_home.join("opencode").join("auth.json")
}

pub fn default_handle_path() -> PathBuf {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })
        .unwrap_or_else(|| PathBuf::from(".config"));
    config_home.join("cortexkit").join("opencode-handles.json")
}

pub fn golden_tombstone_fixtures() -> Result<TombstoneFixtures, OpenCodeFilesError> {
    let golden: Value = serde_json::from_str(include_str!(
        "../../../../../packages/opencode/golden/tombstone.json"
    ))
    .map_err(OpenCodeFilesError::Json)?;
    let fixture = |shape: &str| -> Result<TombstoneFixture, OpenCodeFilesError> {
        let item = &golden["fixtures"][shape];
        let provider = item["provider"]
            .as_str()
            .filter(|provider| !provider.is_empty())
            .ok_or_else(|| {
                OpenCodeFilesError::Invalid(format!("golden {shape} provider is invalid"))
            })?
            .to_string();
        let entry = item["entry"].clone();
        validate_auth_entry(&entry)?;
        Ok(TombstoneFixture { provider, entry })
    };
    Ok(TombstoneFixtures {
        api: fixture("api")?,
        oauth: fixture("oauth")?,
    })
}

pub fn read_auth_entries(path: &Path) -> Result<BTreeMap<String, Value>, OpenCodeFilesError> {
    validate_secure_file(path)?;
    let bytes = read_limited(path, AUTH_FILE_MAX_BYTES, "auth file")?;
    let entries: BTreeMap<String, Value> =
        serde_json::from_slice(&bytes).map_err(OpenCodeFilesError::Json)?;
    for (provider, entry) in &entries {
        validate_identifier(provider, "provider")?;
        validate_auth_entry(entry)?;
    }
    Ok(entries)
}

pub fn write_auth_entry(
    path: &Path,
    provider: &str,
    entry: Value,
) -> Result<(), OpenCodeFilesError> {
    validate_identifier(provider, "provider")?;
    validate_auth_entry(&entry)?;
    let mut entries = if path.exists() {
        read_auth_entries(path)?
    } else {
        BTreeMap::new()
    };
    entries.insert(provider.to_string(), entry);
    let bytes = serde_json::to_vec(&entries).map_err(OpenCodeFilesError::Json)?;
    write_atomic(path, &bytes, false)
}

pub fn verify_auth_written(
    path: &Path,
    provider: &str,
    expected: &Value,
) -> Result<(), OpenCodeFilesError> {
    let entries = read_auth_entries(path)?;
    if entries.get(provider) != Some(expected) {
        return Err(OpenCodeFilesError::Invalid(
            "auth entry did not persist exactly".into(),
        ));
    }
    Ok(())
}

pub fn read_handle_file(path: &Path) -> Result<HandleFile, OpenCodeFilesError> {
    validate_secure_file(path)?;
    let bytes = read_limited(path, HANDLE_FILE_MAX_BYTES, "handle file")?;
    let file: HandleFile = serde_json::from_slice(&bytes).map_err(OpenCodeFilesError::Json)?;
    validate_handle_file(&file)?;
    Ok(file)
}

pub fn write_handle_file(path: &Path, file: &HandleFile) -> Result<(), OpenCodeFilesError> {
    write_handle_file_for_tenant(
        path,
        OPENCODE_CLAUSTRUM_TENANT,
        file,
        ManifestLockOptions::default(),
    )
}

pub fn verify_handle_written(path: &Path, expected: &HandleFile) -> Result<(), OpenCodeFilesError> {
    validate_handle_file(expected)?;
    let written = read_handle_file(path)?;
    let expected_owned: Vec<_> = expected
        .providers
        .iter()
        .filter(|provider| provider.serve == OPENCODE_CLAUSTRUM_TENANT)
        .cloned()
        .collect();
    let written_owned: Vec<_> = written
        .providers
        .iter()
        .filter(|provider| provider.serve == OPENCODE_CLAUSTRUM_TENANT)
        .cloned()
        .collect();
    if written_owned != expected_owned {
        return Err(OpenCodeFilesError::Invalid(
            "handle file tenant block did not persist exactly".into(),
        ));
    }
    Ok(())
}

fn write_handle_file_for_tenant(
    path: &Path,
    tenant: &str,
    desired: &HandleFile,
    options: ManifestLockOptions,
) -> Result<(), OpenCodeFilesError> {
    validate_handle_file(desired)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| OpenCodeFilesError::Invalid("file path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|source| io_error("create parent directory", source))?;
    validate_secure_parent(parent)?;
    set_mode(parent, 0o700)?;
    let before_manifest_rename = options.before_manifest_rename.clone();
    with_manifest_lock_with_options(path, tenant, options, |lease| {
        let current = match fs::symlink_metadata(path) {
            Ok(_) => read_handle_file(path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HandleFile {
                version: 1,
                providers: Vec::new(),
            },
            Err(error) => return Err(io_error("stat handle file", error)),
        };
        let before_foreign: Vec<Vec<u8>> = current
            .providers
            .iter()
            .filter(|provider| provider.serve != tenant)
            .map(serde_json::to_vec)
            .collect::<Result<_, _>>()
            .map_err(OpenCodeFilesError::Json)?;
        let mut providers: Vec<_> = current
            .providers
            .into_iter()
            .filter(|provider| provider.serve != tenant)
            .collect();
        providers.extend(
            desired
                .providers
                .iter()
                .filter(|provider| provider.serve == tenant)
                .cloned(),
        );
        let next = HandleFile {
            version: 1,
            providers,
        };
        validate_handle_file(&next)?;
        let bytes = serde_json::to_vec(&next).map_err(OpenCodeFilesError::Json)?;
        write_atomic_guarded(path, &bytes, true, || {
            if let Some(before_manifest_rename) = &before_manifest_rename {
                before_manifest_rename(&lock_path(path));
            }
            lease.commit()
        })?;
        let readback = read_handle_file(path)?;
        if readback != next {
            return Err(OpenCodeFilesError::Invalid(
                "handle file readback did not persist exactly".into(),
            ));
        }
        let after_foreign: Vec<Vec<u8>> = readback
            .providers
            .iter()
            .filter(|provider| provider.serve != tenant)
            .map(serde_json::to_vec)
            .collect::<Result<_, _>>()
            .map_err(OpenCodeFilesError::Json)?;
        if after_foreign != before_foreign {
            return Err(OpenCodeFilesError::Invalid(
                "handle file readback changed another tenant block".into(),
            ));
        }
        Ok(())
    })
}

fn lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

fn current_time_ms() -> Result<u64, OpenCodeFilesError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| OpenCodeFilesError::Invalid("system clock is before UNIX epoch".into()))
}

fn random_nonce() -> Result<String, OpenCodeFilesError> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OpenCodeFilesError::Invalid("generate manifest lock nonce failed".into()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn io_error(action: &'static str, source: std::io::Error) -> OpenCodeFilesError {
    OpenCodeFilesError::Io { action, source }
}

fn parse_lock_owner(source: &str) -> Result<ManifestLockOwner, OpenCodeFilesError> {
    serde_json::from_str(source).map_err(OpenCodeFilesError::Json)
}

fn read_lock_owner(path: &Path) -> Result<ManifestLockOwner, OpenCodeFilesError> {
    let source =
        fs::read_to_string(path).map_err(|source| io_error("read manifest lock owner", source))?;
    parse_lock_owner(&source)
}

fn write_lock_owner(lock: &Path, owner: &ManifestLockOwner) -> Result<(), OpenCodeFilesError> {
    let owner_path = lock.join("owner");
    let temporary = lock.join(format!(
        "owner.{}.{}.tmp",
        std::process::id(),
        random_nonce()?
    ));
    let result = (|| -> Result<(), OpenCodeFilesError> {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|source| io_error("create manifest lock owner", source))?
        };
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| io_error("create manifest lock owner", source))?;
        set_mode(&temporary, 0o600)?;
        serde_json::to_writer(&mut file, owner).map_err(OpenCodeFilesError::Json)?;
        file.write_all(b"\n")
            .map_err(|source| io_error("write manifest lock owner", source))?;
        file.sync_all()
            .map_err(|source| io_error("sync manifest lock owner", source))?;
        drop(file);
        fs::rename(&temporary, &owner_path)
            .map_err(|source| io_error("rename manifest lock owner", source))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn stale_target_matches(value: &str) -> bool {
    let Some(rest) = value.strip_prefix(".lock.stale-") else {
        return false;
    };
    let Some((claimed, random)) = rest.split_once('-') else {
        return false;
    };
    !claimed.is_empty()
        && claimed.bytes().all(|byte| byte.is_ascii_digit())
        && !random.is_empty()
        && random
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn warn_lease_lost(path: &Path) {
    #[cfg(test)]
    LEASE_LOST_WARNINGS.fetch_add(1, Ordering::SeqCst);
    eprintln!(
        "manifest lock lease lost, not releasing: {}",
        path.display()
    );
}

fn jitter(options: &ManifestLockOptions) -> Duration {
    let min = options.retry_min.as_millis() as u64;
    let max = options.retry_max.as_millis() as u64;
    if max <= min {
        return Duration::from_millis(min);
    }
    let mut bytes = [0_u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return Duration::from_millis(min);
    }
    Duration::from_millis(min + u64::from_le_bytes(bytes) % (max - min + 1))
}

fn release_manifest_lock(
    path: &Path,
    lock: &Path,
    nonce: &str,
    ttl: Duration,
) -> Result<(), OpenCodeFilesError> {
    let owner = match read_lock_owner(&lock.join("owner")) {
        Ok(owner) => owner,
        Err(_) => {
            warn_lease_lost(path);
            return Ok(());
        }
    };
    let now = current_time_ms()?;
    if owner.nonce != nonce || now.saturating_sub(owner.claimed_at_ms) >= ttl.as_millis() as u64 {
        warn_lease_lost(path);
        return Ok(());
    }
    let release = PathBuf::from(format!("{}.release-{nonce}", lock.display()));
    if fs::rename(lock, &release).is_err() {
        warn_lease_lost(path);
        return Ok(());
    }
    let moved = read_lock_owner(&release.join("owner")).ok();
    let moved_is_ours = moved.is_some_and(|owner| {
        owner.nonce == nonce
            && current_time_ms()
                .is_ok_and(|now| now.saturating_sub(owner.claimed_at_ms) < ttl.as_millis() as u64)
    });
    if !moved_is_ours {
        let _ = fs::rename(&release, lock);
        warn_lease_lost(path);
        return Ok(());
    }
    fs::remove_dir_all(&release).map_err(|source| io_error("remove manifest lock", source))
}

fn with_manifest_lock_with_options<T, F>(
    path: &Path,
    tenant: &str,
    options: ManifestLockOptions,
    operation: F,
) -> Result<T, OpenCodeFilesError>
where
    F: FnOnce(&mut ManifestLease) -> Result<T, OpenCodeFilesError>,
{
    let lock = lock_path(path);
    let owner_path = lock.join("owner");
    let nonce = random_nonce()?;
    let started_at_ms = current_time_ms()?;
    let deadline = Instant::now() + options.ttl;
    loop {
        match fs::create_dir(&lock) {
            Ok(()) => {
                set_mode(&lock, 0o700)?;
                let owner = ManifestLockOwner {
                    tenant: tenant.into(),
                    pid: std::process::id(),
                    claimed_at_ms: current_time_ms()?,
                    nonce: nonce.clone(),
                };
                if let Err(error) = write_lock_owner(&lock, &owner) {
                    let _ = fs::remove_dir_all(&lock);
                    return Err(error);
                }
                if let Some(after_claim) = &options.after_claim {
                    after_claim();
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error("create manifest lock", error)),
        }

        if let Ok(observed) = read_lock_owner(&owner_path) {
            if started_at_ms.saturating_sub(observed.claimed_at_ms)
                >= options.ttl.as_millis() as u64
            {
                if let Some(before_evict) = &options.before_evict {
                    before_evict();
                }
                let stale = PathBuf::from(format!(
                    "{}.stale-{}-{}",
                    lock.display(),
                    observed.claimed_at_ms,
                    random_nonce()?
                ));
                match fs::rename(&lock, &stale) {
                    Ok(()) => {
                        let moved = read_lock_owner(&stale.join("owner")).ok();
                        if moved.is_some_and(|owner| {
                            owner.nonce == observed.nonce
                                && owner.claimed_at_ms == observed.claimed_at_ms
                        }) {
                            if let Some(after_evict) = &options.after_evict {
                                after_evict();
                            }
                            continue;
                        }
                        let _ = fs::rename(&stale, &lock);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(io_error("rename stale manifest lock", error)),
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(OpenCodeFilesError::Invalid("manifest lock busy".into()));
        }
        thread::sleep(jitter(&options).min(deadline.saturating_duration_since(Instant::now())));
    }

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let renewal_lock = lock.clone();
    let renewal_nonce = nonce.clone();
    let renewal_ttl = options.ttl;
    let renewal_every = options.renew_every;
    let renewal_failed = Arc::new(AtomicBool::new(false));
    let renewal_failed_thread = Arc::clone(&renewal_failed);
    let renewal = thread::spawn(move || loop {
        match stop_rx.recv_timeout(renewal_every) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let owner_path = renewal_lock.join("owner");
                let Ok(mut owner) = read_lock_owner(&owner_path) else {
                    renewal_failed_thread.store(true, Ordering::SeqCst);
                    break;
                };
                let Ok(now) = current_time_ms() else {
                    renewal_failed_thread.store(true, Ordering::SeqCst);
                    break;
                };
                if owner.nonce != renewal_nonce
                    || now.saturating_sub(owner.claimed_at_ms) >= renewal_ttl.as_millis() as u64
                {
                    renewal_failed_thread.store(true, Ordering::SeqCst);
                    break;
                }
                owner.claimed_at_ms = now;
                if write_lock_owner(&renewal_lock, &owner).is_err() {
                    renewal_failed_thread.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });
    let mut lease = ManifestLease {
        lock: lock.clone(),
        nonce: nonce.clone(),
        ttl: options.ttl,
        renewal_failed,
        stop_tx: Some(stop_tx),
        renewal: Some(renewal),
    };
    let result = operation(&mut lease);
    lease.stop_renewal();
    let result = match result {
        Ok(_) if lease.renewal_failed.load(Ordering::SeqCst) => Err(OpenCodeFilesError::Invalid(
            "manifest lock renewal failed; write aborted".into(),
        )),
        other => other,
    };
    let release = release_manifest_lock(path, &lock, &nonce, options.ttl);
    match (result, release) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn validate_auth_entry(entry: &Value) -> Result<(), OpenCodeFilesError> {
    let object = entry
        .as_object()
        .ok_or_else(|| OpenCodeFilesError::Invalid("auth entry must be an object".into()))?;
    match object.get("type").and_then(Value::as_str) {
        Some("api") | Some("oauth") | Some("wellknown") => Ok(()),
        _ => Err(OpenCodeFilesError::Invalid("unknown auth shape".into())),
    }
}

fn validate_handle_file(file: &HandleFile) -> Result<(), OpenCodeFilesError> {
    if file.version != 1 {
        return Err(OpenCodeFilesError::Invalid(
            "handle file must have version 1".into(),
        ));
    }
    let mut provider_ids = BTreeSet::new();
    for (index, provider) in file.providers.iter().enumerate() {
        if !identifier_is_valid(&provider.provider) {
            return Err(OpenCodeFilesError::Invalid(format!(
                "provider {index} has invalid provider"
            )));
        }
        if !provider_ids.insert(&provider.provider) {
            return Err(OpenCodeFilesError::Invalid(format!(
                "provider {index} duplicates provider {}",
                provider.provider
            )));
        }
    }
    for (index, provider) in file.providers.iter().enumerate() {
        match provider.shape {
            HandleShape::Api | HandleShape::Oauth => {}
        }
        if provider.serve.is_empty() {
            return Err(OpenCodeFilesError::Invalid(format!(
                "provider {index} requires serve"
            )));
        }
        if provider.accounts.is_empty() {
            return Err(OpenCodeFilesError::Invalid(format!(
                "provider {index} has invalid accounts"
            )));
        }
        let mut labels = BTreeSet::new();
        for account in &provider.accounts {
            if !identifier_is_valid(&account.label) {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} has an invalid account label"
                )));
            }
            if !labels.insert(&account.label) {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} duplicates account label {}",
                    account.label
                )));
            }
            if !valid_handle(&account.handle) {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} account {} has invalid handle",
                    account.label
                )));
            }
            if account.credential_id.is_empty() {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} account {} has invalid credential id",
                    account.label
                )));
            }
            if account
                .superseded
                .iter()
                .any(|handle| !valid_handle(handle))
            {
                return Err(OpenCodeFilesError::Invalid(format!(
                    "provider {index} account {} has invalid superseded handle",
                    account.label
                )));
            }
        }
    }
    Ok(())
}

fn valid_handle(handle: &str) -> bool {
    handle.strip_prefix("ckh_").is_some_and(|body| {
        body.len() == 43
            && body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn identifier_is_valid(value: &str) -> bool {
    !matches!(value, "__proto__" | "constructor" | "prototype")
        && !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

fn validate_identifier(value: &str, kind: &str) -> Result<(), OpenCodeFilesError> {
    if identifier_is_valid(value) {
        Ok(())
    } else {
        Err(OpenCodeFilesError::Invalid(format!(
            "{kind} must match [a-z0-9][a-z0-9._-]{{0,63}}"
        )))
    }
}

fn write_atomic(path: &Path, bytes: &[u8], secure_parent: bool) -> Result<(), OpenCodeFilesError> {
    write_atomic_guarded(path, bytes, secure_parent, || Ok(()))
}

fn write_atomic_guarded<F>(
    path: &Path,
    bytes: &[u8],
    secure_parent: bool,
    before_rename: F,
) -> Result<(), OpenCodeFilesError>
where
    F: FnOnce() -> Result<(), OpenCodeFilesError>,
{
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| OpenCodeFilesError::Invalid("file path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(|source| OpenCodeFilesError::Io {
        action: "create parent directory",
        source,
    })?;
    validate_secure_parent(parent)?;
    if secure_parent {
        set_mode(parent, 0o700)?;
    }
    let name = path
        .file_name()
        .ok_or_else(|| OpenCodeFilesError::Invalid("file path has no filename".into()))?;
    let temp = parent.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<(), OpenCodeFilesError> {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|source| OpenCodeFilesError::Io {
                    action: "create temporary file",
                    source,
                })?
        };
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|source| OpenCodeFilesError::Io {
                action: "create temporary file",
                source,
            })?;
        set_mode(&temp, 0o600)?;
        file.write_all(bytes)
            .map_err(|source| OpenCodeFilesError::Io {
                action: "write temporary file",
                source,
            })?;
        file.sync_all().map_err(|source| OpenCodeFilesError::Io {
            action: "sync temporary file",
            source,
        })?;
        before_rename()?;
        fs::rename(&temp, path).map_err(|source| OpenCodeFilesError::Io {
            action: "rename temporary file",
            source,
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| OpenCodeFilesError::Io {
                action: "sync parent directory",
                source,
            })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn validate_secure_file(path: &Path) -> Result<(), OpenCodeFilesError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| OpenCodeFilesError::Io {
        action: "stat file",
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(OpenCodeFilesError::Invalid(
            "file must be a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != current_uid()? {
            return Err(OpenCodeFilesError::Invalid(
                "file is not owned by the current uid".into(),
            ));
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(OpenCodeFilesError::Invalid(
                "file mode must be exactly 0600".into(),
            ));
        }
    }
    Ok(())
}

fn read_limited(path: &Path, max_bytes: u64, kind: &str) -> Result<Vec<u8>, OpenCodeFilesError> {
    let metadata = fs::metadata(path).map_err(|source| OpenCodeFilesError::Io {
        action: "stat file for read limit",
        source,
    })?;
    if metadata.len() > max_bytes {
        let limit = if max_bytes == AUTH_FILE_MAX_BYTES {
            "1 MiB".into()
        } else {
            format!("{} KiB", max_bytes / 1024)
        };
        return Err(OpenCodeFilesError::Invalid(format!(
            "{kind} exceeds {limit}",
        )));
    }
    fs::read(path).map_err(|source| OpenCodeFilesError::Io {
        action: "read file",
        source,
    })
}

fn validate_secure_parent(path: &Path) -> Result<(), OpenCodeFilesError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| OpenCodeFilesError::Io {
        action: "stat parent directory",
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(OpenCodeFilesError::Invalid(
            "parent directory must be a directory".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != current_uid()? {
            return Err(OpenCodeFilesError::InsecureParent {
                path: path.into(),
                reason: "not owned by the current uid",
            });
        }
        let mode = metadata.permissions().mode();
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            return Err(OpenCodeFilesError::InsecureParent {
                path: path.into(),
                reason: "world-writable without sticky bit",
            });
        }
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), OpenCodeFilesError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
            OpenCodeFilesError::Io {
                action: "set file mode",
                source,
            }
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> Result<u32, OpenCodeFilesError> {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|source| OpenCodeFilesError::Io {
            action: "determine current uid",
            source,
        })
        .and_then(|output| {
            if !output.status.success() {
                return Err(OpenCodeFilesError::Invalid(
                    "determine current uid failed".into(),
                ));
            }
            String::from_utf8(output.stdout)
                .map_err(|_| OpenCodeFilesError::Invalid("current uid was not UTF-8".into()))?
                .trim()
                .parse()
                .map_err(|_| OpenCodeFilesError::Invalid("current uid was invalid".into()))
        })
}

#[cfg(test)]
mod manifest_lock_tests {
    use super::*;
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        sync::{Arc, Barrier, Mutex},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "claustrum-manifest-lock-{}-{}",
                std::process::id(),
                TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn manifest(&self) -> PathBuf {
            self.0.join("opencode-handles.json")
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn handle(letter: char) -> String {
        format!("ckh_{}", letter.to_string().repeat(43))
    }

    fn provider(provider: &str, tenant: &str, letter: char) -> HandleProvider {
        HandleProvider {
            provider: provider.into(),
            shape: HandleShape::Api,
            serve: tenant.into(),
            accounts: vec![HandleAccount {
                label: "main".into(),
                handle: handle(letter),
                credential_id: format!("apikey:{provider}:main"),
                superseded: Vec::new(),
            }],
        }
    }

    fn file(provider: HandleProvider) -> HandleFile {
        HandleFile {
            version: 1,
            providers: vec![provider],
        }
    }

    fn write_fixture_owner(path: &Path, claimed_at_ms: u64, tenant: &str) {
        let lock = lock_path(path);
        fs::create_dir(&lock).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o700)).unwrap();
        let source = format!(
            "{{\"tenant\":\"{tenant}\",\"pid\":41,\"claimed_at_ms\":{claimed_at_ms},\"nonce\":\"0123456789abcdef0123456789abcdef\"}}\n"
        );
        fs::write(lock.join("owner"), source).unwrap();
        fs::set_permissions(lock.join("owner"), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn short_options() -> ManifestLockOptions {
        ManifestLockOptions {
            ttl: Duration::from_millis(40),
            renew_every: Duration::from_millis(10),
            retry_min: Duration::from_millis(2),
            retry_max: Duration::from_millis(3),
            ..ManifestLockOptions::default()
        }
    }

    #[test]
    fn concurrent_tenant_writers_preserve_both_provider_blocks() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let root = TempRoot::new();
        let path = root.manifest();
        let claimed = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let first_options = ManifestLockOptions {
            after_claim: Some({
                let claimed = Arc::clone(&claimed);
                let release = Arc::clone(&release);
                Arc::new(move || {
                    claimed.wait();
                    release.wait();
                })
            }),
            ..ManifestLockOptions::default()
        };
        let first_path = path.clone();
        let first = thread::spawn(move || {
            write_handle_file_for_tenant(
                &first_path,
                "anthropic-auth",
                &file(provider("anthropic", "anthropic-auth", 'A')),
                first_options,
            )
        });
        claimed.wait();
        let second_path = path.clone();
        let second = thread::spawn(move || {
            write_handle_file_for_tenant(
                &second_path,
                "openai-auth",
                &file(provider("openai", "openai-auth", 'B')),
                ManifestLockOptions::default(),
            )
        });
        thread::sleep(Duration::from_millis(15));
        release.wait();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();

        let mut names: Vec<_> = read_handle_file(&path)
            .unwrap()
            .providers
            .into_iter()
            .map(|entry| entry.provider)
            .collect();
        names.sort();
        assert_eq!(names, ["anthropic", "openai"]);
    }

    #[test]
    fn stale_owner_is_evicted_by_rename_and_quarantined() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let root = TempRoot::new();
        let path = root.manifest();
        write_fixture_owner(&path, now_ms() - MANIFEST_LOCK_TTL_MS - 1, "other-tenant");

        with_manifest_lock_with_options(
            &path,
            "opencode-claustrum",
            ManifestLockOptions::default(),
            |_| Ok(()),
        )
        .unwrap();

        let stale: Vec<_> = fs::read_dir(&root.0)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("opencode-handles.json.lock.stale-"))
            .collect();
        assert_eq!(stale.len(), 1);
        assert!(stale_target_matches(
            stale[0].strip_prefix("opencode-handles.json").unwrap()
        ));
    }

    #[test]
    fn fresh_owner_fails_manifest_lock_busy_after_bounded_window() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let root = TempRoot::new();
        let path = root.manifest();
        write_fixture_owner(&path, now_ms(), "other-tenant");
        let started = std::time::Instant::now();

        let error =
            with_manifest_lock_with_options(&path, "opencode-claustrum", short_options(), |_| {
                Ok(())
            })
            .unwrap_err();

        assert!(error.to_string().contains("manifest lock busy"));
        assert!(started.elapsed() >= Duration::from_millis(35));
    }

    #[test]
    fn owner_exists_while_held_and_lock_is_gone_after_release() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let root = TempRoot::new();
        let path = root.manifest();
        let lock = lock_path(&path);

        with_manifest_lock_with_options(
            &path,
            "opencode-claustrum",
            ManifestLockOptions::default(),
            |_| {
                let owner = read_lock_owner(&lock.join("owner"))?;
                assert_eq!(owner.tenant, "opencode-claustrum");
                Ok(())
            },
        )
        .unwrap();

        assert!(!lock.exists());
    }

    #[test]
    fn two_stale_evictors_have_one_winner_and_non_overlapping_holders() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let root = TempRoot::new();
        let path = root.manifest();
        write_fixture_owner(&path, now_ms() - MANIFEST_LOCK_TTL_MS - 1, "other-tenant");
        let eviction_barrier = Arc::new(Barrier::new(2));
        let eviction_wins = Arc::new(AtomicU64::new(0));
        let active = Arc::new(AtomicU64::new(0));
        let max_active = Arc::new(AtomicU64::new(0));
        let mut joins = Vec::new();
        for tenant in ["anthropic-auth", "openai-auth"] {
            let path = path.clone();
            let barrier = Arc::clone(&eviction_barrier);
            let wins = Arc::clone(&eviction_wins);
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            joins.push(thread::spawn(move || {
                let options = ManifestLockOptions {
                    before_evict: Some(Arc::new(move || {
                        barrier.wait();
                    })),
                    after_evict: Some(Arc::new(move || {
                        wins.fetch_add(1, Ordering::SeqCst);
                    })),
                    ..ManifestLockOptions::default()
                };
                with_manifest_lock_with_options(&path, tenant, options, |_| {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(current, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(15));
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
            }));
        }
        for join in joins {
            join.join().unwrap().unwrap();
        }
        assert_eq!(eviction_wins.load(Ordering::SeqCst), 1);
        assert_eq!(max_active.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_holder_does_not_release_and_warns() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let root = TempRoot::new();
        let path = root.manifest();
        let lock = lock_path(&path);
        let before_warnings = LEASE_LOST_WARNINGS.load(Ordering::SeqCst);
        let options = ManifestLockOptions {
            renew_every: Duration::from_secs(1),
            ..short_options()
        };

        with_manifest_lock_with_options(&path, "opencode-claustrum", options, |_| {
            let owner_path = lock.join("owner");
            let mut owner = read_lock_owner(&owner_path)?;
            owner.claimed_at_ms = now_ms() - 41;
            write_lock_owner(&lock, &owner)
        })
        .unwrap();

        assert!(lock.exists());
        assert_eq!(
            LEASE_LOST_WARNINGS.load(Ordering::SeqCst),
            before_warnings + 1
        );
    }

    #[test]
    fn atomic_publication_is_0600_under_umask_022() {
        let _serial = TEST_SERIAL.lock().unwrap();
        if let Some(path) = std::env::var_os("CK_MANIFEST_UMASK_CHILD_PATH") {
            write_handle_file_for_tenant(
                Path::new(&path),
                "opencode-claustrum",
                &file(provider("deepseek", "opencode-claustrum", 'C')),
                ManifestLockOptions::default(),
            )
            .unwrap();
            return;
        }
        let root = TempRoot::new();
        let path = root.manifest();
        let executable = std::env::current_exe().unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 022; exec \"$CK_MANIFEST_TEST_EXE\" atomic_publication_is_0600_under_umask_022 --nocapture")
            .env("CK_MANIFEST_TEST_EXE", executable)
            .env("CK_MANIFEST_UMASK_CHILD_PATH", &path)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn pins_cross_language_constants_and_renewal_bound() {
        assert_eq!(MANIFEST_LOCK_TTL_MS, 30_000);
        assert_eq!(MANIFEST_LOCK_RENEW_EVERY_MS, 10_000);
        assert_eq!(
            MANIFEST_LOCK_OWNER_KEYS,
            ["tenant", "pid", "claimed_at_ms", "nonce"]
        );
        assert_eq!(
            MANIFEST_LOCK_STALE_TARGET_PATTERN,
            r"^\.lock\.stale-\d+-[A-Za-z0-9_-]+$"
        );
        let renew_every = std::hint::black_box(MANIFEST_LOCK_RENEW_EVERY_MS);
        assert!(renew_every * 3 <= MANIFEST_LOCK_TTL_MS);
    }

    #[test]
    fn parses_a_typescript_shaped_owner_fixture() {
        let literal = r#"{"tenant":"anthropic-auth","pid":123,"claimed_at_ms":456,"nonce":"MDEyMzQ1Njc4OWFiY2RlZg"}"#;
        let owner = parse_lock_owner(literal).unwrap();
        assert_eq!(owner.tenant, "anthropic-auth");
        assert_eq!(owner.pid, 123);
        assert_eq!(owner.claimed_at_ms, 456);
        assert_eq!(owner.nonce, "MDEyMzQ1Njc4OWFiY2RlZg");
    }

    #[test]
    fn dangling_manifest_symlink_is_refused_without_replacement() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let root = TempRoot::new();
        let path = root.manifest();
        let target = root.0.join("missing-target.json");
        symlink(&target, &path).unwrap();

        let error = write_handle_file_for_tenant(
            &path,
            "opencode-claustrum",
            &file(provider("deepseek", "opencode-claustrum", 'D')),
            ManifestLockOptions::default(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("regular file"));
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!target.exists());
    }

    #[test]
    fn renewal_loss_aborts_before_manifest_rename() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let root = TempRoot::new();
        let path = root.manifest();
        write_handle_file_for_tenant(
            &path,
            "opencode-claustrum",
            &file(provider("deepseek", "opencode-claustrum", 'D')),
            ManifestLockOptions::default(),
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let options = ManifestLockOptions {
            ttl: Duration::from_millis(100),
            renew_every: Duration::from_millis(2),
            before_manifest_rename: Some(Arc::new(|lock| {
                fs::rename(lock, PathBuf::from(format!("{}.vanished", lock.display()))).unwrap();
                thread::sleep(Duration::from_millis(10));
            })),
            ..short_options()
        };

        let error = write_handle_file_for_tenant(
            &path,
            "opencode-claustrum",
            &file(provider("deepseek", "opencode-claustrum", 'E')),
            options,
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "manifest lock renewal failed; write aborted"
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn missing_and_unparseable_owner_records_are_busy_without_eviction() {
        let _serial = TEST_SERIAL.lock().unwrap();
        for source in [None, Some("{")] {
            let root = TempRoot::new();
            let path = root.manifest();
            let lock = lock_path(&path);
            fs::create_dir(&lock).unwrap();
            if let Some(source) = source {
                fs::write(lock.join("owner"), source).unwrap();
            }

            let error = with_manifest_lock_with_options(
                &path,
                "opencode-claustrum",
                ManifestLockOptions {
                    ttl: Duration::from_millis(25),
                    renew_every: Duration::from_millis(8),
                    retry_min: Duration::from_millis(2),
                    retry_max: Duration::from_millis(3),
                    ..ManifestLockOptions::default()
                },
                |_| Ok(()),
            )
            .unwrap_err();

            assert!(error.to_string().contains("manifest lock busy"));
            assert!(lock.exists());
            assert!(!fs::read_dir(&root.0)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| { entry.file_name().to_string_lossy().contains(".lock.stale-") }));
        }
    }
}
