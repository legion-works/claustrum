use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
const AUTH_FILE_MAX_BYTES: u64 = 1024 * 1024;
const HANDLE_FILE_MAX_BYTES: u64 = 256 * 1024;

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
    validate_handle_file(file)?;
    let bytes = serde_json::to_vec(file).map_err(OpenCodeFilesError::Json)?;
    write_atomic(path, &bytes, true)
}

pub fn verify_handle_written(path: &Path, expected: &HandleFile) -> Result<(), OpenCodeFilesError> {
    if &read_handle_file(path)? != expected {
        return Err(OpenCodeFilesError::Invalid(
            "handle file did not persist exactly".into(),
        ));
    }
    Ok(())
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
        match provider.shape {
            HandleShape::Api | HandleShape::Oauth => {}
        }
        if provider.serve.is_empty() {
            return Err(OpenCodeFilesError::Invalid(format!(
                "provider {index} requires serve"
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
    handle.starts_with("ckh_") && handle.len() == 47
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
