use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::json;

use super::{
    commit_admin, opencode_files, opencode_migration, parse_inventory, request_admin_status,
    store_op, CliError, GlobalArgs,
};
use credentials_core::{
    admin_ops::{AdminAuditOp, StoreMode},
    credential_id::{default_refresh_adapter, AuthMethod},
    oauth::{OAuthCredential, CUSTODY_TOMBSTONE_PREFIX},
    record::{RecordIdentity, VaultRecord},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginExport {
    version: u8,
    provider: String,
    serve: String,
    accounts: Vec<PluginAccount>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginAccount {
    label: String,
    kind: String,
    access: String,
    refresh: String,
    expires_ms: i64,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

struct PluginMigrationArgs {
    serve: String,
    provider: String,
    from: PathBuf,
    replace: bool,
    skip_existing: bool,
    dry_run: bool,
    allow_expired: bool,
}

pub(crate) fn cmd_migrate_plugin(global: &GlobalArgs, raw: &[String]) -> Result<(), CliError> {
    let args = PluginMigrationArgs::parse(raw)?;
    let export = read_export(&args.from)?;
    let adapter = validate_export(&args, &export)?;

    let mut handles =
        opencode_migration::read_handles_or_empty(&opencode_files::default_handle_path())?;
    validate_manifest_block(&handles, &args, &export)?;
    let status = parse_inventory(&request_admin_status(global)?)?;
    let versions: BTreeMap<_, _> = status
        .into_iter()
        .map(|(_, version, id)| (id, version))
        .collect();
    validate_existing(&versions, &args, &export)?;

    if args.dry_run {
        for account in &export.accounts {
            let id = credential_id(&args.provider, &account.label);
            let exists = versions.contains_key(&id);
            let action = if exists {
                if args.replace {
                    "replace"
                } else {
                    "skip"
                }
            } else {
                "import"
            };
            println!(
                "{}: credential_id={} exists={} action={} identity_present={}",
                account.label,
                id,
                exists,
                action,
                account.account_id.is_some() || account.email.is_some(),
            );
        }
        println!(
            "summary: dry-run {} account(s), no writes",
            export.accounts.len()
        );
        return Ok(());
    }

    let handle_path = opencode_files::default_handle_path();
    let mut imported = 0;
    let mut replaced = 0;
    let mut skipped = 0;
    for account in &export.accounts {
        let id = credential_id(&args.provider, &account.label);
        let exists = versions.contains_key(&id);
        if exists && args.skip_existing {
            println!("{}: skipped (exists)", account.label);
            skipped += 1;
            continue;
        }

        let record = oauth_record(&args.provider, account, &adapter)?;
        let new_version = versions.get(&id).copied().unwrap_or(0) + 1;
        let outcome = if exists { "replaced" } else { "imported" };
        commit_admin(
            global,
            store_op(
                &id,
                record,
                AdminAuditOp::Import,
                if exists {
                    StoreMode::ReplaceUnconditional
                } else {
                    StoreMode::Create
                },
            ),
        )?;
        opencode_migration::mint_then_persist(global, &id, |handle| {
            insert_manifest_account(&mut handles, &args, account, &id, handle)?;
            opencode_migration::write_and_verify_handles_for_tenant(
                &handle_path,
                &args.serve,
                &handles,
            )
        })?;
        finalize_replaced_handle(global, &mut handles, &args, &handle_path)?;
        println!(
            "{}: {outcome} {id} v{new_version}, handle written",
            account.label
        );
        if exists {
            replaced += 1;
        } else {
            imported += 1;
        }
    }
    println!(
        "summary: imported={imported} replaced={replaced} skipped={skipped} total={}",
        export.accounts.len()
    );
    Ok(())
}

impl PluginMigrationArgs {
    fn parse(raw: &[String]) -> Result<Self, CliError> {
        let serve = value(raw, "--serve")?;
        let provider = value(raw, "--provider")?;
        let from = PathBuf::from(value(raw, "--from")?);
        let replace = flag(raw, "--replace");
        let skip_existing = flag(raw, "--skip-existing");
        if replace && skip_existing {
            return Err(CliError::Usage(
                "--replace and --skip-existing are mutually exclusive".into(),
            ));
        }
        Ok(Self {
            serve,
            provider,
            from,
            replace,
            skip_existing,
            dry_run: flag(raw, "--dry-run"),
            allow_expired: flag(raw, "--allow-expired"),
        })
    }
}

fn read_export(path: &Path) -> Result<PluginExport, CliError> {
    let bytes = opencode_files::read_secret_file(path, "plugin export").map_err(|_| {
        CliError::Usage("plugin export must be a regular 0600 file no larger than 256 KiB".into())
    })?;
    serde_json::from_slice(&bytes).map_err(|_| CliError::Usage("plugin export is invalid".into()))
}

fn validate_export(args: &PluginMigrationArgs, export: &PluginExport) -> Result<String, CliError> {
    if export.version != 1 {
        return Err(CliError::Usage(
            "refusing plugin export: version must be 1".into(),
        ));
    }
    if export.provider != args.provider {
        return Err(CliError::Usage(
            "refusing plugin export: provider does not match --provider".into(),
        ));
    }
    if export.serve != args.serve {
        return Err(CliError::Usage(
            "refusing plugin export: serve does not match --serve".into(),
        ));
    }
    opencode_files::validate_manifest_label(&args.serve).map_err(|_| {
        CliError::Usage("refusing plugin export: serve is not a valid tenant label".into())
    })?;
    opencode_files::validate_manifest_label(&args.provider).map_err(|_| {
        CliError::Usage("refusing plugin export: provider is not a valid label".into())
    })?;
    let adapter =
        default_refresh_adapter(Some(AuthMethod::Oauth), &args.provider).ok_or_else(|| {
            CliError::Usage(format!(
                "refusing plugin export: no refresh adapter for provider '{}'",
                args.provider
            ))
        })?;
    let now = now_ms()?;
    let mut labels = BTreeSet::new();
    for account in &export.accounts {
        if account.kind != "oauth" {
            return Err(CliError::Usage(
                "refusing plugin export: account kind must be oauth".into(),
            ));
        }
        opencode_files::validate_manifest_label(&account.label).map_err(|_| {
            CliError::Usage(format!(
                "refusing plugin export: label '{}' is invalid",
                account.label
            ))
        })?;
        if account.label == "main" {
            return Err(CliError::Usage(
                "refusing plugin export: label 'main' must not enter through migrate-plugin".into(),
            ));
        }
        if !labels.insert(&account.label) {
            return Err(CliError::Usage(format!(
                "refusing plugin export: duplicate label '{}'",
                account.label
            )));
        }
        if account.access.starts_with(CUSTODY_TOMBSTONE_PREFIX)
            || account.refresh.starts_with(CUSTODY_TOMBSTONE_PREFIX)
        {
            return Err(CliError::Usage(
                "refusing plugin export: reserved tombstone prefix".into(),
            ));
        }
        if account.expires_ms < now && !args.allow_expired {
            return Err(CliError::Usage(format!(
                "refusing plugin export: label '{}' is expired; rerun with --allow-expired",
                account.label
            )));
        }
        if account.expires_ms < now {
            eprintln!(
                "{}: expired export accepted under --allow-expired",
                account.label
            );
        }
    }
    Ok(adapter)
}

fn validate_manifest_block(
    handles: &opencode_files::HandleFile,
    args: &PluginMigrationArgs,
    export: &PluginExport,
) -> Result<(), CliError> {
    let Some(block) = handles
        .providers
        .iter()
        .find(|block| block.provider == args.provider)
    else {
        return Ok(());
    };
    if block.serve != args.serve {
        return Err(CliError::Usage(format!(
            "manifest provider '{}' belongs to tenant '{}'",
            args.provider, block.serve
        )));
    }
    if !matches!(block.shape, opencode_files::HandleShape::Oauth) {
        return Err(CliError::Usage(format!(
            "manifest provider '{}' is not an oauth block",
            args.provider
        )));
    }
    for account in &export.accounts {
        if block
            .accounts
            .iter()
            .any(|entry| entry.label == account.label)
            && !args.replace
            && !args.skip_existing
        {
            return Err(CliError::Usage(format!(
                "manifest account '{}' already exists; rerun with --replace or --skip-existing",
                account.label
            )));
        }
    }
    Ok(())
}

fn validate_existing(
    versions: &BTreeMap<String, u64>,
    args: &PluginMigrationArgs,
    export: &PluginExport,
) -> Result<(), CliError> {
    for account in &export.accounts {
        let id = credential_id(&args.provider, &account.label);
        if versions.contains_key(&id) && !args.replace && !args.skip_existing {
            return Err(CliError::Usage(format!(
                "existing credential {id}; rerun with --replace or --skip-existing"
            )));
        }
    }
    Ok(())
}

fn oauth_record(
    provider: &str,
    account: &PluginAccount,
    adapter: &str,
) -> Result<VaultRecord, CliError> {
    let raw = serde_json::to_vec(&json!({
        provider: {
            "type": "oauth",
            "access": account.access,
            "refresh": account.refresh,
            "expires": account.expires_ms,
        }
    }))
    .map_err(|_| CliError::Usage("plugin export is invalid".into()))?;
    let oauth = OAuthCredential::import_provider("opencode", &raw, provider)
        .map_err(|_| CliError::Usage("plugin export is invalid".into()))?;
    let record = VaultRecord::new_oauth(
        "opencode",
        adapter,
        oauth.clone(),
        oauth.access_token.into_bytes(),
    );
    if account.account_id.is_some() || account.email.is_some() {
        Ok(record.with_identity(RecordIdentity {
            account_id: account.account_id.clone(),
            email: account.email.clone(),
            org_name: None,
        }))
    } else {
        Ok(record)
    }
}

fn insert_manifest_account(
    handles: &mut opencode_files::HandleFile,
    args: &PluginMigrationArgs,
    account: &PluginAccount,
    credential_id: &str,
    handle: &str,
) -> Result<(), CliError> {
    if let Some(block) = handles
        .providers
        .iter_mut()
        .find(|block| block.provider == args.provider)
    {
        let entry = block
            .accounts
            .iter_mut()
            .find(|entry| entry.label == account.label);
        if let Some(entry) = entry {
            if !args.replace {
                return Err(CliError::Usage(format!(
                    "manifest account '{}' already exists; rerun with --replace",
                    account.label
                )));
            }
            if entry.credential_id != credential_id {
                return Err(CliError::Io(
                    "manifest account points at another credential".into(),
                ));
            }
            let old = std::mem::replace(&mut entry.handle, handle.into());
            if old != handle && !entry.superseded.contains(&old) {
                entry.superseded.push(old);
            }
            return Ok(());
        }
        block.accounts.push(opencode_files::HandleAccount {
            label: account.label.clone(),
            handle: handle.into(),
            credential_id: credential_id.into(),
            superseded: Vec::new(),
        });
        return Ok(());
    }
    handles.providers.push(opencode_files::HandleProvider {
        provider: args.provider.clone(),
        shape: opencode_files::HandleShape::Oauth,
        serve: args.serve.clone(),
        accounts: vec![opencode_files::HandleAccount {
            label: account.label.clone(),
            handle: handle.into(),
            credential_id: credential_id.into(),
            superseded: Vec::new(),
        }],
    });
    Ok(())
}

fn finalize_replaced_handle(
    global: &GlobalArgs,
    handles: &mut opencode_files::HandleFile,
    args: &PluginMigrationArgs,
    path: &Path,
) -> Result<(), CliError> {
    let pending: Vec<String> = handles
        .providers
        .iter()
        .find(|block| block.provider == args.provider)
        .into_iter()
        .flat_map(|block| block.accounts.iter())
        .flat_map(|account| account.superseded.iter().cloned())
        .collect();
    for handle in pending {
        opencode_migration::revoke_handle(global, &handle)?;
    }
    if let Some(block) = handles
        .providers
        .iter_mut()
        .find(|block| block.provider == args.provider)
    {
        for account in &mut block.accounts {
            account.superseded.clear();
        }
        opencode_migration::write_and_verify_handles_for_tenant(path, &args.serve, handles)?;
    }
    Ok(())
}

fn credential_id(provider: &str, label: &str) -> String {
    format!("oauth:{provider}:{label}")
}

fn now_ms() -> Result<i64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .map_err(|_| CliError::Io("system clock is before UNIX epoch".into()))
}

fn value(raw: &[String], flag_name: &str) -> Result<String, CliError> {
    raw.iter()
        .position(|arg| arg == flag_name)
        .and_then(|index| raw.get(index + 1))
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| CliError::Usage(format!("{flag_name} requires a value")))
}

fn flag(raw: &[String], wanted: &str) -> bool {
    raw.iter().any(|arg| arg == wanted)
}
