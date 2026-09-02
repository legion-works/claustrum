use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    commit_admin, credential_client, opencode_files, parse_inventory, request_admin_status,
    store_op, CliError, GlobalArgs,
};
use credentials_core::admin_ops::{AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1};
use credentials_core::oauth::CUSTODY_TOMBSTONE_PREFIX as TOMBSTONE_PREFIX;
use credentials_core::record::{CredentialKind, VaultRecord};

const ACCOUNT: &str = "main";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProviderShape {
    Api,
    ApiEnv,
    ApiDiscovery,
    ApiMetadata,
}

impl ProviderShape {
    fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::ApiEnv => "api-env",
            Self::ApiDiscovery => "api-discovery",
            Self::ApiMetadata => "api-metadata",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProviderShapeDefinition {
    why: String,
    if_forced: String,
}

#[derive(Debug, Deserialize)]
struct ProviderShapeEntry {
    shapes: Vec<ProviderShape>,
    sites: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProviderShapeTable {
    version: u8,
    shape_definitions: BTreeMap<ProviderShape, ProviderShapeDefinition>,
    providers: BTreeMap<String, ProviderShapeEntry>,
    examined_servable: BTreeMap<String, String>,
    maintainer_note: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct UnsafeProviderShape {
    shapes: Vec<ProviderShape>,
    why: Vec<String>,
    if_forced: Vec<String>,
    sites: Vec<String>,
}

impl UnsafeProviderShape {
    pub(crate) fn shape_names(&self) -> String {
        self.shapes
            .iter()
            .map(|shape| shape.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }

    pub(crate) fn why(&self) -> String {
        self.why.join(" | ")
    }

    pub(crate) fn sites(&self) -> String {
        self.sites.join(",")
    }

    fn if_forced(&self) -> String {
        self.if_forced.join(" | ")
    }
}

fn provider_shape_table() -> Result<&'static ProviderShapeTable, CliError> {
    static TABLE: OnceLock<Result<ProviderShapeTable, String>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            let table: ProviderShapeTable =
                serde_json::from_str(include_str!("opencode-provider-shapes.json"))
                    .map_err(|error| format!("provider shape table is invalid JSON: {error}"))?;
            if table.version != 1 {
                return Err(format!(
                    "provider shape table has unsupported version {}",
                    table.version
                ));
            }
            if !table.examined_servable.contains_key("github-copilot") {
                return Err(
                    "provider shape table must record github-copilot as examined and servable"
                        .into(),
                );
            }
            if table.maintainer_note.len() != 2 {
                return Err(
                    "provider shape table must retain both derivation traps for maintainers".into(),
                );
            }
            for (provider, entry) in &table.providers {
                if entry.shapes.is_empty() || entry.sites.is_empty() {
                    return Err(format!(
                        "provider shape table has an empty shape or site list for {provider}"
                    ));
                }
                for shape in &entry.shapes {
                    if *shape == ProviderShape::Api || !table.shape_definitions.contains_key(shape)
                    {
                        return Err(format!(
                            "provider shape table has an undefined non-api shape for {provider}"
                        ));
                    }
                }
            }
            Ok(table)
        })
        .as_ref()
        .map_err(|error| CliError::Io(error.clone()))
}

pub(crate) fn unsafe_provider_shape(
    provider: &str,
) -> Result<Option<UnsafeProviderShape>, CliError> {
    let Some(entry) = provider_shape_table()?.providers.get(provider) else {
        return Ok(None);
    };
    if entry.shapes.as_slice() == [ProviderShape::Api] {
        return Ok(None);
    }
    let definitions = &provider_shape_table()?.shape_definitions;
    let mut why = Vec::new();
    let mut if_forced = Vec::new();
    for shape in &entry.shapes {
        let definition = definitions.get(shape).ok_or_else(|| {
            CliError::Io(format!(
                "provider shape table is missing {}",
                shape.as_str()
            ))
        })?;
        why.push(definition.why.clone());
        if_forced.push(definition.if_forced.clone());
    }
    Ok(Some(UnsafeProviderShape {
        shapes: entry.shapes.clone(),
        why,
        if_forced,
        sites: entry.sites.clone(),
    }))
}

struct MigrationArgs {
    dry_run: bool,
    replace: bool,
    force_shape: bool,
    restore: Option<String>,
    auth_file: PathBuf,
    handle_file: PathBuf,
    providers: Vec<String>,
    serve_by: String,
}

pub fn cmd_migrate_opencode(global: &GlobalArgs, raw: &[String]) -> Result<(), CliError> {
    let args = MigrationArgs::parse(raw)?;
    if let Some(provider) = &args.restore {
        return restore_provider(global, &args, provider);
    }
    migrate_providers(global, &args)
}

impl MigrationArgs {
    fn parse(raw: &[String]) -> Result<Self, CliError> {
        let mut dry_run = false;
        let mut replace = false;
        let mut force_shape = false;
        let mut restore = None;
        let mut auth_file = None;
        let mut handle_file = None;
        let mut providers = Vec::new();
        let mut serve_by = None;
        let mut index = 0;
        while index < raw.len() {
            match raw[index].as_str() {
                "--dry-run" => dry_run = true,
                "--replace" => replace = true,
                "--force-shape" => force_shape = true,
                "--restore" | "--auth-file" | "--handle-file" | "--provider" | "--serve-by" => {
                    let value = raw
                        .get(index + 1)
                        .filter(|value| !value.starts_with("--"))
                        .ok_or_else(|| CliError::Usage(format!("{} requires a value", raw[index])))?
                        .clone();
                    match raw[index].as_str() {
                        "--restore" => restore = Some(value),
                        "--auth-file" => auth_file = Some(PathBuf::from(value)),
                        "--handle-file" => handle_file = Some(PathBuf::from(value)),
                        "--provider" => providers.push(value),
                        "--serve-by" => serve_by = Some(value),
                        _ => unreachable!(),
                    }
                    index += 1;
                }
                _ => {}
            }
            index += 1;
        }
        if restore.is_some() && (dry_run || replace || force_shape || !providers.is_empty()) {
            return Err(CliError::Usage(
                "--restore is mutually exclusive with --dry-run, --replace, --force-shape, and --provider".into(),
            ));
        }
        Ok(Self {
            dry_run,
            replace,
            force_shape,
            restore,
            auth_file: auth_file.unwrap_or_else(opencode_files::default_auth_path),
            handle_file: handle_file.unwrap_or_else(opencode_files::default_handle_path),
            providers,
            serve_by: serve_by.unwrap_or_else(|| "opencode-claustrum".into()),
        })
    }
}

fn migrate_providers(global: &GlobalArgs, args: &MigrationArgs) -> Result<(), CliError> {
    let auth = opencode_files::read_auth_entries(&args.auth_file).map_err(files_error)?;
    let providers = selected_api_providers(&auth, &args.providers)?;
    if providers.is_empty() {
        println!("no eligible OpenCode api entries");
        return Ok(());
    }
    for provider in providers {
        if let Some(shape) = unsafe_provider_shape(&provider)? {
            if !args.force_shape {
                println!(
                    "provider={provider} refused shape={} why={} source={}; use --force-shape to override. availability-only, sentinel non-secret.",
                    shape.shape_names(),
                    shape.why(),
                    shape.sites(),
                );
                continue;
            }
            println!(
                "provider={provider} force_shape shape={} consequence={}; availability-only, sentinel non-secret.",
                shape.shape_names(),
                shape.if_forced(),
            );
        }
        let entry = auth.get(&provider).expect("selected provider exists");
        if is_api_tombstone(entry, &provider) {
            if args.dry_run {
                println!("provider={provider} tombstone=api dry_run pending_revoke_check");
            } else {
                let mut handles = read_handles_or_empty(&args.handle_file)?;
                let recovered =
                    finalize_superseded(global, &mut handles, &provider, &args.handle_file)?;
                println!(
                    "provider={provider} tombstone=api {}",
                    if recovered { "recovered" } else { "identical" }
                );
            }
            continue;
        }
        let material = api_material(entry, &provider)?;
        if material.starts_with(TOMBSTONE_PREFIX.as_bytes()) {
            println!("provider={provider} refused reserved prefix={TOMBSTONE_PREFIX}");
            continue;
        }
        migrate_one(global, args, &provider, material)?;
    }
    Ok(())
}

fn migrate_one(
    global: &GlobalArgs,
    args: &MigrationArgs,
    provider: &str,
    material: Vec<u8>,
) -> Result<(), CliError> {
    let id = format!("apikey:{provider}:{ACCOUNT}");
    let status = parse_inventory(&request_admin_status(global)?)?;
    let exists = status.iter().any(|(_, _, candidate)| candidate == &id);
    let mut handles = read_handles_or_empty(&args.handle_file)?;
    if !args.dry_run {
        finalize_superseded(global, &mut handles, provider, &args.handle_file)?;
    }
    let known_handle = account_handle(&handles, provider, ACCOUNT, &id)?;

    if args.dry_run {
        let verdict = if !exists {
            "absent"
        } else if known_handle.is_none() {
            "requires_capability_mint"
        } else {
            "requires_capability_read"
        };
        println!("provider={provider} credential_id={id} dry_run compare={verdict}");
        return Ok(());
    }

    let mut old_handle = known_handle;
    let mut same = false;
    if exists {
        let handle = match old_handle.as_deref() {
            Some(handle) => handle.to_owned(),
            None => {
                let handle = mint_then_persist(global, &id, |handle| {
                    update_handle(&mut handles, provider, &args.serve_by, &id, handle, false)?;
                    write_and_verify_handles(&args.handle_file, &handles)?;
                    Ok(handle.to_owned())
                })?;
                old_handle = Some(handle.clone());
                handle
            }
        };
        match get_material(global, &handle)? {
            Some(existing) => same = existing == material,
            None => {
                let replacement = mint_then_persist(global, &id, |replacement| {
                    update_handle(
                        &mut handles,
                        provider,
                        &args.serve_by,
                        &id,
                        replacement,
                        false,
                    )?;
                    write_and_verify_handles(&args.handle_file, &handles)?;
                    Ok(replacement.to_owned())
                })?;
                old_handle = Some(replacement.clone());
                same = get_material(global, &replacement)?.ok_or_else(|| {
                    CliError::Io("a freshly minted capability was revoked".into())
                })? == material;
            }
        }
        if !same && !args.replace {
            return Err(CliError::Usage(format!(
                "existing credential {id} differs; rerun with --replace"
            )));
        }
    }

    let outcome = if !exists {
        commit_admin(
            global,
            store_op(
                &id,
                VaultRecord::new_static(CredentialKind::ApiKey, "opencode", material, None),
                AdminAuditOp::Import,
                StoreMode::Create,
            ),
        )?;
        "created"
    } else if same {
        "identical"
    } else {
        let reread = opencode_files::read_auth_entries(&args.auth_file).map_err(files_error)?;
        if reread
            .get(provider)
            .and_then(|entry| entry.get("key"))
            .and_then(Value::as_str)
            .map(str::as_bytes)
            != Some(material.as_slice())
        {
            return Err(CliError::Io(
                "OpenCode auth entry changed before replacement".into(),
            ));
        }
        commit_admin(
            global,
            store_op(
                &id,
                VaultRecord::new_static(CredentialKind::ApiKey, "opencode", material, None),
                AdminAuditOp::Import,
                StoreMode::ReplaceUnconditional,
            ),
        )?;
        "replaced"
    };

    let replacement_required = !exists || outcome == "replaced";
    if replacement_required {
        mint_then_persist(global, &id, |handle| {
            update_handle(&mut handles, provider, &args.serve_by, &id, handle, true)?;
            write_and_verify_handles(&args.handle_file, &handles)?;
            Ok(())
        })?
    } else {
        let handle = old_handle
            .clone()
            .ok_or_else(|| CliError::Io("missing current handle after comparison".into()))?;
        let superseded =
            update_handle(&mut handles, provider, &args.serve_by, &id, &handle, false)?;
        if superseded.as_deref() != Some(handle.as_str()) {
            write_and_verify_handles(&args.handle_file, &handles)?;
        }
    }

    let tombstone = api_tombstone(provider);
    opencode_files::write_auth_entry(&args.auth_file, provider, tombstone.clone())
        .map_err(files_error)?;
    #[cfg(feature = "opencode-test-seam")]
    if std::env::var("CK_OPENCODE_TEST_FAIL_TOMBSTONE_REREAD").as_deref() == Ok("1") {
        return Err(CliError::Io(
            "OpenCode files: auth entry did not persist exactly; re-run converges from the written tombstone"
                .into(),
        ));
    }
    opencode_files::verify_auth_written(&args.auth_file, provider, &tombstone)
        .map_err(files_error)?;
    finalize_superseded(global, &mut handles, provider, &args.handle_file)?;
    println!(
        "provider={provider} credential_id={id} {outcome} handle_file={} tombstone=api",
        args.handle_file.display()
    );
    Ok(())
}

fn restore_provider(
    global: &GlobalArgs,
    args: &MigrationArgs,
    provider: &str,
) -> Result<(), CliError> {
    let mut handles = read_handles_or_empty(&args.handle_file)?;
    let provider_index = handles
        .providers
        .iter()
        .position(|item| item.provider == provider)
        .ok_or_else(|| CliError::Usage(format!("no handle entry for provider {provider}")))?;
    if !matches!(
        handles.providers[provider_index].shape,
        opencode_files::HandleShape::Api
    ) {
        return Err(CliError::Usage(format!(
            "restore for {provider} accepts only api entries"
        )));
    }
    let accounts = handles.providers[provider_index].accounts.clone();
    for account in accounts {
        let mut handle = account.handle.clone();
        let material = match get_material(global, &handle) {
            Ok(Some(material)) => material,
            Ok(None) => {
                handle = mint_then_persist(global, &account.credential_id, |handle| {
                    update_specific_handle(&mut handles, provider, &account.label, handle)?;
                    write_and_verify_handles(&args.handle_file, &handles)?;
                    Ok(handle.to_owned())
                })?;
                get_material(global, &handle)?
                    .ok_or_else(|| CliError::Io("a freshly minted capability was revoked".into()))?
            }
            Err(CliError::Io(message)) if message == "credential needs reauthentication" => {
                return Err(CliError::Io(format!(
                    "refusing restore for {}: vault record needs re-authentication",
                    account.credential_id
                )));
            }
            Err(error) => return Err(error),
        };
        let key = String::from_utf8(material)
            .map_err(|_| CliError::Io("api credential material was not UTF-8".into()))?;
        let entry = json!({"type": "api", "key": key});
        opencode_files::write_auth_entry(&args.auth_file, provider, entry.clone())
            .map_err(files_error)?;
        opencode_files::verify_auth_written(&args.auth_file, provider, &entry)
            .map_err(files_error)?;
        commit_admin(
            global,
            AdminOpBody::RevokeHandle {
                v: ADMIN_OP_SCHEMA_V1,
                handle,
            },
        )?;
        remove_account(&mut handles, provider, &account.label)?;
        write_and_verify_handles(&args.handle_file, &handles)?;
    }
    println!(
        "provider={provider} restored handle_file={}",
        args.handle_file.display()
    );
    Ok(())
}

fn selected_api_providers(
    auth: &BTreeMap<String, Value>,
    filters: &[String],
) -> Result<Vec<String>, CliError> {
    let candidates: Vec<String> = if filters.is_empty() {
        auth.iter()
            .filter(|(_, entry)| entry.get("type").and_then(Value::as_str) == Some("api"))
            .map(|(provider, _)| provider.clone())
            .collect()
    } else {
        let mut seen = BTreeSet::new();
        filters
            .iter()
            .filter(|provider| seen.insert((*provider).clone()))
            .filter_map(|provider| auth.get(provider).map(|entry| (provider, entry)))
            .filter(|(_, entry)| entry.get("type").and_then(Value::as_str) == Some("api"))
            .map(|(provider, _)| provider.clone())
            .collect()
    };
    for provider in filters {
        if !auth.contains_key(provider) {
            return Err(CliError::Usage(format!(
                "OpenCode auth has no provider {provider}"
            )));
        }
    }
    Ok(candidates)
}

fn api_material(entry: &Value, provider: &str) -> Result<Vec<u8>, CliError> {
    entry
        .get("key")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .map(|key| key.as_bytes().to_vec())
        .ok_or_else(|| CliError::Usage(format!("OpenCode api entry for {provider} has no key")))
}

fn api_tombstone(provider: &str) -> Value {
    json!({"type": "api", "key": format!("{TOMBSTONE_PREFIX}{provider}")})
}

pub(crate) fn is_api_tombstone(entry: &Value, provider: &str) -> bool {
    entry == &api_tombstone(provider)
}

pub(crate) fn read_handles_or_empty(path: &Path) -> Result<opencode_files::HandleFile, CliError> {
    if path.exists() {
        opencode_files::read_handle_file(path).map_err(files_error)
    } else {
        Ok(opencode_files::HandleFile {
            version: 1,
            providers: Vec::new(),
        })
    }
}

fn account_handle(
    handles: &opencode_files::HandleFile,
    provider: &str,
    label: &str,
    credential_id: &str,
) -> Result<Option<String>, CliError> {
    let Some(provider) = handles
        .providers
        .iter()
        .find(|item| item.provider == provider)
    else {
        return Ok(None);
    };
    if !matches!(provider.shape, opencode_files::HandleShape::Api) || provider.serve.is_empty() {
        return Err(CliError::Io(
            "handle provider is not an api custody entry".into(),
        ));
    }
    match provider
        .accounts
        .iter()
        .find(|account| account.label == label)
    {
        Some(account) if account.credential_id != credential_id => Err(CliError::Io(
            "handle account credential id does not match the api main record".into(),
        )),
        Some(account) => Ok(Some(account.handle.clone())),
        None => Ok(None),
    }
}

pub(crate) fn finalize_superseded(
    global: &GlobalArgs,
    handles: &mut opencode_files::HandleFile,
    provider: &str,
    handle_path: &Path,
) -> Result<bool, CliError> {
    let pending: Vec<String> = handles
        .providers
        .iter()
        .find(|item| item.provider == provider)
        .map(|item| {
            item.accounts
                .iter()
                .flat_map(|account| account.superseded.iter().cloned())
                .collect()
        })
        .unwrap_or_default();
    if pending.is_empty() {
        return Ok(false);
    }
    for handle in pending {
        commit_admin(
            global,
            AdminOpBody::RevokeHandle {
                v: ADMIN_OP_SCHEMA_V1,
                handle,
            },
        )?;
    }
    let item = handles
        .providers
        .iter_mut()
        .find(|item| item.provider == provider)
        .ok_or_else(|| {
            CliError::Io("handle provider disappeared before superseded revoke".into())
        })?;
    for account in &mut item.accounts {
        account.superseded.clear();
    }
    write_and_verify_handles(handle_path, handles)?;
    Ok(true)
}

fn update_handle(
    handles: &mut opencode_files::HandleFile,
    provider: &str,
    serve_by: &str,
    credential_id: &str,
    handle: &str,
    retain_superseded: bool,
) -> Result<Option<String>, CliError> {
    if let Some(item) = handles
        .providers
        .iter_mut()
        .find(|item| item.provider == provider)
    {
        if !matches!(item.shape, opencode_files::HandleShape::Api) {
            return Err(CliError::Io("provider handle shape is not api".into()));
        }
        item.serve = serve_by.into();
        if let Some(account) = item
            .accounts
            .iter_mut()
            .find(|account| account.label == ACCOUNT)
        {
            if account.credential_id != credential_id {
                return Err(CliError::Io(
                    "main handle account points at another credential".into(),
                ));
            }
            let old = std::mem::replace(&mut account.handle, handle.into());
            if retain_superseded && old != handle && !account.superseded.contains(&old) {
                account.superseded.push(old.clone());
            }
            return Ok(Some(old));
        }
        item.accounts.push(opencode_files::HandleAccount {
            label: ACCOUNT.into(),
            handle: handle.into(),
            credential_id: credential_id.into(),
            superseded: Vec::new(),
        });
        return Ok(None);
    }
    handles.providers.push(opencode_files::HandleProvider {
        provider: provider.into(),
        shape: opencode_files::HandleShape::Api,
        serve: serve_by.into(),
        accounts: vec![opencode_files::HandleAccount {
            label: ACCOUNT.into(),
            handle: handle.into(),
            credential_id: credential_id.into(),
            superseded: Vec::new(),
        }],
    });
    Ok(None)
}

fn update_specific_handle(
    handles: &mut opencode_files::HandleFile,
    provider: &str,
    label: &str,
    handle: &str,
) -> Result<(), CliError> {
    let account = handles
        .providers
        .iter_mut()
        .find(|item| item.provider == provider)
        .and_then(|item| {
            item.accounts
                .iter_mut()
                .find(|account| account.label == label)
        })
        .ok_or_else(|| CliError::Io("handle account disappeared before restore".into()))?;
    account.handle = handle.into();
    Ok(())
}

pub(crate) fn remove_account(
    handles: &mut opencode_files::HandleFile,
    provider: &str,
    label: &str,
) -> Result<(), CliError> {
    let index = handles
        .providers
        .iter()
        .position(|item| item.provider == provider)
        .ok_or_else(|| CliError::Io("handle provider disappeared before restore".into()))?;
    let accounts = &mut handles.providers[index].accounts;
    let account = accounts
        .iter()
        .position(|account| account.label == label)
        .ok_or_else(|| CliError::Io("handle account disappeared before restore".into()))?;
    accounts.remove(account);
    if handles.providers[index].accounts.is_empty() {
        handles.providers.remove(index);
    }
    Ok(())
}

pub(crate) fn write_and_verify_handles(
    path: &Path,
    handles: &opencode_files::HandleFile,
) -> Result<(), CliError> {
    #[cfg(feature = "opencode-test-seam")]
    if std::env::var("CK_OPENCODE_TEST_FAIL_HANDLE_WRITE").as_deref() == Ok("1") {
        return Err(CliError::Io(
            "OpenCode files: handle file write interrupted; re-run converges from the stored credential"
                .into(),
        ));
    }
    opencode_files::write_handle_file(path, handles).map_err(files_error)?;
    opencode_files::verify_handle_written(path, handles).map_err(files_error)
}

pub(crate) fn mint_handle(global: &GlobalArgs, id: &str) -> Result<String, CliError> {
    commit_admin(
        global,
        AdminOpBody::MintHandle {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.into(),
        },
    )?
    .get("handle")
    .and_then(Value::as_str)
    .filter(|handle| !handle.is_empty())
    .map(Into::into)
    .ok_or_else(|| CliError::Io("mint did not return a handle".into()))
}

/// Mints a handle for `id` and runs `persist` with it. This is for handles meant to outlive the
/// call: if `persist` fails, the handle is revoked before the error propagates, so a failed file
/// write never strands a live bearer capability. Use `with_scoped_handle` when the handle is only
/// needed during the closure and must die before it returns. If the revoke also fails, the returned
/// error names the credential id and the two commands that close the window (`ck auth audit` shows
/// the mint; `ck auth revoke-all-handles <id>` revokes it). The `superseded` journal covers the
/// replace-then-crash case; this covers mint-then-crash, whose journal precondition is what failed.
pub(crate) fn mint_then_persist<T>(
    global: &GlobalArgs,
    id: &str,
    persist: impl FnOnce(&str) -> Result<T, CliError>,
) -> Result<T, CliError> {
    let handle = mint_handle(global, id)?;
    match persist(&handle) {
        Ok(value) => Ok(value),
        Err(persist_error) => match revoke_handle(global, &handle) {
            Ok(()) => Err(persist_error),
            Err(revoke_error) => Err(CliError::Io(format!(
                "failed to persist minted handle for credential {id}: {persist_error}; cleanup also failed: {revoke_error}; run `ck auth audit` to find the mint, then `ck auth revoke-all-handles {id}` to revoke it"
            ))),
        },
    }
}

/// Mints a handle for a single operation and revokes it on every return path.
pub(crate) fn with_scoped_handle<T>(
    global: &GlobalArgs,
    id: &str,
    operation: impl FnOnce(&str) -> Result<T, CliError>,
) -> Result<T, CliError> {
    let handle = mint_handle(global, id)?;
    match operation(&handle) {
        Ok(value) => revoke_handle(global, &handle).map_err(|revoke_error| {
            CliError::Io(format!(
                "verification handle cleanup failed for credential {id}: {revoke_error}; run `ck auth audit` to find the mint, then `ck auth revoke-all-handles {id}` to revoke it"
            ))
        })
        .map(|()| value),
        Err(operation_error) => match revoke_handle(global, &handle) {
            Ok(()) => Err(operation_error),
            Err(revoke_error) => Err(CliError::Io(format!(
                "operation using verification handle for credential {id} failed: {operation_error}; cleanup also failed: {revoke_error}; run `ck auth audit` to find the mint, then `ck auth revoke-all-handles {id}` to revoke it"
            ))),
        },
    }
}

pub(crate) fn revoke_handle(global: &GlobalArgs, handle: &str) -> Result<(), CliError> {
    #[cfg(feature = "opencode-test-seam")]
    if std::env::var("CK_OPENCODE_TEST_FAIL_REVOKE").as_deref() == Ok("1") {
        return Err(CliError::Io(
            "OpenCode test seam: handle revoke interrupted".into(),
        ));
    }
    commit_admin(
        global,
        AdminOpBody::RevokeHandle {
            v: ADMIN_OP_SCHEMA_V1,
            handle: handle.into(),
        },
    )?;
    Ok(())
}

pub(crate) fn revoke_all_handles(global: &GlobalArgs, id: &str) -> Result<(), CliError> {
    commit_admin(
        global,
        AdminOpBody::RevokeAllHandles {
            v: ADMIN_OP_SCHEMA_V1,
            id: id.into(),
        },
    )?;
    Ok(())
}

pub(crate) fn get_material(global: &GlobalArgs, handle: &str) -> Result<Option<Vec<u8>>, CliError> {
    #[cfg(feature = "opencode-test-seam")]
    if std::env::var("CK_OPENCODE_TEST_FAIL_GET_MATERIAL").as_deref() == Ok("1") {
        return Err(CliError::Io(
            "OpenCode test seam: material read interrupted".into(),
        ));
    }
    let connection = global.subc_conn.as_deref().ok_or_else(|| {
        CliError::Usage("migrate-opencode needs --subc for capability reads".into())
    })?;
    match credential_client::get_online(connection, &global.data_dir, handle) {
        Ok(credential) => Ok(Some(credential.payload)),
        Err(credential_client::CredentialReadError::NotFound) => Ok(None),
        Err(credential_client::CredentialReadError::NeedsReauth) => {
            Err(CliError::Io("credential needs reauthentication".into()))
        }
        Err(error) => Err(CliError::Io(error.to_string())),
    }
}

fn files_error(error: opencode_files::OpenCodeFilesError) -> CliError {
    CliError::Io(format!("OpenCode files: {error}"))
}
