use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use super::{
    commit_admin, opencode_files, opencode_migration, request_admin_status, store_op, CliError,
    GlobalArgs,
};
use credentials_core::admin_ops::{AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1};
use credentials_core::record::{CredentialKind, VaultRecord};

pub(crate) fn cmd_opencode_account(global: &GlobalArgs, raw: &[String]) -> Result<(), CliError> {
    let subcommand = raw
        .first()
        .ok_or_else(|| CliError::Usage("opencode-account requires add, remove, or list".into()))?;
    match subcommand.as_str() {
        "add" => add(global, &raw[1..]),
        "remove" => remove(global, &raw[1..]),
        "list" => list(global, &raw[1..]),
        other => Err(CliError::Usage(format!(
            "unknown opencode-account verb '{other}'"
        ))),
    }
}

fn add(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let provider = required(args, "--provider")?;
    let label = required(args, "--label")?;
    validate_label(&label)?;
    let key_file = required(args, "--key-file")?;
    let before = optional(args, "--before");
    let handle_path = handle_path(args);

    if let Some(shape) = opencode_migration::unsafe_provider_shape(&provider)? {
        return Err(CliError::Usage(format!(
            "refusing opencode-account add for {provider}: shape={} why={} source={}; this is availability-only (the sentinel is non-secret), but account failover cannot make a provider outside the fetch seam safe; run migrate-opencode --restore {provider}",
            shape.shape_names(),
            shape.why(),
            shape.sites(),
        )));
    }

    let mut handles = opencode_migration::read_handles_or_empty(&handle_path)?;
    let provider_entry = handles
        .providers
        .iter()
        .find(|entry| entry.provider == provider)
        .ok_or_else(|| {
            CliError::Usage(format!(
                "provider {provider} is not migrated; run migrate-opencode first"
            ))
        })?;
    if !matches!(provider_entry.shape, opencode_files::HandleShape::Api)
        || provider_entry.serve.is_empty()
    {
        return Err(CliError::Usage(format!(
            "provider {provider} has an unsupported handle shape; migrate-opencode supports api entries"
        )));
    }
    let existing_account = provider_entry
        .accounts
        .iter()
        .find(|account| account.label == label)
        .cloned();
    let insert_at = before
        .as_deref()
        .map(|wanted| {
            provider_entry
                .accounts
                .iter()
                .position(|account| account.label == wanted)
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "--before label '{wanted}' does not exist for provider {provider}"
                    ))
                })
        })
        .transpose()?;

    let material = read_key_material(&key_file)?;
    if material.is_empty() {
        return Err(CliError::Usage(
            "--key-file contains no key material".into(),
        ));
    }
    let id = format!("apikey:{provider}:{label}");
    if let Some(account) = existing_account {
        if global.subc_conn.is_none() {
            return Err(CliError::Usage(format!(
                "account label '{label}' already exists for provider {provider}"
            )));
        }
        if account.credential_id != id {
            return Err(CliError::Io(
                "existing handle account points at another credential".into(),
            ));
        }
        let existing = opencode_migration::get_material(global, &account.handle)?
            .ok_or_else(|| CliError::Io("existing account handle was revoked".into()))?;
        if existing != material {
            return Err(CliError::Usage(format!(
                "existing credential {id} differs; remove the account before replacing it"
            )));
        }
        opencode_migration::finalize_superseded(global, &mut handles, &provider, &handle_path)?;
        println!(
            "provider={provider} label={label} credential_id={id} identical handle_file={}",
            handle_path.display()
        );
        return Ok(());
    }

    let exists = super::parse_inventory(&super::request_admin_status(global)?)?
        .iter()
        .any(|(_, _, candidate)| candidate == &id);
    if exists {
        let verification_handle = opencode_migration::mint_handle(global, &id)?;
        let existing = opencode_migration::get_material(global, &verification_handle)?
            .ok_or_else(|| CliError::Io("fresh capability was revoked before comparison".into()))?;
        if existing != material {
            return Err(CliError::Usage(format!(
                "existing credential {id} differs; remove the account before replacing it"
            )));
        }
        opencode_migration::revoke_all_handles(global, &id)?;
    } else {
        commit_admin(
            global,
            store_op(
                &id,
                VaultRecord::new_static(CredentialKind::ApiKey, "opencode", material, None),
                AdminAuditOp::Import,
                StoreMode::Create,
            ),
        )?;
    }
    opencode_migration::mint_then_persist(global, &id, |handle| {
        let provider_entry = handles
            .providers
            .iter_mut()
            .find(|entry| entry.provider == provider)
            .expect("provider validated before store");
        let account = opencode_files::HandleAccount {
            label: label.clone(),
            handle: handle.into(),
            credential_id: id.clone(),
            superseded: Vec::new(),
        };
        if let Some(index) = insert_at {
            provider_entry.accounts.insert(index, account);
        } else {
            provider_entry.accounts.push(account);
        }
        opencode_migration::write_and_verify_handles(&handle_path, &handles)
    })?;
    opencode_migration::finalize_superseded(global, &mut handles, &provider, &handle_path)?;
    println!(
        "provider={provider} label={label} credential_id={id} added handle_file={}",
        handle_path.display()
    );
    Ok(())
}

fn remove(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let provider = required(args, "--provider")?;
    let label = required(args, "--label")?;
    validate_label(&label)?;
    let handle_path = handle_path(args);
    let mut handles = opencode_migration::read_handles_or_empty(&handle_path)?;
    let provider_entry = handles
        .providers
        .iter()
        .find(|entry| entry.provider == provider)
        .ok_or_else(|| CliError::Usage(format!("no handle entry for provider {provider}")))?;
    if !matches!(provider_entry.shape, opencode_files::HandleShape::Api) {
        return Err(CliError::Usage(format!(
            "remove for {provider} accepts only api entries"
        )));
    }
    let account = provider_entry
        .accounts
        .iter()
        .find(|account| account.label == label)
        .cloned()
        .ok_or_else(|| {
            CliError::Usage(format!(
                "no account label '{label}' for provider {provider}"
            ))
        })?;
    if provider_entry.accounts.len() == 1 {
        return Err(CliError::Usage(format!(
            "refusing to remove the last account for {provider}; use migrate-opencode --restore"
        )));
    }

    let mut handles_to_revoke = vec![account.handle];
    handles_to_revoke.extend(account.superseded);
    for handle in handles_to_revoke {
        commit_admin(
            global,
            AdminOpBody::RevokeHandle {
                v: ADMIN_OP_SCHEMA_V1,
                handle,
            },
        )?;
    }
    opencode_migration::remove_account(&mut handles, &provider, &label)?;
    opencode_migration::write_and_verify_handles(&handle_path, &handles)?;
    println!(
        "provider={provider} label={label} removed handle_file={}",
        handle_path.display()
    );
    Ok(())
}

fn list(global: &GlobalArgs, args: &[String]) -> Result<(), CliError> {
    let provider_filter = optional(args, "--provider");
    let handle_path = handle_path(args);
    let handles = opencode_migration::read_handles_or_empty(&handle_path)?;
    let status = super::parse_inventory(&request_admin_status(global)?)?;
    let metadata: BTreeMap<String, (String, u64)> = status
        .into_iter()
        .map(|(state, version, id)| (id, (state, version)))
        .collect();

    for provider_entry in handles.providers {
        if provider_filter
            .as_deref()
            .is_some_and(|wanted| wanted != provider_entry.provider)
        {
            continue;
        }
        for account in provider_entry.accounts {
            let (state, version) = metadata.get(&account.credential_id).ok_or_else(|| {
                CliError::Io(format!(
                    "handle account {} points at missing credential {}",
                    account.label, account.credential_id
                ))
            })?;
            println!(
                "provider={} label={} credential_id={} {state} v{version}",
                provider_entry.provider, account.label, account.credential_id
            );
        }
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), CliError> {
    if label.contains(':') {
        return Err(CliError::Usage("account label must not contain ':'".into()));
    }
    if label.is_empty()
        || label.len() > 64
        || matches!(label, "__proto__" | "constructor" | "prototype")
        || !label.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
    {
        return Err(CliError::Usage(
            "account label must match [a-z0-9][a-z0-9._-]{0,63}".into(),
        ));
    }
    Ok(())
}

fn read_key_material(path: &str) -> Result<Vec<u8>, CliError> {
    if path == "-" {
        let mut material = Vec::new();
        std::io::stdin()
            .read_to_end(&mut material)
            .map_err(|error| CliError::Io(format!("read key material from stdin: {error}")))?;
        trim_terminal_newline(&mut material);
        return Ok(material);
    }
    std::fs::read(path).map_err(|error| CliError::Io(format!("read key file {path}: {error}")))
}

fn trim_terminal_newline(material: &mut Vec<u8>) {
    if material.ends_with(b"\r\n") {
        material.truncate(material.len() - 2);
    } else if material.ends_with(b"\n") {
        material.pop();
    }
}

fn handle_path(args: &[String]) -> PathBuf {
    optional(args, "--handle-file")
        .map(PathBuf::from)
        .unwrap_or_else(opencode_files::default_handle_path)
}

fn required(args: &[String], flag: &str) -> Result<String, CliError> {
    optional(args, flag).ok_or_else(|| CliError::Usage(format!("{flag} is required")))
}

fn optional(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .filter(|value| !value.starts_with("--"))
        .cloned()
}
