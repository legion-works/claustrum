//! CLI driver for the two Google-family vault-native login flows.
//!
//! The core crate owns the provider wire helpers; this module owns only the
//! interactive browser/listener and admin-store integration.

use credentials_core::google_login::{
    self as google, GoogleLoginProvider, AUTHORIZE_URL, SCOPES, TOKEN_URL,
};
use credentials_core::oauth_login::{
    build_authorize_url_google, exchange_authorization_code_google, generate_state, parse_callback,
};
use credentials_core::record::{RecordIdentity, VaultRecord};

use super::{has_flag, login_id_is_valid, optional, CliError, GlobalArgs};

/// Whether a provider flag belongs to one of the Google-family login flows.
pub fn is_provider(provider: &str) -> bool {
    GoogleLoginProvider::parse(provider).is_some()
}

/// Return the default id used by a Google-family provider, for picker and logout
/// metadata without requiring the PKCE-oriented provider table to own this wire.
pub fn default_id(provider: &str) -> Option<&'static str> {
    GoogleLoginProvider::parse(provider).map(GoogleLoginProvider::default_id)
}

/// Drive a Google authorization-code login and commit the resulting record.
pub fn cmd_login(
    global: &GlobalArgs,
    args: &[String],
    provider: &str,
    id_override: Option<String>,
    replace_override: bool,
) -> Result<(), CliError> {
    let wire = GoogleLoginProvider::parse(provider).expect("caller checked Google provider");
    let id = optional(args, "--id")
        .or(id_override)
        .unwrap_or_else(|| wire.default_id().to_string());
    if !login_id_is_valid(wire.default_id(), &id) {
        return Err(CliError::Usage(format!(
            "login --id must be '{d}' or '{d}:<label>' (a labeled account of the same provider, e.g. '{d}:work') — got '{id}'",
            d = wire.default_id()
        )));
    }

    let client_id = wire.client_id();
    let client_secret = wire.client_secret();
    let state = generate_state().map_err(|error| CliError::Io(format!("csprng: {error}")))?;
    let authorize_url = build_authorize_url_google(
        AUTHORIZE_URL,
        &client_id,
        wire.redirect_uri(),
        SCOPES,
        &state,
        google::AUTHORIZE_EXTRA_PARAMS,
    )
    .map_err(|error| CliError::Io(format!("building authorize url: {error}")))?;

    let listener = if has_flag(args, "--no-listener") {
        None
    } else {
        super::login_listener::loopback_bind_addr(wire.redirect_uri())
            .and_then(|address| super::login_listener::capture_callback(&address))
    };

    println!("Open this URL in a browser signed into the account to custody:");
    println!();
    println!("  {authorize_url}");
    println!();
    let _ = super::open_in_browser(&authorize_url);

    let captured = match listener {
        Some(listener) => {
            println!("Approve in the browser — the login completes here automatically.");
            let callback = listener.wait();
            if callback.is_some() {
                println!("Browser redirect received — completing the login, nothing to paste.");
            }
            callback
        }
        None => None,
    };
    let raw_callback = match captured {
        Some(callback) => callback,
        None => {
            let port = match wire {
                GoogleLoginProvider::Gemini => 8085,
                GoogleLoginProvider::Antigravity => 51121,
            };
            println!(
                "The browser may show a connection-refused page at 127.0.0.1:{port}; that is expected.\n\
                 Copy the FULL URL from the browser's address bar and paste it here, then Enter:"
            );
            let mut pasted = String::new();
            std::io::stdin()
                .read_line(&mut pasted)
                .map_err(|error| CliError::Io(format!("reading pasted code: {error}")))?;
            pasted
        }
    };
    let callback = parse_callback(&raw_callback)
        .ok_or_else(|| CliError::Usage("could not parse the login callback".to_string()))?;

    let http = credentials_core::http::ReqwestTransport::new()
        .map_err(|error| CliError::Io(error.to_string()))?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let tokens = super::tokio_block_on(exchange_authorization_code_google(
        &http,
        TOKEN_URL,
        &client_id,
        &client_secret,
        wire.redirect_uri(),
        &callback,
        &state,
        now_ms,
    ))
    .map_err(|error| CliError::Io(error.to_string()))?;

    let project = if wire == GoogleLoginProvider::Antigravity {
        Some(
            super::tokio_block_on(google::discover_antigravity_project(
                &http,
                &tokens.access_token,
            ))
            .map_err(|error| CliError::Io(error.to_string()))?,
        )
    } else {
        None
    };
    let email = super::tokio_block_on(google::google_userinfo_email(&http, &tokens.access_token));
    if let Some(email) = email.as_deref() {
        println!("account: {email}");
    }

    let refresh_token = match project.as_ref() {
        Some(project) => google::pack_antigravity_refresh(&tokens.refresh_token, project),
        None => tokens.refresh_token.clone(),
    };
    let oauth = credentials_core::oauth::OAuthCredential {
        access_token: tokens.access_token.clone(),
        refresh_token,
        expires_at_ms: tokens.expires_at_ms,
        token_url: TOKEN_URL.to_string(),
        client_id: Some(client_id),
        scopes: SCOPES.iter().map(|scope| (*scope).to_string()).collect(),
    };
    let record = VaultRecord::new_oauth(
        "login",
        wire.adapter_name(),
        oauth,
        tokens.access_token.into_bytes(),
    )
    .with_identity(RecordIdentity {
        // The email is the identity, not just a label. The read surface serves
        // `account_id` as the field consumers join on and treats `email` as display
        // metadata, so populating only `email` yields a record that renders a value
        // while resolving no identity -- a consumer labelling per account collapses
        // its accounts into one unlabelled entry and the wire looks unchanged. The
        // read surface states the invariant: email never ships without account_id.
        //
        // Google/antigravity access tokens are opaque rather than JWTs, so there is no
        // claim to parse live and no other stable per-account identifier available.
        account_id: email.clone(),
        email,
        org_name: None,
    });

    let replace = has_flag(args, "--replace") || replace_override;
    if replace {
        super::commit_admin(
            global,
            super::store_op(
                &id,
                record,
                credentials_core::admin_ops::AdminAuditOp::Login,
                credentials_core::admin_ops::StoreMode::ReplaceUnconditional {
                    clear_identity: false,
                },
            ),
        )?;
        println!("logged in and replaced {id}");
        return Ok(());
    }

    let result = super::commit_admin(
        global,
        super::store_op(
            &id,
            record,
            credentials_core::admin_ops::AdminAuditOp::Login,
            credentials_core::admin_ops::StoreMode::Create,
        ),
    );
    let already_exists = match &result {
        Err(CliError::Store(credentials_core::store::StoreOpError::AlreadyExists)) => true,
        Err(CliError::RouteRefused(message)) => message.contains("already exists"),
        _ => false,
    };
    if already_exists {
        return Err(CliError::Usage(format!(
            "'{id}' already holds a credential. To replace it, pass --replace (keeps its handles)."
        )));
    }
    result?;
    println!("logged in and stored {id}");
    Ok(())
}
