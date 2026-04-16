use std::collections::HashMap;
use std::time::Duration;

use tracing::debug;

use crate::constants::CLIENT_CREDENTIALS_TIMEOUT_SECS;
use crate::error::{Error, Result};

const DEFAULT_SCOPES: &str = "openid email";

/// Handle OAuth client credentials grant. No browser interaction needed.
/// Tries `client_secret_basic` (HTTP Basic Auth) first, falls back to `client_secret_post`.
pub async fn handle_client_credentials_flow(
    config: &crate::config::Config,
    oidc_config: &crate::oidc::OidcConfig,
) -> Result<()> {
    debug!("Starting client credentials flow");

    let token_endpoint = &oidc_config.token_endpoint;
    let scopes = config.scopes.as_deref().unwrap_or(DEFAULT_SCOPES);

    // client_credentials flow requires both client_id and client_secret (validated in Config).
    let client_id = config
        .client_id
        .as_deref()
        .expect("client_id is required for client_credentials flow");
    let client_secret = config
        .client_secret
        .as_deref()
        .expect("client_secret is required for client_credentials flow");

    let client = crate::http::shared_client();

    // Base form data shared by both authentication methods
    let mut base_form = HashMap::new();
    base_form.insert("grant_type", "client_credentials");
    base_form.insert("scope", scopes);

    // --- Try client_secret_basic first (credentials in Authorization header) ---
    let basic_result = try_client_secret_basic(
        &client,
        token_endpoint,
        &base_form,
        client_id,
        client_secret,
    )
    .await;

    if let Some(response_text) = basic_result {
        return process_client_credentials_response(config, oidc_config, &response_text).await;
    }

    // --- Fall back to client_secret_post (credentials in POST body) ---
    let response_text = try_client_secret_post(
        &client,
        token_endpoint,
        &base_form,
        client_id,
        client_secret,
    )
    .await?;

    process_client_credentials_response(config, oidc_config, &response_text).await
}

/// Attempt `client_secret_basic` authentication (HTTP Basic Auth).
/// Returns `Some(response_body)` on HTTP 200, `None` on failure (to trigger fallback).
async fn try_client_secret_basic(
    client: &reqwest::Client,
    token_endpoint: &str,
    form: &HashMap<&str, &str>,
    client_id: &str,
    client_secret: &str,
) -> Option<String> {
    debug!("Attempting client_secret_basic authentication");

    let result = client
        .post(token_endpoint)
        .basic_auth(client_id, Some(client_secret))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration::from_secs(CLIENT_CREDENTIALS_TIMEOUT_SECS))
        .form(form)
        .send()
        .await;

    match result {
        Ok(resp) => {
            if resp.status().as_u16() == 200 {
                debug!("client_secret_basic succeeded");
                match resp.text().await {
                    Ok(body) => Some(body),
                    Err(e) => {
                        debug!(
                            "client_secret_basic response read failed: {e}, falling back to client_secret_post"
                        );
                        None
                    }
                }
            } else {
                debug!(
                    "client_secret_basic failed ({}), falling back to client_secret_post",
                    resp.status().as_u16()
                );
                None
            }
        }
        Err(e) => {
            debug!("client_secret_basic request failed: {e}, falling back to client_secret_post");
            None
        }
    }
}

/// Attempt `client_secret_post` authentication (credentials in POST body).
/// Returns `Ok(response_body)` on HTTP 200, or an [`Error::TokenRequest`] on
/// failure so the caller can surface the error to `main` instead of exiting
/// directly.
async fn try_client_secret_post(
    client: &reqwest::Client,
    token_endpoint: &str,
    base_form: &HashMap<&str, &str>,
    client_id: &str,
    client_secret: &str,
) -> Result<String> {
    debug!("Attempting client_secret_post authentication");

    let mut form = base_form.clone();
    form.insert("client_id", client_id);
    form.insert("client_secret", client_secret);

    let resp = client
        .post(token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration::from_secs(CLIENT_CREDENTIALS_TIMEOUT_SECS))
        .form(&form)
        .send()
        .await
        .map_err(|e| Error::TokenRequest(format!("Failed to request token from provider: {e}")))?;

    if resp.status().as_u16() != 200 {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::TokenRequest(format!(
            "Token request failed with both client_secret_basic and client_secret_post: {body}"
        )));
    }

    debug!("client_secret_post succeeded");
    resp.text()
        .await
        .map_err(|e| Error::TokenRequest(format!("Failed to request token from provider: {e}")))
}

/// Process a successful client credentials token response.
/// Extracts the token (preferring `id_token` over `access_token`), assumes the AWS role,
/// and writes credentials to the configured file.
async fn process_client_credentials_response(
    config: &crate::config::Config,
    oidc_config: &crate::oidc::OidcConfig,
    response_body: &str,
) -> Result<()> {
    let tokens: serde_json::Value = serde_json::from_str(response_body)
        .map_err(|e| Error::TokenRequest(format!("Failed to parse token response JSON: {e}")))?;

    // Prefer id_token, fall back to access_token (matching Python behavior)
    let token = tokens
        .get("id_token")
        .or_else(|| tokens.get("access_token"))
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingIdToken)?;

    debug!("Token received from client credentials grant");

    let assume_result = crate::aws::assume_role_with_token(
        &config.region,
        &config.role,
        token,
        config.duration_seconds,
        config.dangerously_log_secrets,
        &oidc_config.issuer,
    )
    .await?;

    if config.export {
        crate::aws::print_credentials_as_exports(&assume_result);
    } else {
        let config_file_str = config.aws_config_file.display().to_string();
        crate::aws::write_credentials(&assume_result, &config_file_str, &config.profile_to_update)?;
    }

    Ok(())
}
