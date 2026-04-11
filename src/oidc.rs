use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;

use crate::constants::HTTP_TIMEOUT_SECS;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// OIDC Discovery
// ---------------------------------------------------------------------------

/// Represents the subset of fields from the OpenID Connect discovery document
/// (.well-known/openid-configuration) that this driver requires.
#[derive(Debug, Deserialize)]
pub struct OidcConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    pub issuer: String,
}

/// Fetches and deserializes the OpenID Connect discovery document.
///
/// On any failure (network error, non-2xx status, JSON parse error), returns
/// an [`Error::OidcDiscovery`] or [`Error::OidcDiscoveryParse`] so the caller
/// can decide how to surface the problem. The Python original exited directly;
/// `main.rs` restores that behavior by matching on the returned `Result`.
pub async fn get_oidc_config(discovery_url: &str) -> Result<OidcConfig> {
    let client = crate::http::shared_client();

    let response = client
        .get(discovery_url)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|source| Error::OidcDiscovery {
            url: discovery_url.to_string(),
            source,
        })?;

    let config: OidcConfig = response
        .json()
        .await
        .map_err(|source| Error::OidcDiscoveryParse {
            url: discovery_url.to_string(),
            source,
        })?;

    tracing::debug!("OIDC configuration received: {config:?}");
    Ok(config)
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration
// ---------------------------------------------------------------------------

/// Holds the client_id obtained through dynamic client registration.
pub struct DynamicClient {
    pub client_id: Option<String>,
}

impl DynamicClient {
    /// Creates a new `DynamicClient` with no client_id.
    pub fn new() -> Self {
        Self { client_id: None }
    }

    /// Registers a dynamic client at the given registration endpoint.
    ///
    /// On success (HTTP 201), stores the `client_id` from the response and
    /// returns `Ok(client_id)`. On failure, returns an error description.
    ///
    /// Matches the Python implementation:
    /// - Sends a JSON POST with application_type, redirect_uris, etc.
    /// - Appends a random suffix to client_name
    /// - Expects 201 with a `client_id` in the response body
    pub async fn register_client(
        &mut self,
        registration_endpoint: &str,
        redirect_uri: &str,
    ) -> Result<String> {
        tracing::debug!("Starting client registration at endpoint: {registration_endpoint}");

        let client_name_randomness = generate_random_suffix();
        let registration_data = serde_json::json!({
            "application_type": "native",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "client_name": format!("AWS STS OIDC Driver {client_name_randomness}"),
            "code_challenge_methods_supported": ["S256"]
        });

        tracing::debug!("Attempting registration with payload:");
        tracing::debug!(
            "{}",
            serde_json::to_string_pretty(&registration_data).unwrap_or_default()
        );

        let client = crate::http::shared_client();

        let response = client
            .post(registration_endpoint)
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .header("Content-Type", "application/json")
            .json(&registration_data)
            .send()
            .await
            .map_err(|e| Error::DynamicRegistration(format!("request failed: {e}")))?;

        let status = response.status();
        tracing::debug!("Registration response status: {status}");

        let response_json: serde_json::Value = response.json().await.map_err(|_| {
            Error::DynamicRegistration("Failed registering dynamic client".to_string())
        })?;

        tracing::debug!("Response body:");
        tracing::debug!(
            "{}",
            serde_json::to_string_pretty(&response_json).unwrap_or_default()
        );

        if status.as_u16() == 201 {
            let client_id = response_json["client_id"]
                .as_str()
                .ok_or_else(|| {
                    Error::DynamicRegistration("No client_id in registration response".to_string())
                })?
                .to_string();

            tracing::debug!("Successfully registered client with ID: {client_id}");
            self.client_id = Some(client_id.clone());
            Ok(client_id)
        } else {
            tracing::debug!("Registration failed with status {status}");
            Err(Error::DynamicRegistration(format!(
                "Registration failed with status {status}"
            )))
        }
    }
}

impl Default for DynamicClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Generates 8 random bytes as a base64url-encoded string (no padding),
/// matching `secrets.token_urlsafe(8)` in the Python code.
fn generate_random_suffix() -> String {
    let mut buf = [0u8; 8];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Register a dynamic client at the OIDC provider's registration endpoint.
/// Returns the dynamically assigned client_id on success.
pub async fn register_dynamic_client(
    registration_endpoint: &str,
    redirect_uri: &str,
) -> Result<String> {
    let mut client = DynamicClient::new();
    client
        .register_client(registration_endpoint, redirect_uri)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_client_new() {
        let client = DynamicClient::new();
        assert!(client.client_id.is_none());
    }

    #[test]
    fn test_dynamic_client_default() {
        let client = DynamicClient::default();
        assert!(client.client_id.is_none());
    }

    #[test]
    fn test_generate_random_suffix_length() {
        let suffix = generate_random_suffix();
        // 8 bytes base64url-encoded without padding = 11 characters
        assert_eq!(suffix.len(), 11);
    }

    #[test]
    fn test_generate_random_suffix_uniqueness() {
        let a = generate_random_suffix();
        let b = generate_random_suffix();
        assert_ne!(a, b);
    }
}
