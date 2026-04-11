use std::time::Duration;

use serde::Deserialize;

use crate::constants::HTTP_TIMEOUT_SECS;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Response from the OIDC token endpoint.
///
/// Both fields are optional because the Python code uses `.get()` which
/// returns `None` when the key is absent.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub id_token: Option<String>,
    #[allow(dead_code)]
    pub access_token: Option<String>,
}

// ---------------------------------------------------------------------------
// Token Exchange
// ---------------------------------------------------------------------------

/// Exchanges an authorization code for tokens at the OIDC token endpoint.
///
/// This matches the Python behavior in `handle_standard_token_exchange` and
/// `handle_dynamic_client_token_exchange`:
/// - POST to token_endpoint with `application/x-www-form-urlencoded` body
/// - Includes grant_type, code, redirect_uri, client_id, code_verifier
/// - 5 second timeout and User-Agent header
/// - On non-200 status, returns [`Error::TokenRequest`] with the response body
/// - Extracts `id_token` and `access_token` from the JSON response
pub async fn exchange_authorization_code(
    token_endpoint: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: &str,
) -> Result<TokenResponse> {
    let client = crate::http::shared_client();

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];

    let response = client
        .post(token_endpoint)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|e| Error::TokenRequest(format!("{e}")))?;

    if response.status().as_u16() != 200 {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read response body>".to_string());
        return Err(Error::TokenRequest(format!(
            "Acquiring tokens from OpenID Provider Failed: {body}"
        )));
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|e| Error::TokenRequest(format!("Failed to parse token response: {e}")))?;

    Ok(token_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_response_deserialization_full() {
        let json = r#"{"id_token": "abc", "access_token": "def"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id_token.as_deref(), Some("abc"));
        assert_eq!(resp.access_token.as_deref(), Some("def"));
    }

    #[test]
    fn test_token_response_deserialization_missing_fields() {
        let json = r#"{}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(resp.id_token.is_none());
        assert!(resp.access_token.is_none());
    }

    #[test]
    fn test_token_response_deserialization_partial() {
        let json = r#"{"id_token": "abc"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id_token.as_deref(), Some("abc"));
        assert!(resp.access_token.is_none());
    }

    #[test]
    fn test_token_request_error_display() {
        let err = Error::TokenRequest("connection refused".to_string());
        assert_eq!(
            err.to_string(),
            "Token endpoint request failed: connection refused"
        );
    }
}
