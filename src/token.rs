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

#[cfg(test)]
mod integration_tests {
    //! End-to-end tests for [`exchange_authorization_code`] backed by a
    //! local [`wiremock`] server. Covers the happy path, server-side
    //! failures, and partial response bodies.
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn exchange_authorization_code_returns_tokens_on_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header("Content-Type", "application/x-www-form-urlencoded"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": "eyJ.fake.idtoken",
                "access_token": "fake-access-token"
            })))
            .mount(&server)
            .await;

        let endpoint = format!("{}/token", server.uri());
        let resp = exchange_authorization_code(
            &endpoint,
            "authcode",
            "http://127.0.0.1:6432/callback",
            "client-abc",
            "verifier-xyz",
        )
        .await
        .expect("should succeed");

        assert_eq!(resp.id_token.as_deref(), Some("eyJ.fake.idtoken"));
        assert_eq!(resp.access_token.as_deref(), Some("fake-access-token"));
    }

    #[tokio::test]
    async fn exchange_authorization_code_accepts_access_token_only() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fake-access-token"
            })))
            .mount(&server)
            .await;

        let endpoint = format!("{}/token", server.uri());
        let resp = exchange_authorization_code(
            &endpoint,
            "authcode",
            "http://127.0.0.1:6432/callback",
            "client-abc",
            "verifier-xyz",
        )
        .await
        .expect("should succeed");

        // `id_token` is optional in the response struct because some
        // providers only return an access token; the struct tolerates both.
        assert!(resp.id_token.is_none());
        assert_eq!(resp.access_token.as_deref(), Some("fake-access-token"));
    }

    #[tokio::test]
    async fn exchange_authorization_code_fails_on_400_with_error_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(
                    r#"{"error":"invalid_grant","error_description":"code expired"}"#,
                ),
            )
            .mount(&server)
            .await;

        let endpoint = format!("{}/token", server.uri());
        let err = exchange_authorization_code(
            &endpoint,
            "authcode",
            "http://127.0.0.1:6432/callback",
            "client-abc",
            "verifier-xyz",
        )
        .await
        .expect_err("should fail");

        match err {
            Error::TokenRequest(msg) => {
                assert!(
                    msg.contains("invalid_grant") && msg.contains("code expired"),
                    "error message should surface OIDC provider body, got: {msg}"
                );
            }
            other => panic!("expected TokenRequest, got {other:?}"),
        }
    }
}
