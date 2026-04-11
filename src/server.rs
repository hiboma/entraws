use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing::{debug, info};

use crate::constants::{CALLBACK_PORT as PORT, REDIRECT_URI};
use crate::error::Error;

/// Shared application state accessible by all route handlers.
pub struct AppState {
    pub config: crate::config::Config,
    pub oidc_config: crate::oidc::OidcConfig,
    pub pkce: crate::pkce::PkceParams,
    /// Client ID obtained from dynamic client registration. Written once
    /// by the `home` handler and read once by `process_token`; there is no
    /// concurrent writer, so `OnceLock` is sufficient (and cheaper than a
    /// `tokio::sync::Mutex`).
    pub dynamic_client_id: std::sync::OnceLock<String>,
    pub shutdown_notify: Arc<Notify>,
}

/// JSON body received on POST /process_token.
#[derive(Deserialize)]
struct ProcessTokenRequest {
    code: Option<String>,
    id_token: Option<String>,
    state: Option<String>,
    #[allow(dead_code)]
    grant_type: Option<String>,
}

/// JSON response returned from POST /process_token and POST /auth/authfail.
#[derive(Serialize)]
struct ApiResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// JSON body received on POST /auth/authfail.
#[derive(Deserialize)]
struct AuthFailRequest {
    reason: Option<String>,
}

/// GET / — Start the OIDC flow by redirecting to the IdP's authorization endpoint.
async fn home(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    debug!("Server received request on \"/\"");

    let config = &state.config;
    let oidc_config = &state.oidc_config;
    let pkce = &state.pkce;

    // スコープ決定
    let scopes = if !config.is_dynamic_client
        && !config.implicit
        && config.openid_url.to_lowercase().contains("okta.com")
    {
        debug!("Okta native client detected, setting scopes to openid email offline_access");
        "openid email offline_access".to_string()
    } else {
        config
            .scopes
            .clone()
            .unwrap_or_else(|| "openid email".to_string())
    };

    // client_id と response_type を分岐で決定
    let (client_id, response_type) = if config.is_dynamic_client {
        // Dynamic client registration
        debug!("We believe this is a dynamic client using authz code flow");
        let id = if let Some(ref ep) = oidc_config.registration_endpoint {
            match crate::oidc::register_dynamic_client(ep, REDIRECT_URI).await {
                Ok(id) => {
                    // `set` only fails if the value was already initialised;
                    // we intentionally ignore that case (idempotent write).
                    state.dynamic_client_id.set(id.clone()).ok();
                    id
                }
                Err(e) => {
                    info!("{}", e);
                    String::new()
                }
            }
        } else {
            String::new()
        };
        (id, "code")
    } else if config.implicit {
        debug!("We believe this is a public client using implicit flow");
        (
            config.client_id.as_deref().unwrap_or_default().to_string(),
            "id_token token",
        )
    } else {
        debug!("We believe this is a public client using authz code flow");
        (
            config.client_id.as_deref().unwrap_or_default().to_string(),
            "code",
        )
    };

    // 共通パラメータ構築
    let params = [
        ("client_id", client_id.as_str()),
        ("response_type", response_type),
        ("redirect_uri", REDIRECT_URI),
        ("scope", &scopes),
        ("state", &pkce.state),
        ("nonce", &pkce.nonce),
        ("code_challenge", &pkce.code_challenge),
        ("code_challenge_method", "S256"),
    ];

    let query_string = serde_urlencoded::to_string(params).unwrap_or_default();
    let auth_url = format!("{}?{}", oidc_config.authorization_endpoint, query_string);
    Redirect::temporary(&auth_url)
}

/// GET /callback — Return HTML/JS that handles both authorization code and implicit flows.
/// This is the exact HTML from the Python original (lines 186-322).
async fn callback(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    debug!("Server received on /callback");

    const TEMPLATE: &str = include_str!("../templates/callback.html");

    let html = TEMPLATE
        .replace("{{role_arn}}", &state.config.role)
        .replace(
            "{{aws_config_file}}",
            &state.config.aws_config_file.display().to_string(),
        )
        .replace("{{profile_to_update}}", &state.config.profile_to_update)
        .replace("{{pkce_state}}", &state.pkce.state);

    Html(html)
}

/// Core logic of `/process_token`: does everything that can fail with a typed
/// [`Error`], and leaves HTTP-status decisions to the outer handler so the
/// mapping from error kind to status code is centralized.
async fn process_token_inner(
    state: &Arc<AppState>,
    body: ProcessTokenRequest,
) -> Result<(), Error> {
    let config = &state.config;

    // Server-side validation of the `state` parameter. The callback HTML
    // already validates it in JavaScript, but an attacker who POSTs directly
    // to /process_token would bypass that check, so we re-validate here
    // using a constant-time comparison to avoid leaking timing information.
    let expected_state = state.pkce.state.as_bytes();
    let state_valid = body
        .state
        .as_deref()
        .map(|s| s.as_bytes().ct_eq(expected_state).into())
        .unwrap_or(false);

    if !state_valid {
        return Err(Error::InvalidState);
    }

    // Determine the id_token either by exchanging a code or using the one provided directly.
    let id_token = if let Some(ref code) = body.code {
        debug!("Authorization code received on /process_token");

        // Determine the client_id to use for the token exchange.
        let client_id = if config.is_dynamic_client {
            debug!("/process_token is handling a dynamic client");
            state.dynamic_client_id.get().cloned().unwrap_or_default()
        } else {
            debug!(
                "/process_token is handling a non-dynamic client using authorization code grant"
            );
            config.client_id.clone().unwrap_or_default()
        };

        let token_response = crate::token::exchange_authorization_code(
            &state.oidc_config.token_endpoint,
            code,
            REDIRECT_URI,
            &client_id,
            &state.pkce.code_verifier,
        )
        .await?;

        debug!("Received id_token from token exchange");
        token_response.id_token.ok_or(Error::MissingIdToken)?
    } else if let Some(ref token) = body.id_token {
        debug!("/process_token is handling an implicit flow request");
        debug!("Received id_token from implicit flow");
        token.clone()
    } else {
        debug!("no id_token or code found in the post to /process_token");
        return Err(Error::TokenRequest(
            "No code or id_token provided".to_string(),
        ));
    };

    // Assume role with the id_token.
    let credentials = crate::aws::assume_role_with_token(
        &config.region,
        &config.role,
        &id_token,
        config.duration_seconds,
        config.dangerously_log_secrets,
        &state.oidc_config.issuer,
    )
    .await?;

    // Write the credentials to the AWS config file.
    let config_file_str = config.aws_config_file.display().to_string();
    crate::aws::write_credentials(&credentials, &config_file_str, &config.profile_to_update)?;

    Ok(())
}

/// Map a crate [`Error`] to an HTTP status code. Anything caused by bad
/// request input gets 400, `InvalidState` gets 403 (same as the old hand-
/// written path), and filesystem/credential write errors are 500. Everything
/// else is surfaced as 400 to avoid leaking details.
fn status_for_error(err: &Error) -> StatusCode {
    match err {
        Error::InvalidState => StatusCode::FORBIDDEN,
        Error::WriteCredentials { .. }
        | Error::ReadCredentials { .. }
        | Error::ParseCredentialsIni { .. }
        | Error::SerializeCredentials(_)
        | Error::SymlinkRejected(_)
        | Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

/// POST /process_token — Exchange authorization code or implicit token for AWS credentials.
async fn process_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ProcessTokenRequest>,
) -> impl IntoResponse {
    debug!("Server received request on /process_token");

    match process_token_inner(&state, body).await {
        Ok(()) => {
            state.shutdown_notify.notify_one();
            let response = ApiResponse {
                status: "success".to_string(),
                message: None,
            };
            Json(response).into_response()
        }
        Err(e) => {
            info!("/process_token failed: {}", e);
            let status = status_for_error(&e);
            // Matches the previous behavior: notify shutdown only for
            // AssumeRoleWithWebIdentity failures (Sts / NoStsCredentials /
            // MissingIssuer / IssuerMismatch / NoRoleSessionName / JwtDecode).
            // InvalidState, token exchange, and write-credentials failures
            // leave the server running.
            if matches!(
                e,
                Error::Sts(_)
                    | Error::NoStsCredentials
                    | Error::MissingIssuer
                    | Error::IssuerMismatch { .. }
                    | Error::NoRoleSessionName
                    | Error::JwtDecode(_)
            ) {
                state.shutdown_notify.notify_one();
            }
            let response = ApiResponse {
                status: "error".to_string(),
                message: Some(e.to_string()),
            };
            (status, Json(response)).into_response()
        }
    }
}

/// POST /auth/authfail — Log the failure and signal shutdown.
async fn auth_failure(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthFailRequest>,
) -> impl IntoResponse {
    debug!("Server received request on /auth/authfail");

    match body.reason {
        Some(ref reason) => {
            info!("Requested by front end to shutdown for: {}", reason);
        }
        None => {
            info!("Received request to terminate from frontend, no reason received");
        }
    }

    state.shutdown_notify.notify_one();

    let response = ApiResponse {
        status: "success".to_string(),
        message: None,
    };
    Json(response)
}

/// Bind the TCP listener and build the router, but do not start serving yet.
///
/// Returns `(TcpListener, Router)` so the caller can open the browser *after*
/// the port is ready, eliminating the race condition where the browser hits a
/// socket that is not yet listening.
pub async fn bind_server(state: Arc<AppState>) -> (TcpListener, Router) {
    let app = Router::new()
        .route("/", get(home))
        .route("/callback", get(callback))
        .route("/process_token", post(process_token))
        .route("/auth/authfail", post(auth_failure))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", PORT);
    info!("Binding server on {}", addr);

    let listener = TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {}: {}", addr, e));

    (listener, app)
}

/// Start serving on an already-bound listener with graceful shutdown.
pub async fn serve(listener: TcpListener, app: Router, shutdown_notify: Arc<Notify>) {
    info!("Serving on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_notify.notified().await;
            info!("Shutdown signal received, stopping server");
        })
        .await
        .unwrap_or_else(|e| {
            info!("Server error: {}", e);
        });
}
