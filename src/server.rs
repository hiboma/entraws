use std::sync::Arc;

use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing::{debug, info};

use crate::constants::{CALLBACK_PORT as PORT, REDIRECT_URI};

/// Shared application state accessible by all route handlers.
pub struct AppState {
    pub config: crate::config::Config,
    pub oidc_config: crate::oidc::OidcConfig,
    pub pkce: crate::pkce::PkceParams,
    pub dynamic_client_id: tokio::sync::Mutex<Option<String>>,
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
                    *state.dynamic_client_id.lock().await = Some(id.clone());
                    id
                }
                Err(e) => {
                    info!("Dynamic client registration failed: {}", e);
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

    let pkce_state = &state.pkce.state;
    let role_arn = &state.config.role;
    let aws_config_file = state.config.aws_config_file.display().to_string();
    let profile_to_update = &state.config.profile_to_update;

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Handling OIDC</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #f7f7f5;
            --fg: #1c1c1c;
            --muted: #6b6b6b;
            --rule: #e3e3de;
            --accent-success: #0f7b4a;
            --accent-error: #9b1c1c;
            --accent-processing: #1c1c1c;
        }}
        * {{ box-sizing: border-box; }}
        html, body {{
            margin: 0;
            padding: 0;
            background: var(--bg);
            color: var(--fg);
            font-family: 'IBM Plex Sans', sans-serif;
            font-size: 15px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }}
        body {{
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 48px 24px;
        }}
        .card {{
            width: 100%;
            max-width: 640px;
            background: #ffffff;
            border: 1px solid var(--rule);
            padding: 48px 56px;
        }}
        .eyebrow {{
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            font-weight: 500;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            color: var(--muted);
            margin: 0 0 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .eyebrow-mark {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: currentColor;
            color: #ffffff;
            font-size: 11px;
            font-weight: 600;
            line-height: 1;
        }}
        .eyebrow-mark svg {{
            width: 10px;
            height: 10px;
        }}
        .card.success .eyebrow {{ color: var(--accent-success); }}
        .card.error .eyebrow {{ color: var(--accent-error); }}
        .card.processing .eyebrow {{ color: var(--accent-processing); }}
        .card.processing .eyebrow-mark {{
            background: transparent;
            border: 2px solid currentColor;
            border-top-color: transparent;
            animation: spin 0.9s linear infinite;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        h1 {{
            font-family: 'IBM Plex Sans', sans-serif;
            font-weight: 600;
            font-size: 22px;
            line-height: 1.35;
            margin: 0 0 20px;
            letter-spacing: -0.01em;
        }}
        h1 code {{
            font-family: 'IBM Plex Mono', monospace;
            font-size: 15px;
            font-weight: 500;
            background: #f2f2ee;
            padding: 2px 6px;
            word-break: break-all;
        }}
        p {{
            margin: 0 0 14px;
            color: #333;
        }}
        p.muted {{ color: var(--muted); }}
        code, kbd {{
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            background: #f2f2ee;
            padding: 2px 6px;
            word-break: break-all;
        }}
        dl {{
            margin: 24px 0 28px;
            padding: 20px 0;
            border-top: 1px solid var(--rule);
            border-bottom: 1px solid var(--rule);
            display: grid;
            grid-template-columns: auto 1fr;
            column-gap: 20px;
            row-gap: 10px;
        }}
        dt {{
            font-family: 'IBM Plex Mono', monospace;
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--muted);
            padding-top: 2px;
        }}
        dd {{
            margin: 0;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            word-break: break-all;
        }}
        hr {{
            border: none;
            border-top: 1px solid var(--rule);
            margin: 24px 0;
        }}
    </style>
</head>
<body>
    <div id="root">
        <div class="card processing">
            <p class="eyebrow"><span class="eyebrow-mark"></span>Processing</p>
            <h1>Completing authentication</h1>
            <p class="muted">Exchanging the authorization response with your identity provider.</p>
        </div>
    </div>
    <script>
        (function() {{
            function signalAuthFailure(reason) {{
                fetch('/auth/authfail', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ reason: reason }})
                }});
            }}

            function escapeHtml(s) {{
                return String(s)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
            }}

            function render(html) {{
                document.getElementById('root').innerHTML = html;
            }}

            function showError(message) {{
                render(`
                    <div class="card error">
                        <p class="eyebrow"><span class="eyebrow-mark">!</span>Failed</p>
                        <h1>Authentication failed</h1>
                        <p>${{escapeHtml(message)}}</p>
                        <hr>
                        <p class="muted">Additional debug information from your identity provider may be present in the address bar.</p>
                        <p class="muted">You may now close this window and try again.</p>
                    </div>`);
            }}

            function showSuccess() {{
                render(`
                    <div class="card success">
                        <p class="eyebrow"><span class="eyebrow-mark">✓</span>Authenticated</p>
                        <h1>Role assumed successfully</h1>
                        <p>Your AWS credentials have been written to the profile below.</p>
                        <dl>
                            <dt>Role</dt>
                            <dd>{role_arn}</dd>
                            <dt>File</dt>
                            <dd>{aws_config_file}</dd>
                            <dt>Profile</dt>
                            <dd>{profile_to_update}</dd>
                        </dl>
                        <p>Use this profile with the AWS CLI by passing <code>--profile {profile_to_update}</code>.</p>
                        <p class="muted">For the AWS SDK, refer to your SDK documentation on specifying a named profile. You may now close this window.</p>
                    </div>`);
                window.location.hash = '';
            }}

            function handleError(response) {{
                if (!response.ok) {{
                    return response.json().then(errorData => {{
                        throw new Error(errorData.message || 'Authentication failed');
                    }});
                }}
                return response.json();
            }}

            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');

            if (code) {{
                console.log("Detected authorization code flow");
                const receivedState = urlParams.get('state');
                if (!receivedState || receivedState !== '{pkce_state}') {{
                    showError('Invalid state parameter');
                    signalAuthFailure('invalid_state');
                    return;
                }}

                fetch('/process_token', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        code: code,
                        state: receivedState,
                        grant_type: 'authorization_code'
                    }})
                }})
                .then(handleError)
                .then(data => {{
                    if (data.status === 'success') {{
                        showSuccess();
                    }} else {{
                        showError(data.message || 'Unknown error occurred');
                        signalAuthFailure('unknown_error');
                    }}
                }})
                .catch(error => {{
                    showError(error.message || 'Failed to process authentication');
                    signalAuthFailure('unknown_error');
                }});
            }} else {{
                const hash = window.location.hash.substr(1);
                const result = hash.split('&').reduce((result, item) => {{
                    const [key, value] = item.split('=');
                    result[key] = decodeURIComponent(value);
                    return result;
                }}, {{}});

                if (!result.state || result.state !== '{pkce_state}') {{
                    showError('Invalid state parameter');
                    signalAuthFailure('invalid_state');
                    return;
                }}
                if (result.id_token) {{
                    console.log("Detected implicit flow");

                    fetch('/process_token', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            id_token: result.id_token,
                            state: result.state,
                            grant_type: 'implicit'
                        }})
                    }})
                    .then(handleError)
                    .then(data => {{
                        if (data.status === 'success') {{
                            showSuccess();
                        }} else {{
                            showError(data.message || 'Unknown error occurred');
                            signalAuthFailure('unknown_error');
                        }}
                    }})
                    .catch(error => {{
                        showError(error.message || 'Failed to process authentication');
                        signalAuthFailure('unknown_error');
                    }});
                }} else {{
                    showError('No code or token found in response');
                    signalAuthFailure('no_token');
                }}
            }}
        }})();
    </script>
</body>
</html>"#,
        role_arn = role_arn,
        aws_config_file = aws_config_file,
        profile_to_update = profile_to_update,
        pkce_state = pkce_state,
    );

    Html(html)
}

/// POST /process_token — Exchange authorization code or implicit token for AWS credentials.
async fn process_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ProcessTokenRequest>,
) -> impl IntoResponse {
    debug!("Server received request on /process_token");

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
        info!("state mismatch from /process_token");
        let response = ApiResponse {
            status: "error".to_string(),
            message: Some("Invalid state parameter".to_string()),
        };
        return (axum::http::StatusCode::FORBIDDEN, Json(response)).into_response();
    }

    // Determine the id_token either by exchanging a code or using the one provided directly.
    let id_token = if let Some(ref code) = body.code {
        debug!("Authorization code received on /process_token");

        // Determine the client_id to use for the token exchange.
        let client_id = if config.is_dynamic_client {
            debug!("/process_token is handling a dynamic client");
            let lock = state.dynamic_client_id.lock().await;
            lock.clone().unwrap_or_default()
        } else {
            debug!(
                "/process_token is handling a non-dynamic client using authorization code grant"
            );
            config.client_id.clone().unwrap_or_default()
        };

        match crate::token::exchange_authorization_code(
            &state.oidc_config.token_endpoint,
            code,
            REDIRECT_URI,
            &client_id,
            &state.pkce.code_verifier,
        )
        .await
        {
            Ok(token_response) => {
                debug!("Received id_token from token exchange");
                token_response.id_token.unwrap_or_default()
            }
            Err(e) => {
                info!("Token exchange failed: {}", e);
                let response = ApiResponse {
                    status: "error".to_string(),
                    message: Some(format!(
                        "Acquiring tokens from OpenID Provider Failed: {}",
                        e
                    )),
                };
                return (axum::http::StatusCode::BAD_REQUEST, Json(response)).into_response();
            }
        }
    } else if let Some(ref token) = body.id_token {
        debug!("/process_token is handling an implicit flow request");
        debug!("Received id_token from implicit flow");
        token.clone()
    } else {
        debug!("no id_token or code found in the post to /process_token");
        let response = ApiResponse {
            status: "error".to_string(),
            message: Some("No code or id_token provided".to_string()),
        };
        return (axum::http::StatusCode::BAD_REQUEST, Json(response)).into_response();
    };

    // Assume role with the id_token.
    let assume_result = crate::aws::assume_role_with_token(
        &config.region,
        &config.role,
        &id_token,
        config.duration_seconds as i32,
        config.dangerously_log_secrets,
        &state.oidc_config.issuer,
    )
    .await;

    let credentials = match assume_result {
        Ok(creds) => creds,
        Err(e) => {
            info!("Failed to assume role: {}", e);
            state.shutdown_notify.notify_one();
            let response = ApiResponse {
                status: "error".to_string(),
                message: Some(format!("Failed to assume role with web identity: {}", e)),
            };
            return (axum::http::StatusCode::BAD_REQUEST, Json(response)).into_response();
        }
    };

    // Write the credentials to the AWS config file.
    let config_file_str = config.aws_config_file.display().to_string();
    if let Err(e) =
        crate::aws::write_credentials(&credentials, &config_file_str, &config.profile_to_update)
    {
        info!("Failed to write credentials: {}", e);
        let response = ApiResponse {
            status: "error".to_string(),
            message: Some(format!("Failed to write credentials: {}", e)),
        };
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(response),
        )
            .into_response();
    }

    state.shutdown_notify.notify_one();

    let response = ApiResponse {
        status: "success".to_string(),
        message: None,
    };
    Json(response).into_response()
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
