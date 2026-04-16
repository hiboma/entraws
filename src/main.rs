mod aws;
mod client_credentials;
mod config;
mod constants;
mod credential;
mod credentials_cmd;
mod error;
mod http;
mod oidc;
mod pkce;
mod server;
mod status_cmd;
mod token;

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{debug, info};

#[tokio::main]
async fn main() {
    // Parse once and branch on whether a subcommand was supplied. The
    // `credentials` subcommand is invoked by the AWS CLI as a
    // `credential_process` helper and therefore must never start a browser
    // flow: we dispatch it here before any tracing output goes to stderr,
    // because AWS CLI captures stderr from credential_process subprocesses.
    match config::parse_invocation() {
        config::Invocation::Credentials(args) => {
            credentials_cmd::run(args);
        }
        config::Invocation::Status(args) => {
            status_cmd::run(args);
        }
        config::Invocation::Login(config) => {
            run_login(config).await;
        }
    }
}

async fn run_login(config: config::Config) {
    // Set STS regional endpoints before any AWS SDK calls
    unsafe {
        std::env::set_var("AWS_STS_REGIONAL_ENDPOINTS", "regional");
    }

    // Initialize tracing
    let filter = if config.debug {
        "debug"
    } else if config.quiet {
        "warn"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .init();

    info!("Starting entraws - AWS STS OIDC Driver");
    debug!("Role ARN: {}", config.role);
    debug!("OpenID URL: {}", config.openid_url);
    debug!("Region: {}", config.region);

    // Fetch OIDC discovery configuration. On failure, print the error chain
    // and exit: this is the only place in the crate that calls `exit(1)` for
    // runtime failures, so every module below returns `Result<_, Error>` and
    // lets `main` decide how to surface it.
    let oidc_config = match oidc::get_oidc_config(&config.openid_url).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if config.client_credentials {
        // Client credentials flow — no browser interaction needed
        info!("Using client_credentials grant flow");
        match client_credentials::handle_client_credentials_flow(&config, &oidc_config).await {
            Ok(()) => {
                info!("Client credentials flow completed successfully");
            }
            Err(e) => {
                eprintln!("Error: Client credentials flow failed: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // Browser-based flow (authorization code or implicit)
        let flow_type = if config.implicit {
            "implicit"
        } else {
            "authorization_code"
        };
        info!("Using {flow_type} flow");

        // Generate PKCE parameters
        let pkce_params = pkce::PkceParams::generate();

        // Shared shutdown signal
        let shutdown = Arc::new(Notify::new());

        // Build shared application state for the server
        let app_state = Arc::new(server::AppState {
            config,
            oidc_config,
            pkce: pkce_params,
            dynamic_client_id: std::sync::OnceLock::new(),
            shutdown_notify: shutdown.clone(),
        });

        // Bind the server first so the port is ready before the browser connects
        let (listener, app) = server::bind_server(app_state.clone()).await;

        // Open browser for authentication (server handles the redirect on GET /)
        let browser_url = format!("http://127.0.0.1:{}/", constants::CALLBACK_PORT);
        info!("Opening browser for authentication...");
        if let Err(e) = webbrowser::open(&browser_url) {
            eprintln!("Error: Failed to open browser: {e}");
            eprintln!("Please open this URL manually: {browser_url}");
        }

        // Run the server with a 2-minute wall-clock timeout
        tokio::select! {
            _ = server::serve(listener, app, shutdown.clone()) => {},
            _ = tokio::time::sleep(Duration::from_secs(120)) => {
                tracing::info!("Operation timed out after 2 minutes");
                shutdown.notify_one();
            }
        }

        info!("Browser flow completed successfully");
    }
}
