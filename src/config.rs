use clap::Parser;
use std::env;
use std::path::PathBuf;

/// AWS STS OIDC Driver - Get temporary AWS credentials via OpenID Connect
#[derive(Parser, Debug)]
#[command(name = "entraws")]
#[command(about = "Get temporary AWS credentials via OpenID Connect")]
pub struct CliArgs {
    /// AWS Role ARN to assume (env: AWS_ROLE_ARN)
    #[arg(long = "role")]
    pub role: Option<String>,

    /// OpenID Connect discovery URL (env: OIDC_DISCOVERY_URL)
    #[arg(long = "openid_url")]
    pub openid_url: Option<String>,

    /// OIDC Client ID (env: OIDC_CLIENT_ID). If absent, dynamic client registration is used.
    #[arg(long = "client_id")]
    pub client_id: Option<String>,

    /// OIDC Client Secret (env: OIDC_CLIENT_SECRET)
    #[arg(long = "client_secret")]
    pub client_secret: Option<String>,

    /// AWS Region (env: AWS_REGION, default: us-east-1)
    #[arg(long = "region")]
    pub region: Option<String>,

    /// Duration in seconds for the STS credentials (env: DURATION_SECONDS, default: 3600)
    #[arg(long = "duration-seconds")]
    pub duration_seconds: Option<u32>,

    /// AWS profile name to update (env: PROFILE_TO_UPDATE, default: entraws)
    #[arg(short = 'p', long = "profile-to-update")]
    pub profile_to_update: Option<String>,

    /// Path to AWS credentials file (env: AWS_CONFIG_FILE, default: ~/.aws/credentials)
    #[arg(long = "aws-config-file")]
    pub aws_config_file: Option<String>,

    /// Enable debug logging
    #[arg(long = "debug")]
    pub debug: bool,

    /// Log secret-bearing values (JWT claims such as iss/aud/sub/ver).
    /// Dangerous: use only when diagnosing authentication issues in a private
    /// environment, and never in shared logs. Implies --debug.
    #[arg(long = "dangerously-log-secrets")]
    pub dangerously_log_secrets: bool,

    /// Use implicit flow instead of authorization code flow
    #[arg(long = "implicit")]
    pub implicit: bool,

    /// Use client_credentials grant instead of browser-based flow
    #[arg(long = "client_credentials")]
    pub client_credentials: bool,

    /// Custom scopes to request
    #[arg(long = "scopes")]
    pub scopes: Option<String>,
}

/// Resolved configuration with all values finalized from CLI args and environment variables.
#[derive(Debug)]
pub struct Config {
    pub role: String,
    pub openid_url: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub region: String,
    pub duration_seconds: u32,
    pub profile_to_update: String,
    pub aws_config_file: PathBuf,
    pub debug: bool,
    pub dangerously_log_secrets: bool,
    pub implicit: bool,
    pub client_credentials: bool,
    pub scopes: Option<String>,
    pub is_dynamic_client: bool,
}

impl Config {
    /// Parse CLI arguments, merge with environment variables, validate, and return a resolved Config.
    /// Exits the process with an error message on invalid configuration.
    pub fn parse_and_resolve() -> Config {
        let args = CliArgs::parse();

        // Resolve role: CLI > env > error
        let role = args
            .role
            .or_else(|| env::var("AWS_ROLE_ARN").ok())
            .unwrap_or_else(|| {
                eprintln!("Error: --role or AWS_ROLE_ARN is required");
                std::process::exit(1);
            });

        // Resolve openid_url: CLI > env > error
        let mut openid_url = args
            .openid_url
            .or_else(|| env::var("OIDC_DISCOVERY_URL").ok())
            .unwrap_or_else(|| {
                eprintln!("Error: --openid_url or OIDC_DISCOVERY_URL is required");
                std::process::exit(1);
            });

        // Append well-known path if not already present
        if !openid_url.contains(".well-known/openid-configuration") {
            if !openid_url.ends_with('/') {
                openid_url.push('/');
            }
            openid_url.push_str(".well-known/openid-configuration");
        }

        // Resolve client_id: CLI > env
        let client_id = args.client_id.or_else(|| env::var("OIDC_CLIENT_ID").ok());

        let is_dynamic_client = client_id.is_none();

        // Resolve client_secret: CLI > env
        let client_secret = args
            .client_secret
            .or_else(|| env::var("OIDC_CLIENT_SECRET").ok());

        // Resolve region: CLI > env > default
        let region = args
            .region
            .or_else(|| env::var("AWS_REGION").ok())
            .unwrap_or_else(|| "us-east-1".to_string());

        // Resolve duration_seconds: CLI > env > default
        let duration_seconds = args.duration_seconds.unwrap_or_else(|| {
            env::var("DURATION_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(3600)
        });

        // Resolve profile_to_update: CLI > env > default
        let profile_to_update = args
            .profile_to_update
            .or_else(|| env::var("PROFILE_TO_UPDATE").ok())
            .unwrap_or_else(|| "entraws".to_string());

        // Resolve aws_config_file: CLI > env > default
        let aws_config_file_str = args
            .aws_config_file
            .or_else(|| env::var("AWS_CONFIG_FILE").ok())
            .unwrap_or_else(|| "~/.aws/credentials".to_string());

        let aws_config_file = if aws_config_file_str.starts_with('~') {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(aws_config_file_str.replacen('~', &home, 1))
        } else {
            PathBuf::from(&aws_config_file_str)
        };

        let dangerously_log_secrets = args.dangerously_log_secrets;
        // --dangerously-log-secrets implies --debug so tracing is at DEBUG level.
        let debug = args.debug || dangerously_log_secrets;
        let implicit = args.implicit;
        let client_credentials = args.client_credentials;
        let scopes = args.scopes;

        // Validation: --implicit and --client_credentials are mutually exclusive
        if implicit && client_credentials {
            eprintln!("Error: --implicit and --client_credentials cannot be used together");
            std::process::exit(1);
        }

        // Validation: client_credentials requires client_secret
        if client_credentials && client_secret.is_none() {
            eprintln!("Error: --client_credentials requires --client_secret or OIDC_CLIENT_SECRET");
            std::process::exit(1);
        }

        // Validation: client_credentials requires client_id
        if client_credentials && client_id.is_none() {
            eprintln!("Error: --client_credentials requires --client_id or OIDC_CLIENT_ID");
            std::process::exit(1);
        }

        Config {
            role,
            openid_url,
            client_id,
            client_secret,
            region,
            duration_seconds,
            profile_to_update,
            aws_config_file,
            debug,
            dangerously_log_secrets,
            implicit,
            client_credentials,
            scopes,
            is_dynamic_client,
        }
    }
}
