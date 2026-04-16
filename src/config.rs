use clap::{Parser, Subcommand};
use std::env;
use std::path::PathBuf;

/// Subcommands. When `None`, the top-level flags run the legacy "login"
/// flow (PKCE/implicit/client-credentials), preserving backwards
/// compatibility with scripts that called `entraws` without a subcommand.
/// When `Some(Command::Credentials { .. })`, the binary behaves as an AWS
/// `credential_process` helper and never opens a browser.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Emit cached credentials as AWS credential_process JSON on stdout.
    ///
    /// This subcommand is invoked by the AWS CLI/SDK as
    /// `credential_process`. It never starts an interactive browser flow
    /// because `credential_process` subprocesses have a ~1 minute timeout
    /// and no TTY. When the cache is empty or stale, the subcommand
    /// prints a hint to stderr and exits non-zero so the operator can
    /// rerun `entraws login`.
    Credentials {
        /// Cache key printed by `entraws login`. Stable across invocations
        /// as long as role/openid-url/client-id are unchanged.
        #[arg(long = "cache-key")]
        cache_key: String,

        /// Source backend to fall back to when the per-process cache is
        /// empty. `file` reads `~/.aws/credentials`; `keychain` (macOS)
        /// reads the login keychain. The default depends on the platform.
        #[arg(long = "source", value_enum, default_value_t = default_source())]
        source: Backend,

        /// Minimum remaining TTL, in seconds, before credentials are
        /// treated as stale. Defaults to 300s (five minutes) which is
        /// both the AWS SDK refresh-ahead convention and the
        /// `PRE_EXPIRE_MARGIN` baked into stored entries.
        #[arg(long = "min-ttl-seconds", default_value_t = 300)]
        min_ttl_seconds: u64,

        /// Profile name inside `~/.aws/credentials` to read when
        /// `--source file`. Ignored for other sources.
        #[arg(short = 'p', long = "profile-to-update")]
        profile_to_update: Option<String>,

        /// Override the credentials-file path (`--source file` only).
        #[arg(long = "aws-config-file")]
        aws_config_file: Option<String>,
    },

    /// Show the remaining TTL and source for a cached credential set.
    ///
    /// This never touches the primary sink (so it will not trigger a
    /// keychain prompt); it reads only the per-process cache under
    /// `~/.entraws/cache/`.
    Status {
        /// Cache key (hex, 64 chars). Usually obtained from
        /// `entraws cache-key ...`.
        #[arg(long = "cache-key")]
        cache_key: String,
    },

    /// Print the cache-key for a given role/IdP/client triple on
    /// stdout. The key is a deterministic SHA-256 of the three inputs,
    /// so running this is a cheap way to regenerate the value you
    /// would paste into `~/.aws/config` without re-logging in.
    CacheKey {
        /// AWS Role ARN (matches `--role` on the login flow).
        #[arg(long = "role")]
        role: String,

        /// OIDC discovery URL (matches `--openid-url` on the login flow).
        /// The `.well-known/openid-configuration` suffix is appended if
        /// missing so the key matches `entraws login`'s resolution.
        #[arg(long = "openid-url")]
        openid_url: String,

        /// OIDC client ID (matches `--client-id` on the login flow).
        /// Pass an empty string for dynamic-client flows.
        #[arg(long = "client-id", default_value = "")]
        client_id: String,
    },
}

/// Backend selector shared by `--sink` (login) and `--source` (credentials).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
    File,
    #[cfg(target_os = "macos")]
    Keychain,
}

impl Backend {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::File => "file",
            #[cfg(target_os = "macos")]
            Backend::Keychain => "keychain",
        }
    }
}

fn default_source() -> Backend {
    #[cfg(target_os = "macos")]
    {
        Backend::Keychain
    }
    #[cfg(not(target_os = "macos"))]
    {
        Backend::File
    }
}

/// AWS STS OIDC Driver - Get temporary AWS credentials via OpenID Connect
#[derive(Parser, Debug)]
#[command(name = "entraws")]
#[command(about = "Get temporary AWS credentials via OpenID Connect")]
pub struct CliArgs {
    /// Optional subcommand. When omitted the binary runs the legacy
    /// login flow using the top-level flags.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// AWS Role ARN to assume (env: AWS_ROLE_ARN)
    #[arg(long = "role")]
    pub role: Option<String>,

    /// OpenID Connect discovery URL (env: OIDC_DISCOVERY_URL)
    #[arg(long = "openid-url", alias = "openid_url")]
    pub openid_url: Option<String>,

    /// OIDC Client ID (env: OIDC_CLIENT_ID). If absent, dynamic client registration is used.
    #[arg(long = "client-id", alias = "client_id")]
    pub client_id: Option<String>,

    /// OIDC Client Secret (env: OIDC_CLIENT_SECRET)
    #[arg(long = "client-secret", alias = "client_secret")]
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

    /// Suppress informational messages (set log level to warn)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Log secret-bearing values (JWT claims such as iss/aud/sub/ver).
    /// Dangerous: use only when diagnosing authentication issues in a private
    /// environment, and never in shared logs. Implies --debug.
    #[arg(long = "dangerously-log-secrets")]
    pub dangerously_log_secrets: bool,

    /// Use implicit flow instead of authorization code flow
    #[arg(long = "implicit")]
    pub implicit: bool,

    /// Use client_credentials grant instead of browser-based flow
    #[arg(long = "client-credentials", alias = "client_credentials")]
    pub client_credentials: bool,

    /// Custom scopes to request
    #[arg(long = "scopes")]
    pub scopes: Option<String>,

    /// Print credentials as shell export statements to stdout instead of
    /// writing them to the AWS credentials file. Intended for use with
    /// `eval "$(entraws ... --export)"`. Implies --quiet unless --debug is set.
    #[arg(long = "export")]
    pub export: bool,

    /// Where to persist credentials after a successful login. `file` writes
    /// `~/.aws/credentials`; `keychain` (macOS) writes the login keychain.
    /// Defaults to `keychain` on macOS and `file` elsewhere. Ignored when
    /// `--export` is set.
    #[arg(long = "sink", value_enum)]
    pub sink: Option<Backend>,

    /// Also write a `credential_process` stanza for this profile into
    /// `~/.aws/config`. Safe by default: refuses to overwrite a
    /// hand-authored section; pass `--force` to replace it anyway.
    /// Useful after a fresh login so the AWS CLI can pick up the new
    /// cache-key without manual editing.
    #[arg(long = "configure-profile")]
    pub configure_profile: bool,

    /// When used with `--configure-profile`, print the proposed change
    /// to stderr and exit without touching `~/.aws/config`.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// When used with `--configure-profile`, overwrite an existing
    /// profile section even if it was not previously managed by
    /// entraws. No-op without `--configure-profile`.
    #[arg(long = "force")]
    pub force: bool,

    /// Override the `~/.aws/config` path that `--configure-profile`
    /// writes to. Primarily for tests and unusual layouts; defaults to
    /// `~/.aws/config`.
    #[arg(long = "aws-config-config-file")]
    pub aws_config_config_file: Option<String>,
}

/// Resolved configuration with all values finalized from CLI args and environment variables.
#[derive(Debug)]
pub struct Config {
    pub role: String,
    pub openid_url: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub region: String,
    pub duration_seconds: i32,
    pub profile_to_update: String,
    pub aws_config_file: PathBuf,
    pub debug: bool,
    pub quiet: bool,
    pub dangerously_log_secrets: bool,
    pub implicit: bool,
    pub client_credentials: bool,
    pub scopes: Option<String>,
    pub is_dynamic_client: bool,
    pub export: bool,
    pub sink: Backend,
    pub configure_profile: bool,
    pub dry_run: bool,
    pub force: bool,
    pub aws_config_config_file: PathBuf,
}

/// Parse CLI arguments once and return either a resolved [`Config`] for
/// the login flow or the [`Command::Credentials`] payload so `main` can
/// dispatch accordingly. Keeping the parser call in one place means
/// `--help` and argument validation behave identically regardless of
/// which path executes.
#[allow(dead_code)]
pub enum Invocation {
    Login(Config),
    Credentials(CredentialsArgs),
    Status(StatusArgs),
    CacheKey(CacheKeyArgs),
}

/// Resolved arguments for the `status` subcommand.
#[allow(dead_code)]
#[derive(Debug)]
pub struct StatusArgs {
    pub cache_key: String,
}

/// Resolved arguments for the `cache-key` subcommand.
#[allow(dead_code)]
#[derive(Debug)]
pub struct CacheKeyArgs {
    pub role: String,
    pub openid_url: String,
    pub client_id: String,
}

/// Resolved arguments for the `credentials` subcommand.
#[allow(dead_code)]
#[derive(Debug)]
pub struct CredentialsArgs {
    pub cache_key: String,
    pub source: Backend,
    pub min_ttl_seconds: u64,
    pub profile_to_update: String,
    pub aws_config_file: PathBuf,
}

#[allow(dead_code)]
pub fn parse_invocation() -> Invocation {
    let args = CliArgs::parse();
    match args.command {
        Some(Command::Credentials {
            cache_key,
            source,
            min_ttl_seconds,
            profile_to_update,
            aws_config_file,
        }) => {
            let profile = profile_to_update
                .or_else(|| env::var("PROFILE_TO_UPDATE").ok())
                .unwrap_or_else(|| "entraws".to_string());
            let file = aws_config_file
                .or_else(|| env::var("AWS_CONFIG_FILE").ok())
                .unwrap_or_else(|| "~/.aws/credentials".to_string());
            let aws_config_file = expand_home(&file);

            Invocation::Credentials(CredentialsArgs {
                cache_key,
                source,
                min_ttl_seconds,
                profile_to_update: profile,
                aws_config_file,
            })
        }
        Some(Command::Status { cache_key }) => Invocation::Status(StatusArgs { cache_key }),
        Some(Command::CacheKey {
            role,
            openid_url,
            client_id,
        }) => {
            // Apply the same well-known-suffix normalisation that
            // `resolve_login` does, so the key this subcommand prints
            // matches what `entraws login` would compute for the same
            // arguments.
            let openid_url = normalize_openid_url(openid_url);
            Invocation::CacheKey(CacheKeyArgs {
                role,
                openid_url,
                client_id,
            })
        }
        None => Invocation::Login(Config::resolve_login(args)),
    }
}

/// Append `.well-known/openid-configuration` to an OIDC URL that does
/// not already include it. Extracted so both the login flow and the
/// `cache-key` subcommand produce matching keys for identical inputs.
fn normalize_openid_url(mut url: String) -> String {
    if !url.contains(".well-known/openid-configuration") {
        if !url.ends_with('/') {
            url.push('/');
        }
        url.push_str(".well-known/openid-configuration");
    }
    url
}

fn expand_home(path_str: &str) -> PathBuf {
    if let Some(rest) = path_str.strip_prefix('~') {
        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(format!("{home}{rest}"))
    } else {
        PathBuf::from(path_str)
    }
}

impl Config {
    /// Parse CLI arguments, merge with environment variables, validate, and return a resolved Config.
    /// Exits the process with an error message on invalid configuration.
    ///
    /// Legacy entry point kept for binaries and tests that predate the
    /// subcommand split; `main` now uses [`parse_invocation`] instead.
    #[allow(dead_code)]
    pub fn parse_and_resolve() -> Config {
        let args = CliArgs::parse();
        if args.command.is_some() {
            eprintln!("Error: parse_and_resolve() cannot be used with a subcommand");
            std::process::exit(1);
        }
        Self::resolve_login(args)
    }

    fn resolve_login(args: CliArgs) -> Config {
        // Resolve role: CLI > env > error
        let role = args
            .role
            .or_else(|| env::var("AWS_ROLE_ARN").ok())
            .unwrap_or_else(|| {
                eprintln!("Error: --role or AWS_ROLE_ARN is required");
                std::process::exit(1);
            });

        // Resolve openid_url: CLI > env > error
        let openid_url = args
            .openid_url
            .or_else(|| env::var("OIDC_DISCOVERY_URL").ok())
            .unwrap_or_else(|| {
                eprintln!("Error: --openid-url or OIDC_DISCOVERY_URL is required");
                std::process::exit(1);
            });
        let openid_url = normalize_openid_url(openid_url);

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

        // Resolve duration_seconds: CLI > env > default.
        //
        // The STS SDK expects `i32`, so we convert the `u32` CLI value
        // (clap stores unsigned) using `i32::try_from`, falling back to
        // the 3600-second default if the value is out of range. STS
        // itself only accepts 900..=43200, so the overflow branch is
        // unreachable in practice, but we still handle it safely.
        let duration_seconds: i32 = args
            .duration_seconds
            .and_then(|v| i32::try_from(v).ok())
            .or_else(|| {
                env::var("DURATION_SECONDS")
                    .ok()
                    .and_then(|v| v.parse::<i32>().ok())
            })
            .unwrap_or(3600);

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

        let aws_config_config_file = {
            let raw = args
                .aws_config_config_file
                .unwrap_or_else(|| "~/.aws/config".to_string());
            expand_home(&raw)
        };

        let aws_config_file = if aws_config_file_str.starts_with('~') {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(aws_config_file_str.replacen('~', &home, 1))
        } else {
            PathBuf::from(&aws_config_file_str)
        };

        let dangerously_log_secrets = args.dangerously_log_secrets;
        // --dangerously-log-secrets implies --debug so tracing is at DEBUG level.
        let debug = args.debug || dangerously_log_secrets;
        let export = args.export;
        // --quiet is overridden by --debug / --dangerously-log-secrets, and
        // implied by --export so informational logs do not pollute the stdout
        // export statements that the shell will evaluate.
        let quiet = (args.quiet || export) && !debug;
        let implicit = args.implicit;
        let client_credentials = args.client_credentials;
        let scopes = args.scopes;

        // Validation: --implicit and --client-credentials are mutually exclusive
        if implicit && client_credentials {
            eprintln!("Error: --implicit and --client-credentials cannot be used together");
            std::process::exit(1);
        }

        // Validation: client-credentials requires client-secret
        if client_credentials && client_secret.is_none() {
            eprintln!("Error: --client-credentials requires --client-secret or OIDC_CLIENT_SECRET");
            std::process::exit(1);
        }

        // Validation: client-credentials requires client-id
        if client_credentials && client_id.is_none() {
            eprintln!("Error: --client-credentials requires --client-id or OIDC_CLIENT_ID");
            std::process::exit(1);
        }

        // Validation: --configure-profile is meaningful only when we
        // actually persist credentials. Combining it with --export
        // would write a credential_process stanza pointing at a
        // non-existent cache, which is confusing.
        if args.configure_profile && args.export {
            eprintln!(
                "Error: --configure-profile cannot be used with --export (nothing is persisted)"
            );
            std::process::exit(1);
        }

        // Validation: --dry-run and --force only affect the
        // --configure-profile path. Reject stand-alone use so users
        // do not assume they have broader semantics.
        if (args.dry_run || args.force) && !args.configure_profile {
            eprintln!("Error: --dry-run and --force require --configure-profile");
            std::process::exit(1);
        }

        let sink = args.sink.unwrap_or_else(default_source);

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
            quiet,
            dangerously_log_secrets,
            implicit,
            client_credentials,
            scopes,
            is_dynamic_client,
            export,
            sink,
            configure_profile: args.configure_profile,
            dry_run: args.dry_run,
            force: args.force,
            aws_config_config_file,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests for [`CliArgs`] parsing. These do not exercise
    //! [`Config::parse_and_resolve`] because that function reads process
    //! environment variables and calls `std::process::exit(1)` on error,
    //! neither of which is compatible with an in-process test harness.
    //! Covering the raw clap surface is enough to catch argument renames
    //! and alias regressions.
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_accepts_kebab_case_long_options() {
        let args = CliArgs::try_parse_from([
            "entraws",
            "--role",
            "arn:aws:iam::123456789012:role/test",
            "--openid-url",
            "https://idp.example.com/",
            "--client-id",
            "my-client",
        ])
        .expect("parse should succeed");
        assert_eq!(
            args.role.as_deref(),
            Some("arn:aws:iam::123456789012:role/test")
        );
        assert_eq!(args.openid_url.as_deref(), Some("https://idp.example.com/"));
        assert_eq!(args.client_id.as_deref(), Some("my-client"));
    }

    #[test]
    fn cli_accepts_snake_case_aliases_for_backward_compatibility() {
        // The original Python CLI used snake_case flags; the Rust port
        // advertises kebab-case but keeps snake_case as aliases so existing
        // shell scripts and CI jobs continue to work.
        let args = CliArgs::try_parse_from([
            "entraws",
            "--role",
            "arn:aws:iam::123456789012:role/test",
            "--openid_url",
            "https://idp.example.com/",
            "--client_id",
            "my-client",
            "--client_secret",
            "s3cr3t",
        ])
        .expect("parse should succeed");
        assert_eq!(args.openid_url.as_deref(), Some("https://idp.example.com/"));
        assert_eq!(args.client_id.as_deref(), Some("my-client"));
        assert_eq!(args.client_secret.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn cli_defaults_are_none_or_false() {
        let args = CliArgs::try_parse_from(["entraws"]).expect("parse should succeed");
        assert!(args.role.is_none());
        assert!(args.openid_url.is_none());
        assert!(args.client_id.is_none());
        assert!(args.client_secret.is_none());
        assert!(args.region.is_none());
        assert!(args.duration_seconds.is_none());
        assert!(args.profile_to_update.is_none());
        assert!(args.aws_config_file.is_none());
        assert!(!args.debug);
        assert!(!args.quiet);
        assert!(!args.dangerously_log_secrets);
        assert!(!args.implicit);
        assert!(!args.client_credentials);
        assert!(args.scopes.is_none());
    }

    #[test]
    fn cli_accepts_boolean_flags() {
        let args = CliArgs::try_parse_from([
            "entraws",
            "--debug",
            "--dangerously-log-secrets",
            "--implicit",
        ])
        .expect("parse should succeed");
        assert!(args.debug);
        assert!(args.dangerously_log_secrets);
        assert!(args.implicit);
    }

    #[test]
    fn cli_accepts_short_profile_flag() {
        let args =
            CliArgs::try_parse_from(["entraws", "-p", "my-profile"]).expect("parse should succeed");
        assert_eq!(args.profile_to_update.as_deref(), Some("my-profile"));
    }

    #[test]
    fn cli_accepts_quiet_flag() {
        let args = CliArgs::try_parse_from(["entraws", "--quiet"]).expect("parse should succeed");
        assert!(args.quiet);
    }

    #[test]
    fn cli_accepts_short_quiet_flag() {
        let args = CliArgs::try_parse_from(["entraws", "-q"]).expect("parse should succeed");
        assert!(args.quiet);
    }

    #[test]
    fn cli_rejects_unknown_flag() {
        let result = CliArgs::try_parse_from(["entraws", "--not-a-real-flag"]);
        assert!(result.is_err(), "unknown flag should fail to parse");
    }

    #[test]
    fn cli_accepts_export_flag() {
        let args = CliArgs::try_parse_from(["entraws", "--export"]).expect("parse should succeed");
        assert!(args.export);
    }

    #[test]
    fn cli_export_defaults_to_false() {
        let args = CliArgs::try_parse_from(["entraws"]).expect("parse should succeed");
        assert!(!args.export);
    }
}
