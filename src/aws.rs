use aws_config::BehaviorVersion;
use aws_sdk_sts::config::Region;
use aws_types::app_name::AppName;
use chrono::{DateTime, TimeZone, Utc};
use jsonwebtoken::dangerous::insecure_decode;
use std::collections::HashMap;

use crate::credential::{Secret, StsCredentials};
use crate::error::{Error, Result};

/// Call STS AssumeRoleWithWebIdentity using the given OIDC token and return
/// temporary credentials.
///
/// The JWT is decoded without signature verification to extract `email`
/// (falling back to `sub`) for the RoleSessionName. The `iss` claim is
/// validated defensively against `expected_issuer` (full string match, as
/// required by the OIDC specification) before the STS call is made. AWS STS
/// still performs the authoritative signature and issuer validation when it
/// receives the token.
pub async fn assume_role_with_token(
    region: &str,
    role_arn: &str,
    token: &str,
    duration_seconds: i32,
    log_secrets: bool,
    expected_issuer: &str,
) -> Result<StsCredentials> {
    // Decode the JWT without any signature or claim validation. STS performs
    // the authoritative verification server-side; we only need the claims to
    // extract `email`/`sub` for RoleSessionName and `iss` for our defensive
    // issuer check. `?` converts `jsonwebtoken::errors::Error` into
    // `Error::JwtDecode` via the `#[from]` impl.
    let token_data = insecure_decode::<HashMap<String, serde_json::Value>>(token)?;

    let claims = token_data.claims;

    // Log identifying JWT claims only when the operator opted in via
    // --dangerously-log-secrets. These values can identify the user and the
    // IdP tenant, so they must not appear in logs by default.
    if log_secrets {
        tracing::debug!(
            "JWT claims (dangerously-log-secrets): iss={:?}, aud={:?}, sub={:?}, ver={:?}",
            claims.get("iss"),
            claims.get("aud"),
            claims.get("sub"),
            claims.get("ver"),
        );
    }

    // Defensive issuer check. AWS STS performs the authoritative signature
    // and issuer validation; this local check is a belt-and-suspenders
    // defense that catches tokens from an unexpected issuer before the STS
    // call is made. OIDC requires an exact string match on `iss`.
    let actual_iss = claims.get("iss").and_then(|v| v.as_str());
    match actual_iss {
        Some(iss) if iss == expected_issuer => {
            // Matches: continue.
        }
        Some(iss) => {
            return Err(Error::IssuerMismatch {
                expected: expected_issuer.to_string(),
                actual: iss.to_string(),
            });
        }
        None => {
            return Err(Error::MissingIssuer);
        }
    }

    // Use email claim if present, otherwise fall back to sub.
    let role_session_name = claims
        .get("email")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("sub").and_then(|v| v.as_str()))
        .ok_or(Error::NoRoleSessionName)?
        .to_string();

    // Build the AWS SDK config with region and user-agent.
    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .app_name(AppName::new("StsOIDCDriver").expect("valid app name"))
        .load()
        .await;

    let sts_client = aws_sdk_sts::Client::new(&sdk_config);

    let response = sts_client
        .assume_role_with_web_identity()
        .role_arn(role_arn)
        .role_session_name(&role_session_name)
        .web_identity_token(token)
        .duration_seconds(duration_seconds)
        .send()
        .await
        .map_err(|e| {
            // Unwrap the full error chain so the root cause (STS error code + message)
            // is visible instead of AWS SDK's top-level Display which shows "service error".
            use std::error::Error as _;
            let mut msg = format!("{e}");
            let mut source: Option<&dyn std::error::Error> = e.source();
            while let Some(s) = source {
                msg.push_str(": ");
                msg.push_str(&format!("{s}"));
                source = s.source();
            }
            Error::Sts(msg)
        })?;

    let credentials = response.credentials().ok_or(Error::NoStsCredentials)?;

    // STS returns expiration as a `DateTime` in its own type. Convert it to
    // a chrono `DateTime<Utc>` so the rest of the crate can reason about
    // expiry uniformly. The conversion is via epoch seconds because
    // `aws_sdk_sts::primitives::DateTime` does not directly implement
    // `Into<chrono::DateTime>`.
    let expiration = sts_datetime_to_chrono(credentials.expiration())?;

    Ok(StsCredentials {
        access_key_id: credentials.access_key_id().to_string(),
        secret_access_key: Secret::new(credentials.secret_access_key().to_string()),
        session_token: Secret::new(credentials.session_token().to_string()),
        expiration,
    })
}

/// Convert AWS SDK's `DateTime` into a `chrono::DateTime<Utc>`.
fn sts_datetime_to_chrono(dt: &aws_sdk_sts::primitives::DateTime) -> Result<DateTime<Utc>> {
    let secs = dt.secs();
    let nanos = dt.subsec_nanos();
    match Utc.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(t) => Ok(t),
        _ => Err(Error::Sts(format!(
            "STS returned an out-of-range expiration: secs={secs}, nanos={nanos}"
        ))),
    }
}

/// Persist STS credentials through the sink selected in [`crate::config::Config`].
///
/// Writes happen twice for every successful login:
///
/// 1. The user-facing sink (Keychain or `~/.aws/credentials`). This is
///    the store the operator can inspect and manage.
/// 2. The per-process [`CacheStore`] at `~/.entraws/cache/`. This is the
///    hot-path read cache used by `entraws credentials` under
///    `credential_process`.
///
/// Before storing, the expiration is moved earlier by [`PRE_EXPIRE_MARGIN`]
/// so the AWS SDK starts refreshing before the true STS expiry. Without
/// the margin, a long-running signed request can see its credentials
/// expire mid-retry (aws-sdk-java-v2 #3408).
pub fn persist_credentials(
    config: &crate::config::Config,
    credentials: &StsCredentials,
) -> Result<()> {
    use crate::config::Backend;
    use crate::credential::cache::CacheStore;
    use crate::credential::file::FileSink;
    use crate::credential::sink::CredentialSink;
    use crate::credential::{cache_key, CacheEntry, PRE_EXPIRE_MARGIN};

    // Shorten the expiration so SDK pre-refresh fires on a clean margin.
    // We clone the credentials to avoid mutating the caller's copy.
    let client_id_for_key = config.client_id.as_deref().unwrap_or("");
    let key = cache_key(&config.role, &config.openid_url, client_id_for_key);

    let mut adjusted = StsCredentials {
        access_key_id: credentials.access_key_id.clone(),
        secret_access_key: credentials.secret_access_key.clone(),
        session_token: credentials.session_token.clone(),
        expiration: credentials.expiration - PRE_EXPIRE_MARGIN,
    };
    // If STS returned an unusually short window (<= margin), clamp to
    // the raw expiration so we never advertise a past timestamp.
    if adjusted.expiration <= Utc::now() {
        adjusted.expiration = credentials.expiration;
    }

    let entry = CacheEntry::new(adjusted, config.role.clone(), key.clone());

    let sink: Box<dyn CredentialSink> = match config.sink {
        Backend::File => Box::new(FileSink::new(
            config.aws_config_file.clone(),
            config.profile_to_update.clone(),
        )),
        #[cfg(target_os = "macos")]
        Backend::Keychain => Box::new(crate::credential::keychain::KeychainSink::new()),
    };

    sink.store(&entry)?;

    // Write to the per-process cache. Failures here are non-fatal for
    // login: the user can still re-run `entraws credentials` which will
    // populate the cache from the primary sink.
    let cache = CacheStore::new(CacheStore::default_root());
    if let Err(e) = cache.store(&key, &entry) {
        tracing::warn!("failed to update credential cache: {e}");
    }

    // Report the outcome on stderr. Intentionally does **not** include
    // the cache-key: the key is a deterministic function of
    // role/openid-url/client-id and is also visible as a filename under
    // `~/.entraws/cache/`, so echoing it on every login would only pad
    // logs. Operators who need the key can regenerate it with
    // `entraws cache-key ...`.
    if !config.quiet {
        eprintln!(
            "stored credentials to {} (profile={})",
            sink.name(),
            config.profile_to_update
        );
    }

    // Optional: write the matching credential_process stanza to
    // ~/.aws/config so the operator does not have to hand-edit it.
    // Failures here do not roll back the sink write — the credentials
    // are still usable via `entraws credentials --cache-key ...` even
    // if ~/.aws/config could not be updated.
    if config.configure_profile {
        maybe_configure_aws_config(config, &key, sink.name())?;
    }

    Ok(())
}

/// Thin wrapper around [`crate::credential::aws_config::configure_profile`]
/// that builds the request payload from a resolved [`Config`] and
/// reports the outcome on stderr so the operator can tell at a glance
/// whether anything changed.
fn maybe_configure_aws_config(
    config: &crate::config::Config,
    cache_key: &str,
    sink_name: &str,
) -> Result<()> {
    use crate::credential::aws_config::{configure_profile, ConfigureOutcome, ConfigureRequest};

    let bin = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "entraws".to_string());

    let req = ConfigureRequest {
        path: &config.aws_config_config_file,
        profile: &config.profile_to_update,
        cache_key,
        source: sink_name,
        region: &config.region,
        binary_path: &bin,
        force: config.force,
        dry_run: config.dry_run,
    };

    let outcome = configure_profile(&req)?;

    if !config.quiet {
        match outcome {
            ConfigureOutcome::Added => eprintln!(
                "wrote [profile {}] to {}",
                config.profile_to_update,
                config.aws_config_config_file.display()
            ),
            ConfigureOutcome::Updated => eprintln!(
                "updated [profile {}] in {}",
                config.profile_to_update,
                config.aws_config_config_file.display()
            ),
            ConfigureOutcome::NoOp => {
                eprintln!("[profile {}] already up-to-date", config.profile_to_update)
            }
            ConfigureOutcome::DryRun => eprintln!(
                "--dry-run: {} would be updated (see diff above)",
                config.aws_config_config_file.display()
            ),
        }
    }

    Ok(())
}

/// Print temporary AWS credentials to stdout as POSIX `export` statements so
/// they can be consumed by `eval "$(entraws ... --export)"`. Values are wrapped
/// in single quotes with embedded single quotes escaped as `'\''`, which is
/// the canonical way to quote an arbitrary string in a POSIX shell.
pub fn print_credentials_as_exports(credentials: &StsCredentials) {
    println!(
        "export AWS_ACCESS_KEY_ID='{}'",
        shell_single_quote(&credentials.access_key_id)
    );
    println!(
        "export AWS_SECRET_ACCESS_KEY='{}'",
        shell_single_quote(credentials.secret_access_key.expose())
    );
    println!(
        "export AWS_SESSION_TOKEN='{}'",
        shell_single_quote(credentials.session_token.expose())
    );
}

/// Escape embedded single quotes for a POSIX single-quoted string. Each `'`
/// inside `s` is replaced with `'\''`, which closes the current quoted span,
/// emits a literal quote, and re-opens the span.
fn shell_single_quote(s: &str) -> String {
    s.replace('\'', r"'\''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_single_quote_preserves_ordinary_strings() {
        assert_eq!(shell_single_quote("AKIA_TEST"), "AKIA_TEST");
        assert_eq!(
            shell_single_quote("abc+/=XYZ"),
            "abc+/=XYZ",
            "base64 characters that are special in double quotes must pass through unchanged"
        );
    }

    #[test]
    fn shell_single_quote_escapes_embedded_single_quotes() {
        // A single embedded quote becomes '\'' — closing the span,
        // a literal quote, and re-opening the span.
        assert_eq!(shell_single_quote("a'b"), r"a'\''b");
        assert_eq!(shell_single_quote("'"), r"'\''");
        assert_eq!(shell_single_quote("a'b'c"), r"a'\''b'\''c");
    }

    #[test]
    fn shell_single_quote_handles_edge_cases() {
        assert_eq!(shell_single_quote(""), "");
        // Two adjacent quotes become two consecutive escape sequences.
        assert_eq!(shell_single_quote("''"), r"'\'''\''");
        // Shell metacharacters are inert inside single quotes, so they
        // must pass through unchanged.
        assert_eq!(shell_single_quote("$`\\!*?"), "$`\\!*?");
    }
}
