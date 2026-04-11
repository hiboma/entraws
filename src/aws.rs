use aws_config::BehaviorVersion;
use aws_sdk_sts::config::Region;
use aws_types::app_name::AppName;
use jsonwebtoken::dangerous::insecure_decode;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

use crate::error::{Error, Result};

/// Temporary AWS credentials obtained from STS AssumeRoleWithWebIdentity.
pub struct StsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

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

    Ok(StsCredentials {
        access_key_id: credentials.access_key_id().to_string(),
        secret_access_key: credentials.secret_access_key().to_string(),
        session_token: credentials.session_token().to_string(),
    })
}

/// Write temporary AWS credentials to the specified config file under the
/// given profile name. Reads any existing INI file, updates only the target
/// profile's three credential keys, and writes the file back so other
/// profiles are preserved.
pub fn write_credentials(
    credentials: &StsCredentials,
    config_file: &str,
    profile: &str,
) -> Result<()> {
    let path = Path::new(config_file);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| Error::WriteCredentials {
            path: PathBuf::from(parent),
            source,
        })?;
    }

    // Load existing INI if present, otherwise start with an empty one.
    let mut ini = if path.exists() {
        ini::Ini::load_from_file(path).map_err(|source| Error::ParseCredentialsIni {
            path: PathBuf::from(path),
            source,
        })?
    } else {
        ini::Ini::new()
    };

    ini.with_section(Some(profile))
        .set("aws_access_key_id", &credentials.access_key_id)
        .set("aws_secret_access_key", &credentials.secret_access_key)
        .set("aws_session_token", &credentials.session_token);

    // Serialize to a string so we can control file permissions on Unix.
    let mut content: Vec<u8> = Vec::new();
    ini.write_to(&mut content)
        .map_err(Error::SerializeCredentials)?;

    // Refuse to follow symbolic links when writing credentials. This is a
    // lightweight TOCTOU-style hardening: an attacker (or a misplaced symlink)
    // could otherwise cause credentials to be written through a link to an
    // unexpected destination. We reject the write rather than try to "fix" it
    // so the operator can inspect and correct the path explicitly.
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(Error::SymlinkRejected(PathBuf::from(path)));
        }
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| Error::WriteCredentials {
                path: PathBuf::from(path),
                source,
            })?;
        file.write_all(&content)
            .map_err(|source| Error::WriteCredentials {
                path: PathBuf::from(path),
                source,
            })?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, &content).map_err(|source| Error::WriteCredentials {
            path: PathBuf::from(path),
            source,
        })?;
    }

    info!("Credentials written");
    debug!("Credentials written to profile {profile} in {config_file}");

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for [`write_credentials`]. All file operations use
    //! [`tempfile::TempDir`] to keep the host's `~/.aws/credentials`
    //! untouched even if the test binary is run with a real HOME.
    use super::*;
    use tempfile::TempDir;

    fn make_credentials() -> StsCredentials {
        StsCredentials {
            access_key_id: "AKIA_TEST".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: "token".to_string(),
        }
    }

    #[test]
    fn write_credentials_creates_new_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");
        let path_str = path.to_str().unwrap();

        write_credentials(&make_credentials(), path_str, "entraws").expect("should write");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[entraws]"));
        assert!(
            content.contains("aws_access_key_id=AKIA_TEST")
                || content.contains("aws_access_key_id = AKIA_TEST")
        );
        assert!(content.contains("secret"));
        assert!(content.contains("token"));
    }

    #[test]
    fn write_credentials_preserves_other_profiles() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");
        std::fs::write(
            &path,
            "[other]\naws_access_key_id=EXISTING\naws_secret_access_key=other-secret\n",
        )
        .unwrap();

        write_credentials(&make_credentials(), path.to_str().unwrap(), "entraws")
            .expect("should write");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[other]"));
        assert!(content.contains("EXISTING"));
        assert!(content.contains("other-secret"));
        assert!(content.contains("[entraws]"));
        assert!(content.contains("AKIA_TEST"));
    }

    #[test]
    fn write_credentials_overwrites_existing_profile() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");
        std::fs::write(
            &path,
            "[entraws]\naws_access_key_id=OLD_KEY\naws_secret_access_key=old-secret\naws_session_token=old-token\n",
        )
        .unwrap();

        write_credentials(&make_credentials(), path.to_str().unwrap(), "entraws")
            .expect("should write");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[entraws]"));
        assert!(content.contains("AKIA_TEST"));
        assert!(
            !content.contains("OLD_KEY"),
            "old access key should have been replaced, got:\n{content}"
        );
        assert!(
            !content.contains("old-secret"),
            "old secret should have been replaced, got:\n{content}"
        );
    }

    #[test]
    fn write_credentials_creates_parent_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested").join("dir").join("credentials");

        write_credentials(&make_credentials(), nested.to_str().unwrap(), "entraws")
            .expect("should create parent directories");

        assert!(nested.exists(), "credentials file should exist after write");
    }

    #[cfg(unix)]
    #[test]
    fn write_credentials_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");

        write_credentials(&make_credentials(), path.to_str().unwrap(), "entraws").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn write_credentials_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        // The target must be parseable as an INI file because
        // write_credentials loads it before the symlink check. Use an
        // empty file so the INI parser accepts it.
        std::fs::write(&target, "").unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();

        let err = write_credentials(&make_credentials(), link.to_str().unwrap(), "entraws")
            .expect_err("should reject symlink");
        match err {
            Error::SymlinkRejected(p) => {
                assert_eq!(p, link);
            }
            other => panic!("expected SymlinkRejected, got {other:?}"),
        }
    }
}
