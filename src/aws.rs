use aws_config::BehaviorVersion;
use aws_sdk_sts::config::Region;
use aws_types::app_name::AppName;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

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
/// (falling back to `sub`) for the RoleSessionName.
pub async fn assume_role_with_token(
    region: &str,
    role_arn: &str,
    token: &str,
    duration_seconds: i32,
    log_secrets: bool,
) -> Result<StsCredentials, String> {
    // Decode JWT without signature verification to extract claims.
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.insecure_disable_signature_validation();

    let token_data = jsonwebtoken::decode::<HashMap<String, serde_json::Value>>(
        token,
        &DecodingKey::from_secret(b""),
        &validation,
    )
    .map_err(|e| format!("Failed to decode JWT: {}", e))?;

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

    // Use email claim if present, otherwise fall back to sub.
    let role_session_name = claims
        .get("email")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("sub").and_then(|v| v.as_str()))
        .ok_or_else(|| "JWT contains neither 'email' nor 'sub' claim".to_string())?
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
            let mut msg = format!("{}", e);
            let mut source: Option<&dyn std::error::Error> = e.source();
            while let Some(s) = source {
                msg.push_str(": ");
                msg.push_str(&format!("{}", s));
                source = s.source();
            }
            format!("Failed to assume role with web identity: {}", msg)
        })?;

    let credentials = response
        .credentials()
        .ok_or_else(|| "No credentials in STS response".to_string())?;

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
) -> Result<(), String> {
    let path = Path::new(config_file);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;
    }

    // Load existing INI if present, otherwise start with an empty one.
    let mut ini = if path.exists() {
        ini::Ini::load_from_file(path)
            .map_err(|e| format!("Failed to parse {}: {}", config_file, e))?
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
        .map_err(|e| format!("Failed to serialize credentials file: {}", e))?;

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
            .map_err(|e| format!("Failed to open {}: {}", config_file, e))?;
        file.write_all(&content)
            .map_err(|e| format!("Failed to write credentials to {}: {}", config_file, e))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, &content)
            .map_err(|e| format!("Failed to write credentials to {}: {}", config_file, e))?;
    }

    println!(
        "Successfully wrote credentials to profile {} in {}",
        profile, config_file
    );

    Ok(())
}
