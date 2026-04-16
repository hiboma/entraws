//! Credential storage abstractions.
//!
//! This module centralises the data types and traits used to persist AWS
//! credentials obtained from STS AssumeRoleWithWebIdentity. Two concerns are
//! deliberately kept separate:
//!
//! * [`Secret`] — a newtype wrapper that redacts the wrapped value from
//!   `Debug` / `Display` output. Credentials travelling through this crate
//!   are wrapped in [`Secret`] so a stray `{:?}` or `println!` cannot leak
//!   them to stderr, which the AWS CLI captures for `credential_process`
//!   subprocesses.
//! * [`StsCredentials`] / [`CacheEntry`] — the plain data shape returned by
//!   STS and the cacheable, backend-agnostic form that sinks and sources
//!   exchange.
//!
//! The [`CredentialSink`] and [`CredentialSource`] traits (see sibling
//! modules) let `main` dispatch to different backends (`~/.aws/credentials`,
//! macOS Keychain, …) without the business logic in `aws.rs` and
//! `server.rs` caring which backend is selected.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod cache;
pub mod file;
#[cfg(target_os = "macos")]
pub mod keychain;
pub mod sink;
pub mod source;

/// Newtype that redacts the wrapped value from `Debug` and `Display`.
///
/// Access the underlying value with [`Secret::expose`]. The name is long and
/// unpleasant on purpose so that call sites which genuinely need the raw
/// string stand out during review.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Return a reference to the underlying secret. Use sparingly and only
    /// when the value must cross a trust boundary (STS API, keychain,
    /// credential_process stdout).
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the underlying secret.
    #[allow(dead_code)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<T> std::fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

/// Temporary AWS credentials as returned by STS AssumeRoleWithWebIdentity.
///
/// `expiration` is the absolute time at which AWS considers the credentials
/// invalid. Consumers that write an `Expiration` field to the AWS
/// `credential_process` JSON should subtract a safety margin (see
/// [`PRE_EXPIRE_MARGIN`]) before emitting so that in-flight SDK retries do
/// not hit the exact expiry instant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StsCredentials {
    pub access_key_id: String,
    pub secret_access_key: Secret<String>,
    pub session_token: Secret<String>,
    pub expiration: DateTime<Utc>,
}

/// Cacheable, backend-agnostic representation of a credential set.
///
/// A [`CacheEntry`] is what both [`CredentialSink`](sink::CredentialSink)
/// implementations persist and what
/// [`CredentialSource`](source::CredentialSource) implementations load. The
/// `version` field allows forward-compatible on-disk schema changes without
/// breaking older binaries that are still installed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub version: u8,
    pub creds: StsCredentials,
    pub role_arn: String,
    pub cache_key: String,
    pub obtained_at: DateTime<Utc>,
}

#[allow(dead_code)]
impl CacheEntry {
    pub const CURRENT_VERSION: u8 = 1;

    pub fn new(creds: StsCredentials, role_arn: String, cache_key: String) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            creds,
            role_arn,
            cache_key,
            obtained_at: Utc::now(),
        }
    }

    /// Return true when the credentials have `min_ttl` or more remaining
    /// before their `expiration`. A [`CacheEntry`] whose remaining lifetime
    /// is under `min_ttl` is treated as a cache miss: the SDK would likely
    /// see the expiry mid-request otherwise.
    pub fn has_sufficient_ttl(&self, now: DateTime<Utc>, min_ttl: chrono::Duration) -> bool {
        self.creds.expiration.signed_duration_since(now) >= min_ttl
    }
}

/// Safety margin applied when credentials are stored. STS returns a
/// hard expiry time, but AWS SDKs can retry a single request across several
/// seconds; to avoid those retries straddling the real expiry instant we
/// shift the recorded expiration five minutes earlier. Reads apply the same
/// margin as the minimum remaining TTL so the buffer is symmetric.
#[allow(dead_code)]
pub const PRE_EXPIRE_MARGIN: chrono::Duration = chrono::Duration::minutes(5);

/// Compute a stable cache key for a given role / IdP / client triple.
///
/// The key is the hex-encoded SHA-256 of `role_arn || 0x00 || openid_url ||
/// 0x00 || client_id`. The NUL separators prevent (role = "a", openid =
/// "bc…") colliding with (role = "ab", openid = "c…"). Profile names are
/// deliberately not part of the key so the same role can back multiple
/// profiles without triggering redundant STS calls.
/// Emit `entry` on `writer` as the JSON shape AWS SDKs expect from a
/// `credential_process` helper. The `Version` is always `1` per the AWS
/// contract; `Expiration` is formatted as RFC 3339 with sub-second
/// precision so SDKs can subtract it from "now" without rounding errors.
///
/// The function writes exactly one JSON object followed by a newline and
/// performs no logging. Secrets cross the trust boundary here and are
/// deliberately emitted in the clear — this is the only sanctioned exit
/// point for raw credentials.
pub fn write_process_credentials<W: std::io::Write>(
    writer: &mut W,
    entry: &CacheEntry,
) -> std::io::Result<()> {
    let payload = serde_json::json!({
        "Version": 1,
        "AccessKeyId": entry.creds.access_key_id,
        "SecretAccessKey": entry.creds.secret_access_key.expose(),
        "SessionToken": entry.creds.session_token.expose(),
        "Expiration": entry.creds.expiration.to_rfc3339_opts(
            chrono::SecondsFormat::Secs,
            true,
        ),
    });
    serde_json::to_writer(&mut *writer, &payload)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[allow(dead_code)]
pub fn cache_key(role_arn: &str, openid_url: &str, client_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(role_arn.as_bytes());
    hasher.update([0u8]);
    hasher.update(openid_url.as_bytes());
    hasher.update([0u8]);
    hasher.update(client_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("AKIA_REAL_KEY".to_string());
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains("AKIA_REAL_KEY"),
            "Secret<T> leaked via Debug: {dbg}"
        );
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn secret_display_is_redacted() {
        let s = Secret::new("supersecret".to_string());
        let display = format!("{s}");
        assert!(!display.contains("supersecret"));
        assert!(display.contains("redacted"));
    }

    #[test]
    fn secret_exposes_inner_on_demand() {
        let s = Secret::new("value".to_string());
        assert_eq!(s.expose(), "value");
    }

    #[test]
    fn cache_key_is_stable() {
        let a = cache_key("arn:aws:iam::1:role/x", "https://idp", "client-1");
        let b = cache_key("arn:aws:iam::1:role/x", "https://idp", "client-1");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "hex-encoded SHA-256 is 64 chars");
    }

    #[test]
    fn cache_key_differs_on_any_input_change() {
        let base = cache_key("r1", "u1", "c1");
        assert_ne!(base, cache_key("r2", "u1", "c1"));
        assert_ne!(base, cache_key("r1", "u2", "c1"));
        assert_ne!(base, cache_key("r1", "u1", "c2"));
    }

    #[test]
    fn cache_key_is_collision_resistant_across_boundaries() {
        // Without a NUL separator, ("a", "bc", "d") and ("ab", "c", "d")
        // would hash to the same bytes. The NUL between fields breaks that.
        let a = cache_key("a", "bc", "d");
        let b = cache_key("ab", "c", "d");
        assert_ne!(a, b);
    }

    #[test]
    fn write_process_credentials_emits_aws_schema() {
        let creds = StsCredentials {
            access_key_id: "AKIA".into(),
            secret_access_key: Secret::new("secret".into()),
            session_token: Secret::new("token".into()),
            expiration: chrono::DateTime::parse_from_rfc3339("2026-04-16T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let entry = CacheEntry::new(creds, "role".into(), "key".into());
        let mut buf = Vec::new();
        write_process_credentials(&mut buf, &entry).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(parsed["Version"], 1);
        assert_eq!(parsed["AccessKeyId"], "AKIA");
        assert_eq!(parsed["SecretAccessKey"], "secret");
        assert_eq!(parsed["SessionToken"], "token");
        assert_eq!(parsed["Expiration"], "2026-04-16T12:00:00Z");
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn has_sufficient_ttl_respects_margin() {
        let now = Utc::now();
        let creds = StsCredentials {
            access_key_id: "AKIA".into(),
            secret_access_key: Secret::new("s".into()),
            session_token: Secret::new("t".into()),
            expiration: now + chrono::Duration::minutes(10),
        };
        let entry = CacheEntry::new(creds, "role".into(), "key".into());
        assert!(entry.has_sufficient_ttl(now, chrono::Duration::minutes(5)));
        assert!(!entry.has_sufficient_ttl(now, chrono::Duration::minutes(15)));
    }
}
