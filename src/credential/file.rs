//! File-backed credential sink targeting `~/.aws/credentials`.
//!
//! This is the original entraws behaviour, extracted verbatim from the
//! former `aws::write_credentials` function and wrapped behind the
//! [`CredentialSink`] trait. The safety properties that existed before —
//! preserving unrelated profiles, refusing to follow symlinks, 0o600 on
//! Unix — are retained unchanged.
//!
//! `Expiration` is deliberately **not** written to `~/.aws/credentials`.
//! The AWS CLI does not read an expiration hint from the credentials file;
//! expiry tracking lives in the CacheStore instead.

use std::fs;
use std::path::{Path, PathBuf};

use tracing::{debug, info};

use crate::credential::sink::CredentialSink;
use crate::credential::source::CredentialSource;
use crate::credential::{CacheEntry, Secret, StsCredentials};
use crate::error::{Error, Result};

/// Sink that writes credentials into an AWS shared-credentials INI file.
///
/// The sink is configured with the target `path` and a `profile` name; each
/// `store` call replaces the three credential keys under that profile and
/// leaves all other profiles untouched.
#[allow(dead_code)]
pub struct FileSink {
    path: PathBuf,
    profile: String,
}

#[allow(dead_code)]
impl FileSink {
    pub fn new<P: Into<PathBuf>>(path: P, profile: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            profile: profile.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl CredentialSink for FileSink {
    fn name(&self) -> &'static str {
        "file"
    }

    fn store(&self, entry: &CacheEntry) -> Result<()> {
        write_ini_credentials(&entry.creds, &self.path, &self.profile)
    }
}

/// Source that reads the three credential keys from an AWS
/// shared-credentials INI file. Used by the `credentials` subcommand when
/// `--source file` is selected.
///
/// Expiration is not stored in the INI file, so the source returns
/// `DateTime<Utc>::MIN_UTC` for the expiration field. The caller is
/// expected to consult the CacheStore for freshness information when the
/// FileSource is used as a fallback; using FileSource alone means the
/// credentials never appear fresh enough to satisfy a TTL check.
#[allow(dead_code)]
pub struct FileSource {
    path: PathBuf,
    profile: String,
}

#[allow(dead_code)]
impl FileSource {
    pub fn new<P: Into<PathBuf>>(path: P, profile: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            profile: profile.into(),
        }
    }
}

impl CredentialSource for FileSource {
    fn name(&self) -> &'static str {
        "file"
    }

    fn load(&self, _cache_key: &str) -> Result<Option<CacheEntry>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let ini =
            ini::Ini::load_from_file(&self.path).map_err(|source| Error::ParseCredentialsIni {
                path: self.path.clone(),
                source,
            })?;

        let section = match ini.section(Some(self.profile.as_str())) {
            Some(s) => s,
            None => return Ok(None),
        };

        let access_key_id = match section.get("aws_access_key_id") {
            Some(v) => v.to_string(),
            None => return Ok(None),
        };
        let secret_access_key = match section.get("aws_secret_access_key") {
            Some(v) => v.to_string(),
            None => return Ok(None),
        };
        let session_token = section
            .get("aws_session_token")
            .unwrap_or_default()
            .to_string();

        let creds = StsCredentials {
            access_key_id,
            secret_access_key: Secret::new(secret_access_key),
            session_token: Secret::new(session_token),
            expiration: chrono::DateTime::<chrono::Utc>::MIN_UTC,
        };

        Ok(Some(CacheEntry {
            version: CacheEntry::CURRENT_VERSION,
            creds,
            role_arn: String::new(),
            cache_key: String::new(),
            obtained_at: chrono::Utc::now(),
        }))
    }
}

/// Write `credentials` into the INI file at `path` under `[profile]`,
/// preserving all other profiles.
///
/// This is intentionally a free function so both the [`FileSink`]
/// implementation and the existing `aws::write_credentials` compatibility
/// shim in [`crate::aws`] can share a single implementation.
pub(crate) fn write_ini_credentials(
    credentials: &StsCredentials,
    path: &Path,
    profile: &str,
) -> Result<()> {
    // Refuse to follow symbolic links when writing credentials. This is
    // a lightweight TOCTOU-style hardening: an attacker (or a misplaced
    // symlink) could otherwise cause credentials to be written through
    // a link to an unexpected destination, or the load-existing step
    // below could be coerced into parsing attacker-controlled content.
    // Reject before touching the file so the operator can inspect and
    // correct the path explicitly.
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(Error::SymlinkRejected(PathBuf::from(path)));
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| Error::WriteCredentials {
            path: PathBuf::from(parent),
            source,
        })?;
    }

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
        .set(
            "aws_secret_access_key",
            credentials.secret_access_key.expose(),
        )
        .set("aws_session_token", credentials.session_token.expose());

    let mut content: Vec<u8> = Vec::new();
    ini.write_to(&mut content)
        .map_err(Error::SerializeCredentials)?;

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
    debug!(
        "Credentials written to profile {profile} in {}",
        path.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    fn make_entry() -> CacheEntry {
        CacheEntry::new(
            StsCredentials {
                access_key_id: "AKIA_TEST".to_string(),
                secret_access_key: Secret::new("secret".to_string()),
                session_token: Secret::new("token".to_string()),
                expiration: Utc::now() + chrono::Duration::hours(1),
            },
            "arn:aws:iam::1:role/x".to_string(),
            "cache-key".to_string(),
        )
    }

    #[test]
    fn file_sink_creates_new_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");
        let sink = FileSink::new(&path, "entraws");

        sink.store(&make_entry()).expect("should write");

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
    fn file_sink_preserves_other_profiles() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");
        std::fs::write(
            &path,
            "[other]\naws_access_key_id=EXISTING\naws_secret_access_key=other-secret\n",
        )
        .unwrap();

        FileSink::new(&path, "entraws")
            .store(&make_entry())
            .expect("should write");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[other]"));
        assert!(content.contains("EXISTING"));
        assert!(content.contains("other-secret"));
        assert!(content.contains("[entraws]"));
        assert!(content.contains("AKIA_TEST"));
    }

    #[test]
    fn file_sink_overwrites_existing_profile() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");
        std::fs::write(
            &path,
            "[entraws]\naws_access_key_id=OLD_KEY\naws_secret_access_key=old-secret\naws_session_token=old-token\n",
        )
        .unwrap();

        FileSink::new(&path, "entraws")
            .store(&make_entry())
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
    fn file_sink_creates_parent_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("nested").join("dir").join("credentials");

        FileSink::new(&nested, "entraws")
            .store(&make_entry())
            .expect("should create parent directories");

        assert!(nested.exists(), "credentials file should exist after write");
    }

    #[cfg(unix)]
    #[test]
    fn file_sink_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");

        FileSink::new(&path, "entraws")
            .store(&make_entry())
            .unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn file_sink_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        // The target must be parseable as an INI file because the sink
        // loads it before the symlink check. Use an empty file so the INI
        // parser accepts it.
        std::fs::write(&target, "").unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();

        let err = FileSink::new(&link, "entraws")
            .store(&make_entry())
            .expect_err("should reject symlink");
        match err {
            Error::SymlinkRejected(p) => assert_eq!(p, link),
            other => panic!("expected SymlinkRejected, got {other:?}"),
        }
    }

    #[test]
    fn file_source_roundtrips_credentials() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");
        FileSink::new(&path, "entraws")
            .store(&make_entry())
            .unwrap();

        let source = FileSource::new(&path, "entraws");
        let loaded = source.load("cache-key").unwrap().expect("should find");
        assert_eq!(loaded.creds.access_key_id, "AKIA_TEST");
        assert_eq!(loaded.creds.secret_access_key.expose(), "secret");
        assert_eq!(loaded.creds.session_token.expose(), "token");
    }

    #[test]
    fn file_source_returns_none_for_missing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("no-such-file");
        let source = FileSource::new(&path, "entraws");
        assert!(source.load("cache-key").unwrap().is_none());
    }

    #[test]
    fn file_source_returns_none_for_missing_profile() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("credentials");
        std::fs::write(
            &path,
            "[other]\naws_access_key_id=X\naws_secret_access_key=Y\n",
        )
        .unwrap();
        let source = FileSource::new(&path, "entraws");
        assert!(source.load("cache-key").unwrap().is_none());
    }
}
