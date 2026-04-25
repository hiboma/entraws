//! Keychain-backed credential sink / source for macOS.
//!
//! Compiled only on macOS (`#[cfg(target_os = "macos")]`). The
//! implementation delegates to the `keyring` crate with the
//! `apple-native` feature, which wraps the Security framework's generic
//! password APIs.
//!
//! Storage model:
//!
//! * **service** is always the literal `"entraws"`. Users can identify
//!   the credentials in Keychain Access.app by this service name.
//! * **account** is the `cache_key` returned by
//!   [`crate::credential::cache_key`], i.e. the hex-encoded SHA-256 of
//!   `role_arn || openid_url || client_id`. Using the hash instead of a
//!   human-readable profile name lets two profiles share a single
//!   keychain entry when they assume the same role.
//! * **value** is the JSON-serialised [`CacheEntry`], so the keychain
//!   stores everything needed to emit a credential_process payload
//!   (expiration, role ARN, obtained_at timestamp).
//!
//! No ACL is attached to the entry. macOS will prompt the user the first
//! time a given binary reads the item ("entraws wants to use your
//! Keychain") and offer "Always Allow". Re-signing the binary (each
//! Homebrew upgrade, each `cargo build` with a different identity)
//! invalidates that trust, so some prompt frequency is unavoidable; the
//! CacheStore layer minimises how often we round-trip to the keychain
//! to keep the UX acceptable.

use keyring::Entry;

use crate::credential::sink::CredentialSink;
use crate::credential::source::CredentialSource;
use crate::credential::CacheEntry;
use crate::error::{Error, Result};

const SERVICE: &str = "entraws";

/// Build a `keyring::Entry` for `cache_key`, mapping its errors onto our
/// crate-wide [`Error`] type.
fn entry(cache_key: &str) -> Result<Entry> {
    Entry::new(SERVICE, cache_key).map_err(map_keyring_err)
}

fn map_keyring_err(e: keyring::Error) -> Error {
    // The keyring crate's errors are all platform-specific strings;
    // collapse them into our generic `CacheIo` variant so the top-level
    // error chain stays readable. `CacheIo` takes a `std::io::Error`,
    // which is what we use as the common carrier for "some backend said
    // no". Using `std::io::ErrorKind::Other` keeps the chain meaningful
    // without pretending we know the underlying cause.
    Error::CacheIo {
        path: std::path::PathBuf::from(format!("keychain:{SERVICE}")),
        source: std::io::Error::other(format!("{e}")),
    }
}

/// Sink that writes a [`CacheEntry`] into the macOS login keychain.
pub struct KeychainSink;

impl KeychainSink {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KeychainSink {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialSink for KeychainSink {
    fn name(&self) -> &'static str {
        "keychain"
    }

    fn store(&self, entry_data: &CacheEntry) -> Result<()> {
        let kc = entry(&entry_data.cache_key)?;
        let json = serde_json::to_string(entry_data).map_err(|source| Error::CacheCorrupt {
            path: std::path::PathBuf::from(format!("keychain:{SERVICE}")),
            source,
        })?;
        kc.set_password(&json).map_err(map_keyring_err)?;
        Ok(())
    }
}

/// Source that reads a [`CacheEntry`] from the macOS login keychain.
pub struct KeychainSource;

impl KeychainSource {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KeychainSource {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialSource for KeychainSource {
    fn name(&self) -> &'static str {
        "keychain"
    }

    fn load(&self, cache_key: &str) -> Result<Option<CacheEntry>> {
        let kc = entry(cache_key)?;
        let json = match kc.get_password() {
            Ok(v) => v,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(e) => return Err(map_keyring_err(e)),
        };
        let parsed: CacheEntry =
            serde_json::from_str(&json).map_err(|source| Error::CacheCorrupt {
                path: std::path::PathBuf::from(format!("keychain:{SERVICE}")),
                source,
            })?;
        Ok(Some(parsed))
    }
}

#[cfg(test)]
mod tests {
    //! Tests that actually touch the login keychain. Each test uses a
    //! unique cache key under the `entraws-test-` prefix so nothing
    //! collides with real entries and the cleanup is idempotent.

    use super::*;
    use crate::credential::{Secret, StsCredentials};
    use chrono::Utc;

    fn unique_key() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        format!("entraws-test-{pid}-{seq}")
    }

    fn cleanup(key: &str) {
        if let Ok(kc) = entry(key) {
            let _ = kc.delete_credential();
        }
    }

    fn make_entry(key: &str) -> CacheEntry {
        CacheEntry::new(
            StsCredentials {
                access_key_id: "AKIA_TEST".into(),
                secret_access_key: Secret::new("secret".into()),
                session_token: Secret::new("token".into()),
                expiration: Utc::now() + chrono::Duration::hours(1),
            },
            "arn:aws:iam::1:role/x".into(),
            key.into(),
        )
    }

    // These tests actually read and write the login keychain. They are
    // marked `#[ignore]` because the GitHub Actions macOS runner has no
    // unlocked login keychain by default and the first write there
    // triggers a blocking UI prompt. Run them locally with
    // `cargo test -- --ignored credential::keychain::tests --test-threads=1`.

    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            cleanup(&self.0);
        }
    }

    fn scopeguard_cleanup(key: &str) -> Cleanup {
        Cleanup(key.to_string())
    }

    #[test]
    #[ignore]
    fn roundtrip_sink_and_source() {
        let key = unique_key();
        let _cleanup = scopeguard_cleanup(&key);
        let sink = KeychainSink::new();
        let src = KeychainSource::new();

        sink.store(&make_entry(&key)).expect("sink.store");
        let loaded = src.load(&key).expect("src.load").expect("has entry");
        assert_eq!(loaded.creds.access_key_id, "AKIA_TEST");
        assert_eq!(loaded.creds.secret_access_key.expose(), "secret");
        assert_eq!(loaded.creds.session_token.expose(), "token");
    }

    #[test]
    #[ignore]
    fn load_returns_none_for_missing_key() {
        let key = unique_key();
        let src = KeychainSource::new();
        assert!(src.load(&key).unwrap().is_none());
    }

    // Compile-time smoke test: make sure the trait impls and
    // constructors are well-formed. Always runs.
    #[test]
    fn keychain_types_compile() {
        let _sink = KeychainSink::new();
        let _src = KeychainSource::new();
        let _ = (unique_key(), make_entry, cleanup);
    }
}
