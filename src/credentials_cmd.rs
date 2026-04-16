//! Implementation of the `entraws credentials` subcommand — the AWS
//! `credential_process` helper.
//!
//! Invariants this module enforces:
//!
//! * No tracing output is produced. The AWS CLI captures `credential_process`
//!   subprocess stderr, so every log line is a potential credential leak.
//!   We do not initialise a tracing subscriber here, and nothing in this
//!   path is instrumented with `tracing::debug!` / `info!`.
//! * The only thing written to stdout is the AWS-schema JSON payload
//!   (`{"Version": 1, "AccessKeyId": ..., ...}`). Diagnostic text goes to
//!   stderr, never stdout — the SDK parses stdout as JSON.
//! * Browser/OIDC flows are never initiated. On cache miss we print a
//!   hint ("run `entraws login` again") and exit non-zero.
//! * CacheStore is always consulted first, even when `--source` points at
//!   a slower backend (keychain). This is what keeps parallel `aws`
//!   invocations from racing on Keychain ACL prompts.

use std::io::Write;

use chrono::Utc;

use crate::config::{Backend, CredentialsArgs};
use crate::credential::cache::CacheStore;
use crate::credential::file::FileSource;
use crate::credential::source::CredentialSource;
use crate::credential::{write_process_credentials, CacheEntry, PRE_EXPIRE_MARGIN};

/// Non-zero exit code meaning "no usable cached credentials; run
/// `entraws login`". Distinct from the "invalid arguments" exit 2 that
/// clap emits so operators can wire automation around the two cases.
const EXIT_CACHE_MISS: i32 = 2;
/// Generic non-zero exit for I/O / corruption errors.
const EXIT_IO_ERROR: i32 = 3;

/// Top-level entry point: dispatches based on `args.source` and writes
/// the result to `stdout` / `stderr`. Exits the process on failure.
pub fn run(args: CredentialsArgs) -> ! {
    let cache = CacheStore::new(CacheStore::default_root());
    let source: Box<dyn CredentialSource> = match args.source {
        Backend::File => Box::new(FileSource::new(
            args.aws_config_file.clone(),
            args.profile_to_update.clone(),
        )),
        #[cfg(target_os = "macos")]
        Backend::Keychain => Box::new(crate::credential::keychain::KeychainSource::new()),
    };

    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    let code = run_with(
        &cache,
        source.as_ref(),
        &args.cache_key,
        args.min_ttl_seconds,
        &mut stdout,
        &mut stderr,
    );
    std::process::exit(code);
}

/// Pure function for test harnesses. Writes the credential_process JSON
/// to `stdout` on success and a hint to `stderr` on failure, returning
/// the desired process exit code.
pub fn run_with<S: CredentialSource + ?Sized, W: Write, E: Write>(
    cache: &CacheStore,
    source: &S,
    cache_key: &str,
    min_ttl_seconds: u64,
    stdout: &mut W,
    stderr: &mut E,
) -> i32 {
    let min_ttl = chrono::Duration::seconds(min_ttl_seconds as i64);
    let now = Utc::now();

    // 1. Fast path: hit the per-process cache first. This is the hot
    //    path for repeated `aws` invocations in a shell session.
    match cache.load(cache_key) {
        Ok(Some(entry)) if entry.has_sufficient_ttl(now, min_ttl) => {
            return emit(stdout, stderr, &entry);
        }
        Ok(_) => {}
        Err(e) => {
            let _ = writeln!(stderr, "entraws: cache read failed: {e}");
            return EXIT_IO_ERROR;
        }
    }

    // 2. Slow path: load from the configured source and refresh the cache.
    //    We serialise the refresh on a per-key flock so parallel
    //    invocations cannot all hit the source simultaneously.
    let _guard = match cache.lock_exclusive(cache_key) {
        Ok(g) => g,
        Err(e) => {
            let _ = writeln!(stderr, "entraws: cache lock failed: {e}");
            return EXIT_IO_ERROR;
        }
    };

    // Re-check the cache under the lock: another process may have just
    // refreshed it while we were waiting for the flock. An I/O error
    // here is still a genuine I/O failure — treat it the same way the
    // first read does so we do not silently paper over permission or
    // corruption problems.
    match cache.load(cache_key) {
        Ok(Some(entry)) if entry.has_sufficient_ttl(now, min_ttl) => {
            return emit(stdout, stderr, &entry);
        }
        Ok(_) => {}
        Err(e) => {
            let _ = writeln!(stderr, "entraws: cache read failed: {e}");
            return EXIT_IO_ERROR;
        }
    }

    match source.load(cache_key) {
        Ok(Some(entry)) if entry.has_sufficient_ttl(now, min_ttl) => {
            // Refresh the cache so the next invocation hits the fast path.
            if let Err(e) = cache.store(cache_key, &entry) {
                let _ = writeln!(stderr, "entraws: cache write failed: {e}");
                // Not fatal — emit credentials anyway.
            }
            emit(stdout, stderr, &entry)
        }
        Ok(Some(_)) | Ok(None) => {
            let _ = writeln!(
                stderr,
                "entraws: no fresh credentials for cache-key {cache_key} (source={}, margin={}s). Run `entraws login` again.",
                source.name(),
                PRE_EXPIRE_MARGIN.num_seconds()
            );
            EXIT_CACHE_MISS
        }
        Err(e) => {
            let _ = writeln!(stderr, "entraws: source read failed: {e}");
            EXIT_IO_ERROR
        }
    }
}

fn emit<W: Write, E: Write>(stdout: &mut W, stderr: &mut E, entry: &CacheEntry) -> i32 {
    match write_process_credentials(stdout, entry) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(stderr, "entraws: stdout write failed: {e}");
            EXIT_IO_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::source::CredentialSource;
    use crate::credential::{Secret, StsCredentials};
    use crate::error::Result;
    use std::cell::RefCell;
    use tempfile::TempDir;

    struct FakeSource {
        entry: RefCell<Option<CacheEntry>>,
    }

    impl FakeSource {
        fn with(entry: Option<CacheEntry>) -> Self {
            Self {
                entry: RefCell::new(entry),
            }
        }
    }

    impl CredentialSource for FakeSource {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn load(&self, _cache_key: &str) -> Result<Option<CacheEntry>> {
            Ok(self.entry.borrow().clone())
        }
    }

    fn fresh_entry() -> CacheEntry {
        CacheEntry::new(
            StsCredentials {
                access_key_id: "AKIA".into(),
                secret_access_key: Secret::new("secret".into()),
                session_token: Secret::new("token".into()),
                expiration: Utc::now() + chrono::Duration::hours(1),
            },
            "arn:aws:iam::1:role/x".into(),
            "key".into(),
        )
    }

    fn expired_entry() -> CacheEntry {
        let mut e = fresh_entry();
        e.creds.expiration = Utc::now() - chrono::Duration::minutes(1);
        e
    }

    #[test]
    fn cache_hit_emits_credentials_and_exits_zero() {
        let dir = TempDir::new().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        cache.store("key", &fresh_entry()).unwrap();
        let source = FakeSource::with(None);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(&cache, &source, "key", 300, &mut stdout, &mut stderr);

        assert_eq!(code, 0);
        let s = String::from_utf8(stdout).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(v["Version"], 1);
        assert_eq!(v["AccessKeyId"], "AKIA");
    }

    #[test]
    fn cache_miss_falls_back_to_source_and_refreshes_cache() {
        let dir = TempDir::new().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        let source = FakeSource::with(Some(fresh_entry()));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(&cache, &source, "key", 300, &mut stdout, &mut stderr);

        assert_eq!(code, 0);
        assert!(cache.load("key").unwrap().is_some(), "cache refreshed");
    }

    #[test]
    fn expired_cache_is_treated_as_miss() {
        let dir = TempDir::new().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        cache.store("key", &expired_entry()).unwrap();
        let source = FakeSource::with(Some(fresh_entry()));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(&cache, &source, "key", 300, &mut stdout, &mut stderr);

        assert_eq!(code, 0);
        // Cache should now contain the fresh entry, not the expired one.
        let loaded = cache.load("key").unwrap().unwrap();
        assert!(loaded.creds.expiration > Utc::now());
    }

    #[test]
    fn total_miss_exits_with_cache_miss_code() {
        let dir = TempDir::new().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        let source = FakeSource::with(None);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(&cache, &source, "key", 300, &mut stdout, &mut stderr);

        assert_eq!(code, EXIT_CACHE_MISS);
        assert!(stdout.is_empty(), "stdout must stay clean on miss");
        let err = String::from_utf8(stderr).unwrap();
        assert!(err.contains("entraws login"), "hint in stderr");
        assert!(
            !err.contains("AKIA") && !err.contains("secret") && !err.contains("token"),
            "stderr must not leak secrets; got: {err}"
        );
    }

    #[test]
    fn expired_source_entry_exits_with_cache_miss_code() {
        let dir = TempDir::new().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        let source = FakeSource::with(Some(expired_entry()));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_with(&cache, &source, "key", 300, &mut stdout, &mut stderr);

        assert_eq!(code, EXIT_CACHE_MISS);
        assert!(stdout.is_empty());
    }

    #[test]
    fn stderr_never_contains_secrets_on_success() {
        let dir = TempDir::new().unwrap();
        let cache = CacheStore::new(dir.path().join("cache"));
        cache.store("key", &fresh_entry()).unwrap();
        let source = FakeSource::with(None);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let _ = run_with(&cache, &source, "key", 300, &mut stdout, &mut stderr);

        let err = String::from_utf8(stderr).unwrap();
        assert!(
            !err.contains("secret") && !err.contains("token"),
            "stderr must never contain secret material; got: {err}"
        );
    }
}
