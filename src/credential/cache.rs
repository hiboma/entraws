//! Process-wide cache for [`CacheEntry`] values, living under
//! `~/.entraws/cache/` by default.
//!
//! The cache exists because AWS SDKs invoke a `credential_process` helper
//! fresh per operation and share no state across invocations. Without a
//! cache, each `aws` call would round-trip to the underlying sink (and
//! then to STS, and then to a browser prompt) — unusable in practice.
//! This store is the "hot path" read layer: `credentials` subcommands hit
//! the cache first, only falling back to the Keychain / file sinks when
//! the cache is stale or missing.
//!
//! Concurrency model:
//!
//! * A per-cache-key lock file (`<hex>.lock`) under the cache directory
//!   serialises read-modify-write from several `aws` invocations.
//! * Writes use `tempfile::NamedTempFile::persist` for atomic replacement
//!   within the same directory so a crashed writer cannot leave the cache
//!   half-written.
//! * Pre-expire margin ([`PRE_EXPIRE_MARGIN`]) is applied both on write
//!   (the stored `expiration` is already shortened by STS expiry minus
//!   the margin) and on read (callers pass it as `min_ttl` to
//!   [`CacheEntry::has_sufficient_ttl`]).

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::credential::CacheEntry;
use crate::error::{Error, Result};

/// On-disk cache store rooted at `root` (typically
/// `~/.entraws/cache/`). A single [`CacheStore`] instance is reused for
/// all operations within a process.
#[allow(dead_code)]
pub struct CacheStore {
    root: PathBuf,
}

#[allow(dead_code)]
impl CacheStore {
    /// Construct a store rooted at `root`. The directory is created lazily
    /// on first write so merely instantiating a [`CacheStore`] is cheap and
    /// will not fail if `$HOME` is read-only.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Default cache root: `$HOME/.entraws/cache/`. Falls back to the
    /// current working directory if `$HOME` is unset, which keeps the
    /// binary usable in unusual environments (CI containers, `sudo -H`
    /// oddities) at the cost of a less convenient path.
    pub fn default_root() -> PathBuf {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".entraws").join("cache")
    }

    fn entry_path(&self, cache_key: &str) -> PathBuf {
        self.root.join(format!("{cache_key}.json"))
    }

    fn lock_path(&self, cache_key: &str) -> PathBuf {
        self.root.join(format!("{cache_key}.lock"))
    }

    /// Ensure the cache directory (and its `~/.entraws/` parent) exist
    /// with 0o700 permissions on Unix. `DirBuilder::mode` applies the
    /// permission to every directory it creates, which closes the gap
    /// where the intermediate `~/.entraws/` was left with the process
    /// umask. Called by any operation that needs to write to the root.
    fn ensure_root(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.root)
                .map_err(|source| Error::CacheIo {
                    path: self.root.clone(),
                    source,
                })?;
            // DirBuilder's mode is only applied to directories it
            // creates, so an existing root keeps its current
            // permissions. Tighten it explicitly to handle the upgrade
            // case where a previous run left the dir with a laxer mode.
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700)).map_err(
                |source| Error::CacheIo {
                    path: self.root.clone(),
                    source,
                },
            )?;
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(&self.root).map_err(|source| Error::CacheIo {
                path: self.root.clone(),
                source,
            })?;
        }

        Ok(())
    }

    /// Acquire an exclusive file lock for `cache_key`.
    ///
    /// The lock is released when the returned guard is dropped. Holding
    /// the guard during read-modify-write serialises parallel `aws`
    /// invocations: without it, two concurrent `credentials` subprocesses
    /// can both see "cache miss", both call STS, and both overwrite each
    /// other's results.
    pub fn lock_exclusive(&self, cache_key: &str) -> Result<CacheLockGuard> {
        self.ensure_root()?;
        let path = self.lock_path(cache_key);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| Error::CacheIo {
                path: path.clone(),
                source,
            })?;
        // `File::lock` has been stable since Rust 1.89 and is implemented
        // via `flock(2)` on Unix / `LockFileEx` on Windows. We prefer it
        // over `fs2` to avoid the extra dependency; the semantics are the
        // same for our needs (blocking exclusive lock released on drop).
        file.lock().map_err(|source| Error::CacheIo {
            path: path.clone(),
            source,
        })?;
        Ok(CacheLockGuard { file, path })
    }

    /// Load the entry for `cache_key`. Returns `Ok(None)` on cache miss
    /// (file absent). Genuine errors (permission denied, corrupt JSON)
    /// are returned as `Err`.
    pub fn load(&self, cache_key: &str) -> Result<Option<CacheEntry>> {
        let path = self.entry_path(cache_key);
        let mut file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(Error::CacheIo { path, source }),
        };
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .map_err(|source| Error::CacheIo {
                path: path.clone(),
                source,
            })?;
        let entry: CacheEntry =
            serde_json::from_str(&buf).map_err(|source| Error::CacheCorrupt { path, source })?;
        Ok(Some(entry))
    }

    /// Atomically write `entry` to the cache under `cache_key`.
    ///
    /// The entry is written to a temp file in the same directory and then
    /// renamed into place so a crash or concurrent reader never observes
    /// a partial payload. On Unix the file is created with mode 0o600.
    pub fn store(&self, cache_key: &str, entry: &CacheEntry) -> Result<()> {
        self.ensure_root()?;
        let path = self.entry_path(cache_key);
        let json = serde_json::to_vec_pretty(entry).map_err(|source| Error::CacheCorrupt {
            path: path.clone(),
            source,
        })?;

        // Write to a temp file in the same directory (so `rename` is a
        // same-filesystem atomic swap), then move into place.
        let tmp = tempfile::Builder::new()
            .prefix(".")
            .suffix(".tmp")
            .tempfile_in(&self.root)
            .map_err(|source| Error::CacheIo {
                path: self.root.clone(),
                source,
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = fs::Permissions::from_mode(0o600);
            fs::set_permissions(tmp.path(), perm).map_err(|source| Error::CacheIo {
                path: tmp.path().to_path_buf(),
                source,
            })?;
        }

        {
            let mut handle = tmp.as_file();
            handle.write_all(&json).map_err(|source| Error::CacheIo {
                path: tmp.path().to_path_buf(),
                source,
            })?;
            handle.sync_all().map_err(|source| Error::CacheIo {
                path: tmp.path().to_path_buf(),
                source,
            })?;
        }

        tmp.persist(&path).map_err(|e| Error::CacheIo {
            path: path.clone(),
            source: e.error,
        })?;
        Ok(())
    }

    /// Remove the cache entry for `cache_key`, if present. Silently
    /// succeeds when the entry does not exist — this is used by
    /// `entraws logout` paths that should be idempotent.
    pub fn delete(&self, cache_key: &str) -> Result<()> {
        let path = self.entry_path(cache_key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::CacheIo { path, source }),
        }
    }

    /// Root directory for test assertions and log messages.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// RAII guard that releases the flock when dropped.
#[allow(dead_code)]
pub struct CacheLockGuard {
    file: fs::File,
    path: PathBuf,
}

impl CacheLockGuard {
    /// Path of the lock file (primarily useful for error messages).
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CacheLockGuard {
    fn drop(&mut self) {
        // Best-effort unlock; if this fails, the OS will release the lock
        // when the file descriptor is closed (i.e. when this guard is
        // dropped and the `file` field goes out of scope) anyway.
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{Secret, StsCredentials};
    use chrono::Utc;
    use tempfile::TempDir;

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

    #[test]
    fn roundtrip_store_and_load() {
        let dir = TempDir::new().unwrap();
        let store = CacheStore::new(dir.path().join("cache"));
        let entry = make_entry("k1");
        store.store("k1", &entry).unwrap();

        let loaded = store.load("k1").unwrap().expect("cache hit");
        assert_eq!(loaded.creds.access_key_id, "AKIA_TEST");
        assert_eq!(loaded.creds.secret_access_key.expose(), "secret");
        assert_eq!(loaded.cache_key, "k1");
    }

    #[test]
    fn load_returns_none_on_miss() {
        let dir = TempDir::new().unwrap();
        let store = CacheStore::new(dir.path().join("cache"));
        assert!(store.load("missing").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn store_sets_0600_on_entry() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let store = CacheStore::new(dir.path().join("cache"));
        store.store("k1", &make_entry("k1")).unwrap();
        let meta = fs::metadata(store.entry_path("k1")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_root_sets_0700_on_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let store = CacheStore::new(dir.path().join("cache"));
        store.store("k1", &make_entry("k1")).unwrap();
        let meta = fs::metadata(store.root()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = CacheStore::new(dir.path().join("cache"));
        store.delete("nonexistent").unwrap();
        store.store("k1", &make_entry("k1")).unwrap();
        store.delete("k1").unwrap();
        assert!(store.load("k1").unwrap().is_none());
        store.delete("k1").unwrap();
    }

    #[test]
    fn store_is_atomic_against_corrupt_existing_file() {
        // If an earlier run (or an attacker) left garbage under the entry
        // path, `store` must replace it cleanly rather than appending to
        // the corrupt bytes.
        let dir = TempDir::new().unwrap();
        let store = CacheStore::new(dir.path().join("cache"));
        fs::create_dir_all(store.root()).unwrap();
        fs::write(store.entry_path("k1"), b"not json").unwrap();

        store.store("k1", &make_entry("k1")).unwrap();
        let loaded = store.load("k1").unwrap().unwrap();
        assert_eq!(loaded.creds.access_key_id, "AKIA_TEST");
    }

    #[test]
    fn load_returns_err_on_corrupt_json() {
        let dir = TempDir::new().unwrap();
        let store = CacheStore::new(dir.path().join("cache"));
        fs::create_dir_all(store.root()).unwrap();
        fs::write(store.entry_path("k1"), b"{not json").unwrap();
        match store.load("k1") {
            Err(Error::CacheCorrupt { .. }) => {}
            other => panic!("expected CacheCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn lock_exclusive_creates_lockfile() {
        let dir = TempDir::new().unwrap();
        let store = CacheStore::new(dir.path().join("cache"));
        let guard = store.lock_exclusive("k1").unwrap();
        assert!(guard.path().exists());
        drop(guard);
    }
}
