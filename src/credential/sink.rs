//! Trait defining where [`CacheEntry`](super::CacheEntry) values are
//! persisted on write. Implementations live in sibling modules:
//!
//! * [`super::file::FileSink`] — writes `~/.aws/credentials`.
//! * [`super::keychain::KeychainSink`] (macOS) — writes the login keychain.
//!
//! The trait is deliberately minimal: `store` is the only required method.
//! Introspection methods like [`CredentialSink::name`] exist for log
//! messages and the post-login "how to configure credential_process" hint.

use crate::credential::CacheEntry;
use crate::error::Result;

// The trait is wired up in Phase 2 when `main` starts dispatching through
// it; Phase 1 ships the type so sinks can be implemented and unit-tested in
// isolation without touching `main.rs` yet.
#[allow(dead_code)]
/// Persist a credential set to a backend.
pub trait CredentialSink {
    /// Short, stable identifier used in user-facing messages
    /// (e.g. `"file"`, `"keychain"`).
    fn name(&self) -> &'static str;

    /// Store `entry` in the backend. Implementations are expected to
    /// overwrite any previous entry with the same `entry.cache_key` so
    /// refreshes do not accumulate.
    fn store(&self, entry: &CacheEntry) -> Result<()>;
}
