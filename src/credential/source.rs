//! Trait defining where [`CacheEntry`](super::CacheEntry) values are
//! loaded from on read, used by the `credentials` (credential_process)
//! subcommand. Implementations are paired with the corresponding
//! [`CredentialSink`](super::sink::CredentialSink) in the same module.

use crate::credential::CacheEntry;
use crate::error::Result;

// Dispatched in Phase 2 by the new `credentials` subcommand; Phase 1 ships
// the trait so sources can be implemented and tested in isolation.
#[allow(dead_code)]
/// Load a credential set from a backend.
pub trait CredentialSource {
    /// Short, stable identifier used in log / error messages
    /// (e.g. `"file"`, `"keychain"`).
    fn name(&self) -> &'static str;

    /// Load the entry stored under `cache_key`. `Ok(None)` signals a cache
    /// miss; errors are reserved for genuine failures (I/O, permissions,
    /// corrupted data). Callers use `Ok(None)` to fall through to the next
    /// source or to print the "run `entraws login`" hint.
    fn load(&self, cache_key: &str) -> Result<Option<CacheEntry>>;
}
