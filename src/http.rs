use std::sync::OnceLock;

use crate::constants::USER_AGENT;

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Returns a process-wide shared `reqwest::Client` with the entraws
/// User-Agent preset. The underlying HTTP connection pool is shared
/// across all outbound calls (OIDC discovery, token exchange, dynamic
/// client registration, client credentials).
///
/// The client is created lazily on first access and reused afterwards.
/// Callers that need a specific timeout should chain `.timeout(...)`
/// on the per-request builder.
pub fn shared_client() -> reqwest::Client {
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .build()
                .expect("failed to build shared reqwest client")
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: calling [`shared_client`] twice must succeed and must not
    /// panic. We do not assert pointer equality because `reqwest::Client`
    /// clones return a new `Client` wrapper around the same `Arc`-backed
    /// inner state; the important invariant is that the builder panic in
    /// `get_or_init` never triggers in practice.
    #[test]
    fn shared_client_returns_without_panic() {
        let c1 = shared_client();
        let c2 = shared_client();
        // Silence unused-variable warnings while keeping the handles alive
        // so the test exercises the clone path as well.
        let _ = (c1, c2);
    }
}
