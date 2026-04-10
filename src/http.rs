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
