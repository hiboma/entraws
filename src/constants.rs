/// User agent string sent with all outbound HTTP requests.
pub const USER_AGENT: &str = concat!("entraws/", env!("CARGO_PKG_VERSION"));

/// Default HTTP request timeout used for OIDC discovery and token exchange.
pub const HTTP_TIMEOUT_SECS: u64 = 5;

/// Timeout for client credentials grant HTTP requests (slightly longer than
/// interactive flows because machine-to-machine flows may traverse slower
/// networks or involve larger payloads).
pub const CLIENT_CREDENTIALS_TIMEOUT_SECS: u64 = 10;

/// Local HTTP server port used to receive the OIDC callback.
/// 6432 spells "OIDC" on a phone keypad.
pub const CALLBACK_PORT: u16 = 6432;

/// The redirect URI that must match the one registered in the OIDC provider.
pub const REDIRECT_URI: &str = "http://127.0.0.1:6432/callback";
