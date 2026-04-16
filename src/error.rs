//! Error types for entraws.
//!
//! The crate-level [`Error`] enum collapses every fallible subsystem into a
//! single type so `main` can print one message and exit. Variants that benefit
//! from contextual information (URLs, file paths, ...) carry their own source
//! field and are produced by hand with `map_err`; simple pass-through errors
//! use `#[from]` so the ergonomic `?` operator works.
//!
//! # Design note
//!
//! `#[from]` can only be declared once per source type, so context-carrying
//! variants like [`Error::OidcDiscovery`] and [`Error::ReadCredentials`]
//! coexist with generic [`Error::Http`] / [`Error::Io`] variants. Call sites
//! that need the context use explicit `map_err`, while everything else is
//! handled via automatic conversion.

use std::path::PathBuf;

/// Top-level error type for the entire crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("OIDC discovery failed for {url}: {source}")]
    OidcDiscovery {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Failed to parse OIDC discovery document from {url}: {source}")]
    OidcDiscoveryParse {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Dynamic client registration failed: {0}")]
    DynamicRegistration(String),

    #[error("Token endpoint request failed: {0}")]
    TokenRequest(String),

    #[error("Token endpoint returned no id_token")]
    MissingIdToken,

    #[error("JWT decode failed: {0}")]
    JwtDecode(#[from] jsonwebtoken::errors::Error),

    #[error("ID token has no 'iss' claim")]
    MissingIssuer,

    #[error("ID token issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    #[error("JWT contains neither 'email' nor 'sub' claim to use as RoleSessionName")]
    NoRoleSessionName,

    #[error("AWS STS AssumeRoleWithWebIdentity failed: {0}")]
    Sts(String),

    #[error("STS returned a response with no credentials")]
    NoStsCredentials,

    #[error("Invalid state parameter")]
    InvalidState,

    // Reserved for future `read_credentials` support (e.g. merging profiles)
    // that is planned but not yet wired up; the variant is kept here so the
    // public error surface is stable once the feature lands.
    #[allow(dead_code)]
    #[error("Failed to read AWS credentials file {}: {source}", path.display())]
    ReadCredentials {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to write AWS credentials file {}: {source}", path.display())]
    WriteCredentials {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "Refusing to write credentials through a symbolic link: {}. \
         Remove the symlink or specify a different --aws-config-file.",
        .0.display()
    )]
    SymlinkRejected(PathBuf),

    #[error("Failed to parse AWS credentials file {}: {source}", path.display())]
    ParseCredentialsIni {
        path: PathBuf,
        #[source]
        source: ini::Error,
    },

    #[error("Failed to serialize AWS credentials file: {0}")]
    SerializeCredentials(#[source] std::io::Error),

    // Reserved for configuration errors surfaced from `config.rs` once that
    // module stops exiting directly. `parse_and_resolve` intentionally still
    // calls `exit(1)` (the clap convention for CLI arg validation), so this
    // variant is unused for now.
    #[allow(dead_code)]
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to access credential cache at {}: {source}", path.display())]
    CacheIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Credential cache at {} is corrupt: {source}", path.display())]
    CacheCorrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    // Reserved for future typed-error dispatch in the `credentials`
    // subcommand; the current implementation surfaces these conditions
    // via exit code + stderr hint instead of returning an `Error`.
    #[allow(dead_code)]
    #[error("No cached credentials found for cache-key {cache_key}. Run `entraws login` first.")]
    CacheMiss { cache_key: String },

    #[allow(dead_code)]
    #[error("Cached credentials expired for cache-key {cache_key}. Run `entraws login` again.")]
    CacheExpired { cache_key: String },

    #[error(
        "AWS config at {} already has a [profile {profile}] section that was not created by entraws. \
         Pass --force to overwrite, or remove the section manually.",
        path.display()
    )]
    ProfileExists { profile: String, path: PathBuf },
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
