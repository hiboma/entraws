# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project summary

`entraws` is a Rust CLI that launches an OpenID Connect (OIDC) flow against an IdP such as Microsoft Entra ID, Okta, Auth0, or Google, exchanges the resulting ID token for temporary AWS credentials via `sts:AssumeRoleWithWebIdentity`, and writes them into an INI profile in `~/.aws/credentials`. It is a Rust port of [awslabs/StsOidcDriver](https://github.com/awslabs/StsOidcDriver).

## Common commands

```sh
cargo build                                                # debug build
cargo build --release --locked                             # release build (CI uses this)
cargo test --all-targets --all-features                    # full test suite, matches CI
cargo test <name>                                          # run a single test by substring match
cargo test -p entraws <module>::tests::<name> -- --exact   # run exactly one test
cargo clippy --all-targets --all-features -- -D warnings   # matches CI — warnings are errors
cargo fmt --all -- --check                                 # matches CI
cargo deny check                                           # advisories / licenses / sources
cargo run -- --role <arn> --openid-url <url> --client-id <id>   # run locally
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy (deny-warnings), and tests on both `ubuntu-latest` and `macos-latest`, plus a release build with `--locked`. Reproduce failures with the four commands above before pushing.

Tests hit real TCP sockets via `wiremock::MockServer` and real temp files via `tempfile::TempDir`, but never reach the network or touch `~/.aws/credentials`. There is no separate integration-test crate — unit tests and `wiremock`-backed tests both live in `#[cfg(test)] mod tests { ... }` / `mod integration_tests { ... }` inside each source file.

## Architecture

The crate is a single binary (`src/main.rs`) composed of narrow modules that each own one concern. `main` is the **only** place in the crate that calls `std::process::exit` on runtime failures — every other module returns `Result<T, crate::error::Error>` and lets `main` decide how to surface it. `config.rs` also exits, but deliberately, because clap-style CLI validation is expected to print-and-exit.

### Flow selection

`config::Config::parse_and_resolve` merges CLI args (kebab-case, with snake_case aliases for backward compatibility) with environment variables, validates mutually exclusive flags, and produces a resolved `Config`. From there `main` dispatches to one of three flows:

1. **Authorization code + PKCE** (default): generate PKCE params, bind an `axum` server on `127.0.0.1:6432`, open the browser, redirect the user to the IdP, receive the code on `/callback`, exchange it at the token endpoint, call STS, write credentials.
2. **Implicit flow** (`--implicit`): same server, but the callback HTML posts the `id_token` directly (no code exchange).
3. **Client credentials grant** (`--client-credentials`): no browser and no local server. Tries `client_secret_basic` first and falls back to `client_secret_post` automatically.

All three flows converge on `aws::assume_role_with_token` → `aws::write_credentials`.

### Local callback server (`src/server.rs`)

- `AppState` is shared across handlers via `Arc`. It holds `Config`, `OidcConfig`, `PkceParams`, a `OnceLock<String>` for the dynamically-registered client id, and a `tokio::sync::Notify` used for graceful shutdown.
- `bind_server` binds the `TcpListener` and builds the `Router` **before** `main` opens the browser, which eliminates the race where the browser would hit a socket that is not yet listening.
- `main` wraps `serve` in a `tokio::select!` against a 2-minute wall-clock timeout — the server will shut down from either a successful token exchange, an authenticated error, or the timeout.
- `process_token` re-validates the PKCE `state` parameter server-side with `subtle::ConstantTimeEq` even though the callback HTML already validates it in JS, because an attacker could POST directly to `/process_token` and bypass the client-side check. **Do not remove this check.**
- `status_for_error` centralizes the `Error → HTTP status` mapping. Errors that indicate an unrecoverable STS/JWT failure also signal shutdown, while `InvalidState`, token-exchange, and filesystem errors leave the server running so the user can retry.
- The front-end HTML lives in `templates/callback.html` and is embedded via `include_str!`; `{{placeholders}}` are substituted at request time.

### Credential file handling (`src/aws.rs`)

- `write_credentials` loads the existing `~/.aws/credentials` as an INI file, **updates only the target profile's three credential keys**, and writes the file back. Other profiles must be preserved — the tests in `aws::tests` lock this behavior in.
- On Unix, the file is opened with `mode(0o600)`.
- A `symlink_metadata` check refuses to write through a symbolic link (returns `Error::SymlinkRejected`). This is lightweight TOCTOU-style hardening; keep it.
- The JWT is decoded with `jsonwebtoken::dangerous::insecure_decode` **only** to extract `email`/`sub` for `RoleSessionName` and to cross-check `iss` against the discovery document's issuer. **AWS STS performs the authoritative signature and issuer validation**, so entraws deliberately does not verify JWT signatures locally — do not add local JWT signature verification without a concrete reason, and update `README.md` § "JWT signature validation" if the stance changes.

### Error type (`src/error.rs`)

One crate-level `Error` enum (thiserror) collapses every fallible subsystem so `main` can print a single error chain and exit. Note the comment block at the top of `error.rs`: `#[from]` can only be declared once per source type, so context-carrying variants like `OidcDiscovery`/`ReadCredentials` coexist with generic `Http`/`Io` variants. Call sites that need URL/path context use explicit `map_err`; everything else uses `?`.

Some variants (`ReadCredentials`, `Config`) are currently `#[allow(dead_code)]`. The comments mark them as reserved for planned features — do not delete them without also removing the documented plan.

### Shared HTTP client (`src/http.rs`)

All outbound HTTP (OIDC discovery, dynamic client registration, token exchange, client credentials) must go through `http::shared_client()`. It returns a `OnceLock`-backed `reqwest::Client` with the `entraws/<version>` `User-Agent` preset and a shared connection pool. Per-request timeouts are applied via `.timeout(...)` on the builder; `constants::HTTP_TIMEOUT_SECS` (5s) is the default, and `CLIENT_CREDENTIALS_TIMEOUT_SECS` (10s) is used for machine-to-machine flows.

### Secret logging

`--dangerously-log-secrets` logs identifying JWT claims (`iss`/`aud`/`sub`/`ver`) at DEBUG level and implies `--debug`. The long name is intentional. The guard in `aws::assume_role_with_token` is the only place that should ever log claim values — do not add further claim logging elsewhere, and never enable this flag by default.

## Conventions to preserve

- **CLI option naming**: canonical form is kebab-case (`--openid-url`, `--client-id`). Snake_case aliases (`--openid_url`, `--client_id`, ...) are kept as hidden aliases for backward compatibility with the original Python driver's CLI. `config::tests::cli_accepts_snake_case_aliases_for_backward_compatibility` locks this in — if you rename an option, also add a matching `alias = "..."` and extend that test.
- **Callback port**: `constants::CALLBACK_PORT = 6432` and `REDIRECT_URI = "http://127.0.0.1:6432/callback"` must stay in sync, and must match whatever is registered in the IdP. The comment notes 6432 spells "OIDC" on a phone keypad.
- **Okta scope handling**: `server::resolve_scopes` special-cases hostnames containing `okta.com` to append `offline_access`. This is a documented workaround for Okta's native-client requirements — do not "clean it up" without testing against Okta.
- **Dependency policy**: `deny.toml` allow-lists only permissive SPDX licenses and restricts crate sources to crates.io. New dependencies must be compatible with that policy; `cargo deny check` runs in CI via `.github/workflows/deny.yml`.
