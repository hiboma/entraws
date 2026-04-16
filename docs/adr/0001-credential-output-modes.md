# 0001. Two credential output modes: credentials file vs. shell exports

- Status: Accepted
- Date: 2026-04-16
- Deciders: @hiboma

## Context

entraws obtains temporary AWS credentials by assuming an IAM role via
`sts:AssumeRoleWithWebIdentity`. The original design wrote the returned
`access_key_id` / `secret_access_key` / `session_token` triple into
`~/.aws/credentials` under a named profile, mirroring the behavior of the
upstream Python driver (`awslabs/StsOidcDriver`).

This single output path is a good fit for long-lived developer machines
where the AWS CLI is already configured to read profiles from the
credentials file. It is a poor fit for other situations:

- **Ephemeral shells**: CI runners, throwaway containers, debugging
  sessions, and `just`/`make` tasks that need credentials only for the
  current process tree. Writing to `~/.aws/credentials` leaves state behind
  that the user must remember to clean up.
- **Non-default credentials file locations**: users who run with a
  non-writable HOME, a read-only filesystem, or a custom
  `AWS_SHARED_CREDENTIALS_FILE` path.
- **Shell composition**: users who want to combine entraws with `eval`,
  `env`, `exec`, or tools like `direnv` that already expect an exporter to
  emit `export` statements on stdout.

Comparable tools solve this with either a flag (`granted` with
`export-all-env-vars` / `-x`) or a subcommand (`saml2aws script`,
`direnv export bash|fish|json`).

## Decision

Add a `--export` flag that switches the output mode from "write the
credentials file" to "print POSIX `export` statements to stdout". Keep
the credentials-file write as the default so existing behavior is not
broken.

Concretely:

- `aws.rs` exposes two sibling functions:
  `write_credentials(credentials, file, profile)` and
  `print_credentials_as_exports(credentials)`.
- Both the browser-based flow (`server::process_token_inner`) and the
  client-credentials flow (`client_credentials::process_client_credentials_response`)
  branch on `config.export` after `assume_role_with_token` succeeds,
  calling exactly one of the two functions. There is no third path.
- `--export` implies `--quiet` unless `--debug` is set, so tracing
  informational output does not contaminate stdout. Tracing already
  writes to stderr (the `tracing_subscriber::fmt()` default), so
  `--export --debug` still produces a stdout stream that `eval` can
  safely consume.
- Values emitted by `print_credentials_as_exports` are wrapped in POSIX
  single quotes. A helper `shell_single_quote` escapes embedded single
  quotes as `'\''` so that arbitrary STS tokens — including those with
  `$`, `` ` ``, `\`, `!`, `*`, `?` — are safe to `eval`.

We rejected two alternatives:

- **An `entraws export` subcommand** in the style of saml2aws or direnv.
  entraws currently has no subcommand surface; introducing one would
  require restructuring the clap parser and promoting every existing
  top-level flag into a subcommand, which is disproportionate for this
  feature. An `--export` flag is additive and compatible.
- **Double-quoted values** (`"..."`). Double quotes are not inert in
  POSIX shells — `$`, `` ` ``, and `\` retain their special meaning. STS
  session tokens routinely contain `$` and other shell metacharacters, so
  double quoting would be latently unsafe.

## Consequences

### Positive

- `eval "$(entraws ... --export)"` is a supported, documented workflow.
- The implementation is small and local: two call sites, one new
  function, one new flag.
- The default behavior is unchanged, so existing users and documentation
  remain correct.

### Negative

- There are now two codepaths after `assume_role_with_token` to keep in
  sync. Every change that affects credential persistence (logging, error
  handling, audit trails) must be considered for both.
- `--export` intentionally suppresses informational output, which could
  surprise users who expect to see the "Credentials written" line. The
  `--export` help text calls this out.

### Neutral

- Future output formats (JSON for tooling consumers, `.envrc` for
  direnv, Windows `set` syntax) would extend this axis. If more than one
  format is ever needed, replacing the boolean `--export` with
  `--output=shell|json|ini|file` becomes the natural next step.
