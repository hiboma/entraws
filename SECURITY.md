# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `entraws`, please report it privately
via GitHub's Private Vulnerability Reporting feature:

- https://github.com/hiboma/entraws/security/advisories/new

Please do **not** open a public issue for security-sensitive reports.

## Scope

`entraws` is a CLI tool that exchanges an OpenID Connect ID token for AWS STS
temporary credentials. Security-relevant areas include:

- Handling of ID tokens, client secrets, and STS credentials
- PKCE parameter generation and state validation
- Local HTTP server used for the OIDC callback (`127.0.0.1:6432`)
- File permissions of the generated AWS credentials file
- Supply chain (dependencies, GitHub Actions workflows)

## What to Include in a Report

- A clear description of the issue and its impact
- Steps to reproduce, including the `entraws` version and platform
- Any proof-of-concept code or logs (please redact any tokens or AWS account
  identifiers)
- Your suggested fix, if any

## Response

We aim to acknowledge reports within five business days and provide an initial
assessment within ten business days. Public disclosure will be coordinated with
the reporter.

## JWT Signature Validation

entraws does **not** cryptographically verify the ID token signature itself.
The security of the token exchange relies on two defenses:

1. **AWS STS performs full signature validation** against the IdP's
   published JWKS before issuing credentials. A forged ID token cannot
   reach a successful `AssumeRoleWithWebIdentity` call, because STS
   itself rejects it. This is the primary defense.
2. **entraws validates the `iss` claim locally** against the OIDC
   discovery document's `issuer` field. This catches tokens from an
   unexpected issuer before the STS call is made.

entraws decodes the JWT locally only to extract the `email` or `sub`
claim (used as `RoleSessionName`) and the `iss` claim (used for the
defensive issuer check above). Local signature verification is
deliberately skipped to avoid duplicating the work that STS performs
server-side.
