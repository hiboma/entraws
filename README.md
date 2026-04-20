# entraws

Obtain temporary AWS credentials by authenticating through an OpenID Connect
(OIDC) provider such as Microsoft Entra ID, Okta, Auth0, or Google. entraws
launches a browser-based OIDC flow, exchanges the resulting ID token for AWS
STS credentials via `AssumeRoleWithWebIdentity`, and writes them into your
`~/.aws/credentials` file under a named profile.

This is a Rust reimplementation of
[awslabs/StsOidcDriver](https://github.com/awslabs/StsOidcDriver). See
[NOTICE](NOTICE) for attribution.

## Features

- Authorization Code flow with PKCE (recommended)
- Implicit flow with PKCE (for providers that do not support code flow)
- Dynamic Client Registration
- Client Credentials grant for machine-to-machine usage
- Safe credential file handling: existing profiles in `~/.aws/credentials`
  are preserved; only the target profile is updated
- `--export` mode prints POSIX `export` statements to stdout for
  `eval "$(entraws ... --export)"` when you do not want to touch the
  on-disk credentials file
- File permissions are set to `0600` on Unix
- Ships as a single static binary

## Installation

### From source

```sh
cargo install --git https://github.com/hiboma/entraws
```

Or clone and build locally:

```sh
git clone https://github.com/hiboma/entraws
cd entraws
cargo install --path .
```

The binary is installed to `~/.cargo/bin/entraws`.

## Usage

### Authorization Code flow (recommended)

```sh
entraws \
  --role "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<ROLE_NAME>" \
  --openid-url "https://<OIDC_PROVIDER>/<TENANT>/v2.0" \
  --client-id "<OIDC_CLIENT_ID>"
```

> **Note**: entraws previously used snake_case CLI option names
> (`--openid_url`, `--client_id`, `--client_secret`, `--client_credentials`).
> These remain as hidden aliases for backward compatibility, but the
> canonical form is now kebab-case.

entraws opens your default browser, directs you to the IdP's sign-in page,
receives the authorization code on `http://127.0.0.1:6432/callback`, exchanges
it for an ID token, and then calls AWS STS to obtain temporary credentials.

On success, the credentials are written to `~/.aws/credentials` under the
`[entraws]` profile by default. Other profiles in the file are preserved.

### Using environment variables

```sh
export AWS_ROLE_ARN="arn:aws:iam::<AWS_ACCOUNT_ID>:role/<ROLE_NAME>"
export OIDC_DISCOVERY_URL="https://<OIDC_PROVIDER>/<TENANT>/v2.0"
export OIDC_CLIENT_ID="<OIDC_CLIENT_ID>"

entraws
```

### Custom profile name

```sh
entraws -p myprofile \
  --role "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<ROLE_NAME>" \
  --openid-url "https://<OIDC_PROVIDER>/<TENANT>/v2.0" \
  --client-id "<OIDC_CLIENT_ID>"
```

Then use the credentials with the AWS CLI:

```sh
env AWS_PROFILE=myprofile aws sts get-caller-identity
```

### Client Credentials flow (machine-to-machine)

```sh
entraws --client-credentials \
  --role "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<ROLE_NAME>" \
  --openid-url "https://<OIDC_PROVIDER>/<TENANT>/v2.0" \
  --client-id "<OIDC_CLIENT_ID>" \
  --client-secret "<OIDC_CLIENT_SECRET>"
```

This flow does not open a browser. It requests a token directly from the
IdP using the client credentials and then calls AWS STS.

### Dynamic Client Registration

If your IdP supports RFC 7591 Dynamic Client Registration, omit `--client-id`:

```sh
entraws \
  --role "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<ROLE_NAME>" \
  --openid-url "https://<OIDC_PROVIDER>/<TENANT>/v2.0"
```

### Export credentials to the current shell (`--export`)

Pass `--export` to print the STS credentials to stdout as POSIX `export`
statements instead of writing them to `~/.aws/credentials`. Combined with
`eval`, this loads the credentials into the current shell session:

```sh
eval "$(entraws --export \
  --role "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<ROLE_NAME>" \
  --openid-url "https://<OIDC_PROVIDER>/<TENANT>/v2.0" \
  --client-id "<OIDC_CLIENT_ID>")"

aws sts get-caller-identity  # reads AWS_ACCESS_KEY_ID / _SECRET / _SESSION_TOKEN
```

`--export` implies `--quiet` (unless `--debug` is also set), so
informational logs do not pollute the stream that `eval` consumes. Tracing
output is emitted to stderr, so `--export --debug` still produces a clean
stdout. Values are POSIX-single-quoted, so credentials containing shell
metacharacters are safe to `eval`.

## Options

| Option | Env Variable | Default | Description |
|---|---|---|---|
| `--role` | `AWS_ROLE_ARN` | *(required)* | IAM Role ARN to assume |
| `--openid-url` | `OIDC_DISCOVERY_URL` | *(required)* | OIDC discovery URL |
| `--client-id` | `OIDC_CLIENT_ID` | *(dynamic registration)* | OIDC Client ID |
| `--client-secret` | `OIDC_CLIENT_SECRET` | | Client secret (for `--client-credentials`) |
| `--region` | `AWS_REGION` | `us-east-1` | AWS region |
| `--duration-seconds` | `DURATION_SECONDS` | `3600` | STS credential lifetime |
| `-p`, `--profile-to-update` | `PROFILE_TO_UPDATE` | `entraws` | Profile name to update |
| `--aws-config-file` | `AWS_CONFIG_FILE` | `~/.aws/credentials` | Credentials file path |
| `--scopes` | | `openid email` | OIDC scopes to request |
| `--export` | | | Print credentials to stdout as `export` statements for `eval "$(...)"` instead of writing them to the credentials file. Implies `--quiet` unless `--debug` is set. |
| `--debug` | | | Enable verbose logging |
| `-q`, `--quiet` | | | Suppress informational log output (warn level only) |
| `--dangerously-log-secrets` | | | Log identifying JWT claims (iss/aud/sub/ver) at DEBUG level. Implies `--debug`. **Use with extreme care.** |
| `--implicit` | | | Use the implicit flow (not recommended) |
| `--client-credentials` | | | Use the client credentials grant |

## Setting up your OIDC provider

### Microsoft Entra ID (Azure AD)

1. **Register an application**
   - Microsoft Entra admin center → App registrations → New registration
   - Name: anything identifiable
   - Supported account types: usually single tenant

2. **Authentication settings**
   - Platform: *Mobile and desktop applications*
   - Redirect URI: `http://127.0.0.1:6432/callback`
   - Allow public client flows: **Yes**

3. **Token configuration**
   - Add an optional claim → ID token → `email`
   - Grant consent for the associated Microsoft Graph `email` permission

4. **Note the identifiers**
   - Application (client) ID
   - Directory (tenant) ID

### Okta, Auth0, and others

The OIDC flow is standard, but each provider has its own UI for creating a
public native client with PKCE and an allowed redirect URI of
`http://127.0.0.1:6432/callback`. Refer to your provider's documentation.

## Setting up AWS

### 1. Create an OIDC identity provider

- IAM → Identity providers → Add provider → OpenID Connect
- Provider URL: your OIDC issuer URL (e.g. `https://login.microsoftonline.com/<TENANT_ID>/v2.0`)
- Audience: your OIDC client ID
- AWS fetches the TLS thumbprint automatically

### 2. Create an IAM role

- Trusted entity type: Web identity
- Identity provider: the one you just created
- Audience: your OIDC client ID
- Attach the permissions you want the role to grant

The generated trust policy will look like:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::<AWS_ACCOUNT_ID>:oidc-provider/<OIDC_PROVIDER_HOST>/<PATH>"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "<OIDC_PROVIDER_HOST>/<PATH>:aud": "<OIDC_CLIENT_ID>"
                }
            }
        }
    ]
}
```

## Security notes

### The default trust policy is permissive

The trust policy above only checks the `aud` claim. That means **any user in
your OIDC tenant who can sign in to the registered application can assume the
role**. For production use you should add a more restrictive condition:

**Restrict by user object ID**

```json
"StringEquals": {
    "<OIDC_PROVIDER_HOST>/<PATH>:aud": "<OIDC_CLIENT_ID>",
    "<OIDC_PROVIDER_HOST>/<PATH>:oid": "<ENTRA_OBJECT_ID_OR_OIDC_SUBJECT>"
}
```

**Restrict by group membership (preferred)**

Configure your IdP to include a `groups` claim and use `ForAnyValue:StringEquals`
to match expected group IDs.

**Restrict at the IdP level**

In Entra ID, toggle *Assignment required?* to `Yes` on the application's
Properties tab and explicitly assign only the intended users and groups.

### Credential file handling

- `~/.aws/credentials` is parsed as INI. Only the specified profile is
  updated; other profiles are preserved.
- On Unix, the file is written with permission `0600`.
- If the file does not exist, it is created.
- With `--export`, the credentials file is not touched at all. The
  credentials are emitted to stdout and never persisted to disk by
  entraws.

### `--dangerously-log-secrets`

This flag logs identifying JWT claims (`iss`, `aud`, `sub`, `ver`) at DEBUG
level. These values do not include the signing material, but they do identify
your tenant and user, and they can help an attacker correlate activity. Only
enable this flag when you are actively debugging a specific issue in a
private environment, and never enable it in shared CI logs or production
environments. The long, awkward name is intentional.

### JWT signature validation

entraws does **not** cryptographically verify the ID token signature itself.
AWS STS performs full signature validation against the IdP's published JWKS
before issuing credentials, so forged tokens cannot reach a successful
`AssumeRoleWithWebIdentity`. entraws only decodes the JWT locally to extract
the `email` or `sub` claim for use as `RoleSessionName`.

### `--client-credentials` risks

The client credentials grant exchanges a long-lived OIDC client secret for
an access token without any human in the loop. This is convenient for CI,
but carries real risks:

- The client secret must be stored somewhere the CI job can read it
  (environment variable, secret manager), and every place that can read it
  can impersonate the machine identity.
- The resulting `RoleSessionName` identifies the OIDC subject, not a
  human, so audit logs lose the usual "who triggered this" signal.
- There is no second factor and no browser-mediated consent; a leaked
  secret directly yields AWS credentials for the trust-policy role.

Prefer short-lived OIDC credentials from your CI platform when available
(for example, GitHub Actions' OIDC token exchanged directly against
`sts:AssumeRoleWithWebIdentity` — no entraws needed). Only use
`--client-credentials` when a long-lived service account is genuinely
required, and rotate the client secret on a schedule.

### `--export` and environment-variable exposure

`--export` + `eval` avoids writing credentials to `~/.aws/credentials`,
but it does not make the credentials "safer" in every sense. Once loaded
into the shell they become environment variables, which means:

- They are inherited by every child process launched from that shell.
- They are visible via `/proc/<pid>/environ` to any process running as
  the same user.
- They can end up in shell history if the `entraws --export` line is
  typed without the `eval` wrapper.
- They survive for the rest of the shell session even after the
  underlying role would normally have expired from a caller's view.

Use `--export` for scratch sessions and ephemeral CI shells, not as a
default "more secure" alternative to the credentials file.

### No automatic credential rotation

entraws is a one-shot CLI. It writes STS credentials and exits; it does
not run as a daemon, does not refresh credentials on expiry, and does
not integrate with the AWS SDK's `credential_process` mechanism. When
the credentials expire (default: 1 hour) you must rerun entraws to
obtain a new set.

If you need automatic credential refresh, `aws sso login` (when IAM
Identity Center is available) or a dedicated credential broker such as
`aws-vault` or `saml2aws` is the better fit. Implementing rotation in
entraws would require storing a long-lived refresh token on disk or in
an OS keychain, which is at odds with the tool's goal of being a small,
stateless CLI.

## Why entraws instead of `aws configure sso` / `aws sso login`?

`aws sso login` is the right tool when your organization has adopted
**AWS IAM Identity Center** and centralizes all AWS account access
through it. entraws targets the cases where that assumption does not
hold. Specifically:

### 1. No IAM Identity Center, no AWS Organizations

`aws sso login` requires an IAM Identity Center **organization
instance**, which in turn is most useful when enabled from an AWS
Organizations management account. An Identity Center **account
instance** cannot grant sign-on to AWS accounts at all — it only
supports AWS managed applications.

entraws talks directly to AWS STS via `AssumeRoleWithWebIdentity`
against an IAM OIDC identity provider. No IAM Identity Center, no AWS
Organizations, no permission sets — just an IAM role with a web
identity trust policy.

### 2. Direct federation with your existing IdP

`aws sso login` federates through IAM Identity Center, even when the
authoritative identity source is Microsoft Entra ID, Okta, Auth0, or
Google. entraws lets the same IdP act as the OIDC provider for AWS
directly, removing Identity Center as a middle layer and the SCIM
provisioning it implies.

### 3. Writes to `~/.aws/credentials`, not the SSO cache

`aws sso login` stores tokens in `~/.aws/sso/cache/` and expects the
consumer to understand SSO-aware profile configuration in
`~/.aws/config`. Older SDKs, third-party tools, and scripts that only
read the classic `[profile]` blocks in `~/.aws/credentials` do not
always support that cache format.

entraws writes plain `aws_access_key_id` / `aws_secret_access_key` /
`aws_session_token` to a named profile in `~/.aws/credentials`, so
anything that reads an INI-style credentials file works unchanged.

### 4. Non-interactive machine-to-machine authentication

`aws sso login` is built around a human opening a browser. It has no
equivalent of the OAuth 2.0 client credentials grant.

entraws supports `--client-credentials` for CI jobs and daemons that
authenticate with a client ID and secret against the IdP, obtain an
access token, and exchange it for AWS credentials — no browser, no
device code, no interactive prompt.

### 5. `eval`-friendly `--export` mode

`--export` emits POSIX `export` statements on stdout so the credentials
can be injected into the current shell with
`eval "$(entraws ... --export)"`. This keeps short-lived AWS
credentials out of the on-disk credentials file entirely, which is
useful for scratch sessions, ephemeral CI shells, and dev containers.

### When `aws sso login` is still the better choice

- Your organization already runs IAM Identity Center and manages
  permission sets centrally.
- You need single sign-on across many AWS accounts from one login.
- You rely on the SDK's automatic SSO token refresh.

In those cases, use `aws sso login`. entraws is aimed at the
complementary case: a small number of roles, no Identity Center, and a
preference for the classic INI credentials file.

## Relationship with existing SSO tools

entraws targets environments where developers already authenticate to their
identity provider from the browser and want a lightweight, standards-based
way to obtain AWS temporary credentials. It is designed to coexist with
other AWS credential tools by writing to a separate profile name (`entraws`
by default) so that existing profiles are preserved.

If your organization already has a SAML-based SSO tool for AWS, entraws is
best used alongside it rather than as a replacement. The OIDC flow used by
entraws complements SAML-based flows: each tool can target a different set
of roles or accounts, and the two can write to different profiles in
`~/.aws/credentials`.

## Development

```sh
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo deny check
```

Architecture decisions are recorded under [`docs/adr/`](docs/adr/).

## License

MIT License. See [LICENSE](LICENSE).

## Acknowledgements

- [awslabs/StsOidcDriver](https://github.com/awslabs/StsOidcDriver) — the
  original Python implementation this project was inspired by.
- [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252) — OAuth 2.0 for
  Native Apps.
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — Proof Key for
  Code Exchange (PKCE).
