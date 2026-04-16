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
- Pluggable credential sinks: `~/.aws/credentials` (default on Linux) or
  the macOS login keychain (default on macOS)
- AWS SDK `credential_process` integration via `entraws credentials`
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

### Credential sinks: Keychain vs. file

On macOS the default sink is the login keychain; on other platforms it
is `~/.aws/credentials`. Override with `--sink`:

```sh
# Explicitly store credentials in the shared credentials file
entraws --sink file --role ... --openid-url ... --client-id ...

# Explicitly store in macOS Keychain
entraws --sink keychain --role ... --openid-url ... --client-id ...
```

After a successful login, entraws prints the `credential_process`
stanza you should add to `~/.aws/config` so the AWS CLI and SDKs can
consume the stored credentials without exposing them to other shell
sessions.

### AWS `credential_process` integration

The `~/.aws/config` stanza entraws expects looks like:

```ini
[profile entraws]
credential_process = entraws credentials --cache-key <hex> --source keychain
region = ap-northeast-1
```

Pass `--configure-profile` to have entraws write this section for you
after a successful login:

```sh
entraws -p entraws --sink keychain --configure-profile \
  --role ... --openid-url ... --client-id ...
```

The write is opt-in and, by default, safe:

- A profile section that was not previously written by entraws is
  left untouched — pass `--force` to overwrite.
- `--dry-run` prints the diff to stderr and exits without modifying
  anything.
- Adjacent profiles, comments, and blank lines are preserved
  byte-for-byte (entraws-managed sections are bracketed by
  `# managed-by: entraws` / `# end: entraws` markers).
- A one-shot `~/.aws/config.entraws.bak` backup is created the first
  time an existing config is touched.

Once configured, the AWS CLI fetches credentials from the sink
(through a per-process cache at `~/.entraws/cache/`) whenever a
command runs under `AWS_PROFILE=entraws`. When the cached credentials
expire, `entraws credentials` exits non-zero with a hint to rerun
`entraws login` — interactive flows are never started from a
`credential_process` subprocess because that path has a short timeout
and no TTY. See [docs/credential-process.md](docs/credential-process.md)
for details.

If you would rather edit `~/.aws/config` by hand, regenerate the
cache-key with:

```sh
entraws cache-key --role ... --openid-url ... --client-id ...
```

### Check remaining TTL

```sh
entraws status --cache-key <hex-from-login-output>
```

Reads only the per-process cache, so it never triggers a keychain
prompt.

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
