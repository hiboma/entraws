# `credential_process` integration

entraws exposes its stored credentials through the AWS SDK
`credential_process` contract, so `aws` and any SDK-based tool can use
them transparently without copying secrets into the environment.

## Setup

1. Run `entraws login` once to populate the sink (Keychain on macOS,
   `~/.aws/credentials` elsewhere). The tool prints a `credential_process`
   stanza on success:

   ```ini
   [profile entraws]
   credential_process = /Users/you/.cargo/bin/entraws credentials \
       --cache-key <hex> --source keychain
   region = ap-northeast-1
   ```

2. Append that stanza to `~/.aws/config` (not `~/.aws/credentials`).
   Use an absolute path to the `entraws` binary so the stanza keeps
   working regardless of the caller's `PATH`.

3. Run AWS commands as usual:

   ```sh
   AWS_PROFILE=entraws aws sts get-caller-identity
   ```

The AWS CLI invokes `entraws credentials` for each command, reads the
JSON payload from stdout, and uses the credentials within that process.

## Behaviour

### Fast path

`entraws credentials` first reads `~/.entraws/cache/<cache-key>.json`.
If the remaining TTL exceeds `--min-ttl-seconds` (default 300), the
cached entry is emitted directly. The keychain is **not** touched on
this path, which is what keeps parallel `aws` invocations from
triggering a flurry of biometric prompts.

### Slow path

When the cache is empty or stale, the subcommand acquires an exclusive
flock on `<cache-key>.lock` and loads the configured source (Keychain
or file). It re-checks the cache under the lock so a parallel refresher
that just finished is observed rather than duplicated. On success the
cache is refreshed and the JSON payload is emitted.

### Miss path

If the source also returns nothing usable, `entraws credentials`
exits **2** and prints `run: entraws login` to stderr. It never opens
a browser — `credential_process` subprocesses have a ~1 minute timeout
(per the AWS SDK Go v2 default) and usually no TTY, making interactive
flows unworkable. The operator must rerun `entraws login` explicitly.

## Pre-expire margin

Every stored entry's `expiration` is shortened by five minutes
(`credential::PRE_EXPIRE_MARGIN`) before it reaches disk. This keeps
the AWS SDK's own refresh-ahead logic from racing the actual STS
expiry during long multi-request operations (aws-sdk-java-v2 #3408,
aws-sdk-js #3581).

## Security properties

- **stdout carries JSON only.** All diagnostic text goes to stderr.
  Never reshape `entraws credentials` output into shell `eval` — it is
  only designed for the AWS SDK JSON consumer.
- **stderr carries no secrets.** The tracing subsystem is deliberately
  not initialised in the `credentials` subcommand, so nothing in the
  code path can log secret material even by accident. The
  `Secret<T>` newtype makes a stray `{:?}` format a compile-time
  redaction.
- **Browser flows are unreachable** from `credential_process`. The
  only code path that spawns a browser is `entraws login`.
- **ACL prompts are minimised** by the CacheStore layer. The keychain
  is consulted only when the per-process cache does not have a fresh
  entry — typically once per session, plus whenever the stored
  credentials are pre-expired.

## Keychain ACL caveat (macOS)

macOS keychain items are bound to the code signature of the binary
that created them. Homebrew reinstalls, `cargo build` with a
different identity, and `codesign --force --sign -` all change the
Designated Requirement, which invalidates the "Always Allow" ACL and
triggers a fresh prompt. This is a macOS property, not an entraws bug;
the CacheStore layer keeps the prompt frequency tolerable in practice.

## Logging out

```sh
rm ~/.entraws/cache/<cache-key>.json
security delete-generic-password -s entraws -a <cache-key>   # macOS
```

A dedicated `entraws logout` subcommand is not part of the initial
release. Remove the cache entry and the keychain item manually if you
need to force the next operation through `entraws login`.
