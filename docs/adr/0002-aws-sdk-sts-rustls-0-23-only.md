# 0002. Pin `aws-sdk-sts` to the rustls 0.23 stack only

- Status: Accepted
- Date: 2026-04-16
- Deciders: @hiboma

## Context

`cargo-deny` started failing CI on PR #11 with two advisories:

- [RUSTSEC-2026-0098](https://rustsec.org/advisories/RUSTSEC-2026-0098)
  — name constraints for URI names were incorrectly accepted.
- [RUSTSEC-2026-0099](https://rustsec.org/advisories/RUSTSEC-2026-0099)
  — permitted subtree name constraints for DNS names were accepted for
  certificates asserting a wildcard name.

Both are fixed in `rustls-webpki >= 0.103.12` (and the 0.104-alpha
series). The advisory explicitly states the 0.101.x branch will not
receive a fix.

`cargo tree -i rustls@0.21.12` showed the vulnerable stack was being
pulled in via:

```
rustls-webpki 0.101.7
└── rustls 0.21.12
    └── aws-smithy-http-client 1.1.12
        └── (enabled by) aws-smithy-runtime "tls-rustls"
            └── (enabled by) aws-sdk-sts default feature "rustls"
```

`aws-sdk-sts`'s default features list includes **both** `rustls`
(= `aws-smithy-runtime/tls-rustls` = `aws-smithy-http-client/legacy-rustls-ring`
= rustls 0.21 + rustls-webpki 0.101.x + hyper-rustls 0.24 + tokio-rustls
0.24) **and** `default-https-client` (= `aws-smithy-http-client/rustls-aws-lc`
= rustls 0.23 + rustls-webpki 0.103.x). The two stacks coexist in the
dependency graph, but only the rustls 0.21 one is used for the actual
HTTPS client path unless `tls-rustls` is explicitly plumbed through — the
rest of the legacy tree is dead weight that still triggers the advisory.

Upgrading `rustls-webpki` to 0.103.12 alone closed the advisory on the
0.103 copy, but the 0.101.7 copy brought in by the legacy stack
continued to fail.

## Decision

Disable `aws-sdk-sts`'s default features and re-enable only the ones we
actually need:

```toml
aws-sdk-sts = { version = "1", default-features = false, features = [
    "default-https-client",
    "rt-tokio",
    "behavior-version-latest",
] }
```

This drops `aws-sdk-sts/rustls`, which in turn prunes the entire
rustls 0.21 / rustls-webpki 0.101.x / hyper-rustls 0.24 / tokio-rustls
0.24 subtree from `Cargo.lock`. The remaining rustls 0.23 + aws-lc-rs
stack is what `aws-config`'s default-https-client already uses, and it
is what actually performs the STS HTTPS calls.

We rejected two alternatives:

- **Ignore the advisories in `deny.toml`** (`[advisories] ignore = ["RUSTSEC-2026-0098", "RUSTSEC-2026-0099"]`).
  This would silence CI without changing the real dependency graph, and
  would require ongoing attention to remember to un-ignore them when
  `aws-smithy-http-client` eventually drops the legacy rustls feature.
  It also normalizes "ignore the advisory" as a reflex rather than a
  last resort.
- **Wait for `aws-smithy-http-client` to drop `legacy-rustls-ring`**.
  Upstream has not signaled an imminent removal of the feature, and the
  entraws build is blocked on green CI in the meantime. Opting out
  locally is a one-line change and is easy to revert once the feature
  is gone upstream.

## Consequences

### Positive

- `cargo-deny advisories` passes. `Cargo.lock` no longer contains
  rustls 0.21.x, rustls-webpki 0.101.x, hyper-rustls 0.24.x, or
  tokio-rustls 0.24.x.
- Smaller dependency graph: fewer crates to audit, faster cold builds.
- The decision to route HTTPS through aws-lc-rs + rustls 0.23 is now
  explicit rather than incidental, and can be re-evaluated if the
  project ever needs FIPS mode (`rustls-aws-lc-fips`) or ring
  (`rustls-ring`).

### Negative

- Any future feature that depends on `aws-sdk-sts/rustls` will need to
  be added to the explicit feature list — or preferably re-routed
  through the modern stack. Contributors who are used to the default
  feature set may be briefly surprised.

### Neutral

- If `aws-smithy-http-client` drops its `legacy-rustls-ring` feature
  upstream, we can revert this pin and let default features apply
  again. That is a desirable follow-up but not urgent.
