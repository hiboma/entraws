# Architecture Decision Records

This directory records architecture decisions for `entraws` in the
[MADR](https://adr.github.io/madr/) format.

Each ADR captures the context, the decision, and the consequences of a
non-obvious architectural choice, so that future maintainers can understand
why the code looks the way it does without having to reconstruct the
reasoning from commit history.

## Index

| ID | Title | Status |
|----|-------|--------|
| [0001](0001-credential-output-modes.md) | Two credential output modes: credentials file vs. shell exports | Accepted |
| [0002](0002-aws-sdk-sts-rustls-0-23-only.md) | Pin `aws-sdk-sts` to the rustls 0.23 stack only | Accepted |

## Writing a new ADR

1. Copy the most recent ADR as a template.
2. Number sequentially (`NNNN-short-slug.md`).
3. Set the status to `Proposed`, `Accepted`, `Deprecated`, or `Superseded by NNNN`.
4. Add a row to the index above.
