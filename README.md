# `codesign`

Remote Authenticode code signing for Windows binaries, backed by a hardware
token (YubiKey PIV). The private key never leaves the token.

This module provides:

-   `signerd` — a small HTTP daemon that runs next to the YubiKey and signs
    PE/MSI files with `osslsigncode` or [jsign](https://github.com/ebourg/jsign).
    Runs on Linux (bare, systemd, or Docker) and macOS (launchd).
-   `codesign` — a CLI (and Go client library) that POSTs a file to `signerd`
    and writes back the signed result. Used locally and from CI.
-   A composite GitHub Action (`uses: golift/codesign@v1`) for signing release
    artifacts from GitHub Actions.

Remote requests are protected by **two required gates**:

1.  **mTLS** at the reverse proxy (nginx `ssl_verify_client on`).
2.  **GitHub Actions OIDC** verified by `signerd` against a fail-closed
    repository allowlist.

Local/operator signing uses an SSH tunnel to the daemon's loopback bind; see
`docs/` once published.

## Status

Under construction. Nothing to install yet.

-   [GoDoc](https://pkg.go.dev/golift.io/codesign)
-   MIT licensed.
