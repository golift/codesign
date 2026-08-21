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

## GitHub Action

Sign release artifacts from a workflow. The job **must** grant
`id-token: write` or the signing service will reject the request with 401.

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write   # REQUIRED: lets the action fetch a GitHub OIDC token.
    steps:
      - uses: actions/checkout@v5
      # ... build your Windows binaries ...
      - uses: golift/codesign@v1
        with:
          files: |
            dist/*.exe
            dist/*.msi
          url: ${{ secrets.CODESIGN_URL }}
          client-cert: ${{ secrets.CODESIGN_CLIENT_CERT }}
          client-key: ${{ secrets.CODESIGN_CLIENT_KEY }}
          name: My Application
          website: https://app.example.com
```

Files are replaced in place with their signed versions. The service operator
must add your `Owner/repo` to the daemon's `allowed_repositories` list, and
your client certificate must chain to the CA that the operator's proxy
verifies. See `docs/` for the server side.

## Status

Under construction; a `v1.0.0` release plants the floating `v1` tag.

-   [GoDoc](https://pkg.go.dev/golift.io/codesign)
-   MIT licensed.
