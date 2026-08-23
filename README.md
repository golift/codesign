# `codesign`

Remote Authenticode signing for Windows PE/MSI files, backed by a YubiKey PIV
token. The private key never leaves the token.

**v1 is built for GitHub Actions.** A workflow POSTs artifacts through an mTLS
proxy to `signerd`, which verifies a GitHub OIDC token against a fail-closed
repository allowlist and signs on the hardware token.

This module provides:

-   A composite GitHub Action (`uses: golift/codesign@v1`).
-   `signerd` — HTTP daemon next to the YubiKey (`osslsigncode` or
    [jsign](https://github.com/ebourg/jsign)), on Linux (Docker/systemd) or macOS (launchd).
-   `codesign` — CLI and Go client library used by the Action.

Remote requests require **both** gates:

1.  **mTLS** at the reverse proxy (nginx `ssl_verify_client on`).
2.  **GitHub Actions OIDC** verified by `signerd` (`allowed_repositories`).

## GitHub Action

The job **must** grant `id-token: write` or the signing service returns 401.

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

Files are replaced in place. The operator must allowlist your `Owner/repo`
and issue a client certificate that chains to the proxy CA. Server-side docs:

-   OIDC allowlist: [docs/github-oidc.md](docs/github-oidc.md)
-   mTLS: [docs/mtls.md](docs/mtls.md)
-   nginx: [docs/nginx.md](docs/nginx.md)
-   YubiKey facts: [docs/yubikey.md](docs/yubikey.md)

## Deploying the daemon

Start with [examples/signerd.toml.example](examples/signerd.toml.example):

-   **Docker** (recommended): [Dockerfile](Dockerfile) +
    [docker-compose.yml.example](docker-compose.yml.example), USB notes in
    [docs/docker-usb.md](docs/docker-usb.md).
-   **systemd**: [systemd/signerd.service.example](systemd/signerd.service.example).
-   **launchd** (macOS): [launchd/signerd.plist.example](launchd/signerd.plist.example).

A `v1.0.0` release plants the floating `v1` tag the Action tracks.

-   [GoDoc](https://pkg.go.dev/golift.io/codesign)
-   MIT licensed.
