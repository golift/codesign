# GitHub Actions OIDC: the second gate

Even with a valid client certificate, signerd refuses to sign unless the
request carries a GitHub Actions OIDC token that passes **all** of:

1. Signature against GitHub's published JWKS
   (`https://token.actions.githubusercontent.com`).
2. `iss` matches the configured issuer.
3. `aud` matches the configured `audience` (conventionally your public
   signing URL).
4. Not expired.
5. `repository` is on the `allowed_repositories` list — **fail closed**: an
   empty list means nobody signs remotely.

## Server configuration

```toml
[github]
  audience = "https://sign.example.com"
  allowed_repositories = [
    "Owner/repo",
  ]
```

## Caller requirements

The workflow **job** (not just the workflow) must request an OIDC token:

```yaml
permissions:
  contents: read
  id-token: write
```

The `golift/codesign` action (and the `codesign` CLI under Actions) fetches
the token automatically, using the service URL as the audience.

## Debugging 401s

| Symptom | Likely cause |
| --- | --- |
| `missing Authorization bearer token` | Job forgot `id-token: write`. Laptop callers cannot use the public URL (no OIDC); local signing is unsupported in v1. |
| `token has invalid audience` | Caller audience differs from the server's `audience` (usually a URL typo or trailing slash). |
| `repository is not on the allowed repositories list` | Add `Owner/repo` to `allowed_repositories` and restart signerd. |
| `allowed repositories list is empty` | You never configured the allowlist; remote signing is disabled by design. |
| TLS handshake failure before any HTTP status | mTLS gate: missing/expired client certificate, or Cloudflare orange-cloud is terminating TLS (must be DNS-only). |

## Loopback skip

Loopback peers skip OIDC only when `allow_unauthenticated_loopback = true`.
The default is **off**: v1 is GitHub Actions, and a reverse proxy aimed at
`http://127.0.0.1:8750` would otherwise present every client as a loopback
peer and skip the gate. Enable the flag only for an SSH-tunnel operator
workflow.

When the skip is on, **any local user or process** that can connect to the
listen address signs with no PIN, no mTLS, and no OIDC — not just your SSH
session. Shell access to that host is then signing authority. Do not bind
anything else to that loopback port.

Two deployment rules keep the skip (if you enable it) from becoming a
proxy bypass:

- Never bind signerd to `0.0.0.0` on a host where the LAN can reach it.
- Never point a reverse proxy at a loopback upstream
  (`http://127.0.0.1:8750`). Proxy over a Docker network or another
  non-loopback address instead (see nginx.md).

## Allowlist granularity

`allowed_repositories` is repository-level only. There is no `ref`, branch,
tag, pull-request, or GitHub Environment pin in v1. Any workflow job in an
allowlisted repo that has `id-token: write` can sign — including a push to
an unreviewed branch. Combine that with an org-wide mTLS client cert (see
mtls.md) and the gates become: "this org's cert" plus "this repo's OIDC".
That is the v1 model; tighten later with per-repo certs or a ref allowlist
if you need it.
