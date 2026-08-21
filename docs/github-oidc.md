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
| `missing Authorization bearer token` | Job forgot `id-token: write`, or you called the public URL from a laptop (use the SSH tunnel instead — see local-signing.md). |
| `token has invalid audience` | Caller audience differs from the server's `audience` (usually a URL typo or trailing slash). |
| `repository is not on the allowed repositories list` | Add `Owner/repo` to `allowed_repositories` and restart signerd. |
| `allowed repositories list is empty` | You never configured the allowlist; remote signing is disabled by design. |
| TLS handshake failure before any HTTP status | mTLS gate: missing/expired client certificate, or Cloudflare orange-cloud is terminating TLS (must be DNS-only). |

## Loopback skip

Requests that reach signerd **from its own loopback interface** skip OIDC.
That is strictly for the operator SSH-tunnel workflow and on-host smoke
tests. Requests proxied by nginx or crossing a Docker bridge network are not
loopback and always authenticate. Never bind signerd to `0.0.0.0` on a host
where the LAN can reach it.
