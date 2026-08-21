# mTLS with a private CA (step-ca)

Gate 1 of 2. The reverse proxy requires a client certificate issued by *your*
CA before a request ever reaches signerd. GitHub Actions holds the client
cert/key as secrets; the CA never leaves your infrastructure.

Any CA works; [smallstep step-ca](https://smallstep.com/docs/step-ca/) is a
good fit for a homelab.

## Issue a client certificate

```bash
# On a machine with step configured against your CA:
step ca certificate "github-codesign" client.crt client.key \
  --san github-codesign --not-after 8760h
```

Keep the lifetime long enough that rotation is a scheduled chore, short
enough that a leak has a horizon (a year is a reasonable start).

## nginx side

`nginx/sign.conf` in this repository already contains the two lines that
matter:

```nginx
ssl_client_certificate /config/keys/client-ca.crt;  # your CA root/intermediate
ssl_verify_client on;
```

Export the CA certificate (public) from step-ca and place it at that path:

```bash
step ca root client-ca.crt
```

## GitHub side

Store the client pair as **organization secrets** so every repo that signs
can use them; the values are the inline PEM contents, not paths:

```bash
gh secret set CODESIGN_CLIENT_CERT -o your-org < client.crt
gh secret set CODESIGN_CLIENT_KEY  -o your-org < client.key
gh secret set CODESIGN_URL         -o your-org --body "https://sign.example.com"
```

## Rotation

Issue a new pair, update the secrets, verify a workflow run, then revoke the
old cert (or just let it expire if your window is short):

```bash
step ca certificate "github-codesign" client-new.crt client-new.key --not-after 8760h
gh secret set CODESIGN_CLIENT_CERT -o your-org < client-new.crt
gh secret set CODESIGN_CLIENT_KEY  -o your-org < client-new.key
```

Nothing on the server changes during client rotation — nginx trusts the CA,
not the individual certificate.
