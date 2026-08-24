# mTLS with a private CA (step-ca)

Gate 1 of 2. The reverse proxy requires a client certificate issued by *your*
CA before a request ever reaches signerd. GitHub Actions holds the client
cert/key as secrets; the CA never leaves your infrastructure.

Any CA works; [smallstep step-ca](https://smallstep.com/docs/step-ca/) is a
good fit for a homelab.

## Issue a client certificate

A default step-ca provisioner caps TLS certificates at **24 hours**, so a
year-long `--not-after 8760h` is rejected until you raise
`maxTLSCertDuration` on the authority/provisioner. Ninety days is a
reasonable GitHub-secret rotation window once that cap is raised:

```jsonc
// in the provisioner (ca.json), then restart step-ca:
"maxTLSCertDuration": "2160h"
```

```bash
# On a machine with step configured against your CA:
step ca certificate "github-codesign" client.crt client.key \
  --san github-codesign --not-after 2160h
```

Without the provisioner change, omit `--not-after` (24h) and rotate often.
Keep the lifetime long enough that rotation is a scheduled chore, short
enough that a leak has a horizon.

## nginx side

`nginx/sign.conf` in this repository already contains the lines that matter:

```nginx
ssl_client_certificate /config/keys/client-ca.crt;  # your CA root/intermediate
ssl_verify_client on;
ssl_verify_depth 2;                                  # leaf -> intermediate -> root
```

step-ca normally issues client certificates through an intermediate, so the
presented chain is leaf → intermediate → root. nginx defaults `ssl_verify_depth`
to 1, which rejects that chain; `2` accepts one intermediate. Raise it if your
CA nests deeper.

Export the CA certificate (public) from step-ca and place it at that path:

```bash
step ca root client-ca.crt
```

## GitHub side

Store the client pair as **organization secrets** so the repos that sign can
use them; the values are the inline PEM contents, not paths. mTLS proves "a
workflow in this org", not "this specific repository". The repository allowlist
(OIDC) is what names the repos that may sign. Any branch of an allowlisted repo
clears OIDC; see github-oidc.md.

`gh secret set -o` defaults to `--visibility private`, which excludes public
repos. Pass `--visibility all` to reach every repo, or scope tightly with
`--visibility selected --repos "org/repo1,org/repo2"` (recommended: list only
the repos that sign):

```bash
gh secret set CODESIGN_CLIENT_CERT -o your-org --visibility all < client.crt
gh secret set CODESIGN_CLIENT_KEY  -o your-org --visibility all < client.key
gh secret set CODESIGN_URL         -o your-org --visibility all --body "https://sign.example.com"
```

## Rotation

Issue a new pair, update the secrets, verify a workflow run, then revoke the
old cert (or just let it expire if your window is short):

```bash
step ca certificate "github-codesign" client-new.crt client-new.key --not-after 2160h
gh secret set CODESIGN_CLIENT_CERT -o your-org --visibility all < client-new.crt
gh secret set CODESIGN_CLIENT_KEY  -o your-org --visibility all < client-new.key
```

Use the same `--visibility`/`--repos` selection you chose when first creating
the secrets so rotation does not silently narrow their reach.

Nothing on the server changes during *client* rotation — nginx trusts the
CA, not the individual certificate. **Revoking** the old cert does not take
effect unless nginx is configured to check a CRL or OCSP (`ssl_crl`, or a
short-lived cert you simply let expire). This example does not ship a CRL;
prefer a lifetime short enough that expiry is the revocation story, or add
`ssl_crl` and reload nginx when you rotate.
