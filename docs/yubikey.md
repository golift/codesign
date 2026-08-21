# YubiKey PIV inventory and signing-slot facts

The daemon signs with a code-signing certificate that lives in a PIV slot
(typically **9A** when issued through SSL.com's eSigner/YubiKey flow). The
private key never leaves the token; back up the *certificate chain*, not the
key, because the key cannot be exported.

## Inventory (safe, read-only)

```bash
brew install ykman            # macOS; apt/pipx elsewhere
ykman piv info                # firmware, PIN retries, slot overview
ykman piv certificates export 9a - | openssl x509 -noout -subject -dates -ext extendedKeyUsage
```

Do not print or export the PIN/PUK anywhere, and never commit slot exports.

## PIN, PUK, management key

| Secret | Used for | Needed by signerd? |
| --- | --- | --- |
| User PIN | Signing operations | Yes (`pin` / `pin_file` / `SIGNERD_PIN`) |
| PUK | Unblocking a locked PIN | **Never.** Recovery only. |
| Management key | Importing/generating keys and certs | No |

SSL.com's portal calls the PUK the "Admin PIN". Recovery, if the PIN gets
blocked by failed attempts:

```bash
ykman piv access unblock-pin
```

## Touch and PIN policy

PIN/touch policies are set when a key is generated or imported and **cannot
be changed afterward** without replacing the key. Check yours:

```bash
ykman piv info
```

A slot with touch policy `Never` and PIN policy `Once` is what makes
unattended server signing possible. If your signing slot requires touch, a
headless daemon cannot use it; you would need to re-import or re-issue with a
different policy (talk to your CA before touching an attested slot).

## Digest must match the key type

An ECC P-384 signing key needs ECDSA Authenticode with SHA-384 digests; that
is the daemon's default (`sha384` for osslsigncode, `SHA-384` for jsign). RSA
keys usually want SHA-256 — set `digest` in the config.
