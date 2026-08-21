# Operator local signing (laptop builds, key on the server)

You built a Windows binary on your laptop and want it signed, but the
YubiKey lives in the server across the house. Do **not** try to hit the
public `sign.*` hostname from the laptop: mTLS may pass, but signerd will
correctly return 401 because you have no GitHub OIDC token. v1 deliberately
has no second public auth path.

Instead, ride SSH. signerd skips OIDC only when the peer *it sees* is
`127.0.0.1`/`::1`, and an SSH local forward makes that true: the daemon
accepts a connection from its own host's loopback, and your laptop talks to
its own `127.0.0.1`. Authentication is your SSH key to the box holding the
token.

```bash
# Terminal 1: forward laptop:8750 to the server's loopback bind.
ssh -N -L 8750:127.0.0.1:8750 user@nas.example

# Terminal 2: health first, then sign.
codesign -url http://127.0.0.1:8750 -health
codesign -url http://127.0.0.1:8750 -output app-signed.exe ./app.exe
# Or in place:
codesign -url http://127.0.0.1:8750 ./app.exe
```

No PIN on the laptop, no mTLS, no OIDC token.

## Docker bridge-mode caveat

If signerd runs in a bridge-network container with `127.0.0.1:8750:8750`
published (the compose example), connections through that published port
reach the daemon **from the Docker gateway address, not loopback**, so the
OIDC skip does not apply and you get 401.

Options:

1. **network_mode: host** for the signerd container, with
   `SIGNERD_LISTEN=127.0.0.1:8750`. The loopback bind is real, tunnels work,
   and nothing is exposed to the LAN. On unRAID this is often the simplest.
2. **docker exec fallback** — copy the file somewhere the container can see
   and sign from inside (the image ships the CLI):

   ```bash
   scp app.exe user@nas.example:/mnt/user/scratch/
   ssh user@nas.example docker exec signerd \
     codesign -url http://127.0.0.1:8750 /config/../scratch/app.exe   # adjust the mount
   scp user@nas.example:/mnt/user/scratch/app.exe ./app-signed.exe
   ```

   Works, but it is the fallback, not the happy path.

## Things not to do

- Do not point `CODESIGN_URL` at the public hostname from a laptop and then
  "fix" the 401 by weakening the server. The 401 is the design working.
- Do not publish signerd on `0.0.0.0` (LAN or internet). That removes the
  nginx mTLS gate for anyone who can reach the port. Non-loopback clients
  still need a valid OIDC token; loopback clients still skip OIDC. The
  failure mode is "mTLS gone, OIDC only", not a total bypass.
- Do not expect the laptop to reach the key with PKCS#11: the token is
  physically in the server; only signerd touches it.
