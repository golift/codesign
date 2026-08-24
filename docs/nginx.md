# nginx / SWAG deployment notes

`examples/nginx/sign.conf` is written for a
[SWAG](https://docs.linuxserver.io/general/swag/) (linuxserver.io) setup with
a wildcard certificate, but any nginx works — replace the `include` lines
with your own ssl/proxy boilerplate.

## Checklist

1. Copy `examples/nginx/sign.conf` to your site-confs directory as `codesign.conf`
   (SWAG: `/config/nginx/site-confs/`).
2. Put your client CA at `/config/keys/client-ca.crt` (see mtls.md).
3. The example sets `$codesign` **inline** to the Docker-network hostname.
   Edit that one line in `examples/nginx/sign.conf` for your deploy. If you prefer a
   gitignored variables file, delete the inline `set` (a later `set` wins,
   so leaving both is confusing):

   ```nginx
   set $codesign http://signerd:8750;
   ```

   With Docker, `signerd` resolves over the shared Docker network; SWAG's
   `resolver.conf` handles container DNS.

   > **Never use a loopback upstream** such as `http://127.0.0.1:8750`.
   > Loopback OIDC skip is off by default, but if an operator enables
   > `allow_unauthenticated_loopback`, nginx proxying from loopback would
   > give every proxied request that free pass. Without Docker, bind signerd
   > to a private non-loopback address (a dedicated bridge or the host's LAN
   > IP firewalled to nginx) so the daemon sees a non-loopback peer and
   > demands OIDC.

4. Reload nginx and verify the gates:

   ```bash
   # No client cert: must fail the handshake or return 400.
   curl -i https://sign.example.com/health
   # With the client cert: 200 from signerd.
   curl -i --cert client.crt --key client.key https://sign.example.com/health
   # Signing without OIDC through the proxy: 401 (this is correct!).
   curl -i --cert client.crt --key client.key -X POST \
     --data-binary @some.exe https://sign.example.com/v1/sign
   ```

## Cloudflare: grey cloud only

`sign.example.com` must be **DNS-only** (grey cloud). Proxied (orange cloud)
records terminate TLS on Cloudflare's edge with Cloudflare's certificate, so
your `ssl_verify_client` never sees the real client certificate.
Bring-your-own-CA mTLS on Cloudflare is an Enterprise feature; this design
does not depend on it.

## Sizing

- `client_max_body_size` must be at least signerd's `max_body_mib`.
- Signing waits on the token plus the RFC 3161 timestamp server; keep
  `proxy_read_timeout` generous (the example uses 300s).
- `proxy_request_buffering off` streams the upload instead of spooling it to
  disk twice.
