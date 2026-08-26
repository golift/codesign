# Windows host: run signerd next to the YubiKey

v1 still Authenticode-signs **PE/MSI**. This page is for operators who keep
the YubiKey in a Windows box and run `signerd.exe` there. GitHub Actions
callers stay on `ubuntu-latest` (or any runner); they POST to your public
URL the same way they would to a Linux daemon.

Do **not** run this in Docker Desktop or WSL. USB/PC/SC passthrough on those
stacks is unreliable. Run the native exe in a **logged-on user session**.

## Layout

| Path | What |
| --- | --- |
| `%ProgramData%\signerd\signerd.toml` | Daemon config (system default after the user config dir) |
| `%ProgramData%\signerd\chain.pem` | Full Authenticode chain (leaf + intermediates) |
| `%ProgramData%\signerd\pin` | PIV user PIN, one line. ACL it to the signing user. Never the PUK. |
| `%ProgramData%\signerd\client-ca.crt` | House/client CA the reverse proxy trusts (Caddy/nginx) |

User-level override: `%AppData%\signerd\signerd.toml`. Point at a file with
`signerd --config`.

Start from [examples/windows/signerd.toml.example](../examples/windows/signerd.toml.example).

## Tools

1. A JRE/JDK 17+ on `PATH`.
2. [jsign](https://ebourg.github.io/jsign/) so `jsign` is a command (Chocolatey,
   or a wrapper next to the jar).
3. [YubiKey Manager](https://www.yubico.com/products/yubikey-manager/) (`ykman`)
   for inventory and the health probe.
4. The YubiKey plugged into the same machine, PIN policy **Once** and touch
   **Never** so a headless daemon can sign. See [yubikey.md](yubikey.md).

`osslsigncode` + `libykcs11.dll` also works if you already have that stack.
jsign `--storetype PIV` is the happy path: it talks to the token over Windows
PC/SC and does not need the PKCS#11 DLL.

## Config

```toml
backend = "jsign"
store_type = "PIV"
alias = "AUTHENTICATION"
cert_file = 'C:\ProgramData\signerd\chain.pem'
pin_file = 'C:\ProgramData\signerd\pin'
health_command = ["ykman", "piv", "info"]
listen = "127.0.0.1:8750"
```

`AUTHENTICATION` is PIV slot **9A**. Use `SIGNATURE` / `9c` if that is where
your code-signing cert lives. `validateConfig` accepts `health_command` in
place of `pkcs11_module`.

Keep `allow_unauthenticated_loopback` **off** (the default) if Caddy or nginx
on this box proxies to loopback. Non-loopback peers still need GitHub OIDC.

## Run at logon, not as a Windows Service

Session 0 often cannot see the YubiKey over PC/SC. Same reason the macOS
example is a LaunchAgent, not a LaunchDaemon.

Import [examples/windows/signerd.task.xml](../examples/windows/signerd.task.xml)
(edit the `Command` / `--config` paths first):

```powershell
schtasks /create /tn signerd /xml C:\ProgramData\signerd\signerd.task.xml
```

The task uses **InteractiveToken** (run only when the user is logged on) and
restarts on failure. Autologon on a dedicated signing box is fine; a Service
Control Manager service running as LocalSystem is not.

Logs: Task Scheduler history, or redirect later if you wrap the exe.

## Reverse proxy (mTLS)

Public hostname, grey-cloud DNS, client certificates: [mtls.md](mtls.md) and
[nginx.md](nginx.md). On Windows, [Caddy](https://caddyserver.com/) is usually
easier than nginx-for-Windows. See
[examples/windows/Caddyfile.example](../examples/windows/Caddyfile.example).

Firewall: **443** (or whatever Caddy binds) from the Internet. **Never** 8750.
Bind signerd to loopback or a private address that only the proxy can reach.
Do not point the proxy at `http://127.0.0.1:8750` if you turn on
`allow_unauthenticated_loopback` — that combination skips OIDC for every
proxied request.

## Health

With the task running:

```powershell
codesign -url http://127.0.0.1:8750 -health
```

`ykman piv info` as `health_command` is healthy when it prints anything; it is
not a PKCS#11 cert listing, so the daemon does not require the
`Certificate Object` marker.

## Defender and SmartScreen

If Windows Defender locks a PE in the work dir mid-sign, exclude
`signerd`'s `work_dir` (or `%TEMP%\signerd-*`).

GitHub Releases Authenticode-sign `signerd.exe` / `codesign.exe` when the
publishing workflow has `CODESIGN_URL`. SmartScreen reputation can still lag
a new certificate.

## GitHub Action

Callers do not change. `uses: golift/codesign@v1` on `ubuntu-latest` with
`id-token: write` is the documented path. A `windows-latest` job can work
because the composite action uses `shell: bash`, but that is not the
supported runner.
