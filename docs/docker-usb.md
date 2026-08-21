# USB passthrough for signerd in Docker (including unRAID)

The container image runs its own `pcscd`. Two rules keep this sane:

1. **One pcscd owns the token.** If the host runs pcscd (or another
   container does), the two fight over exclusive PC/SC access. Pick one.
2. **Pass only the YubiKey**, never a whole bus or `/dev/bus/usb`.

## Find the device

Yubico's USB vendor ID is `1050`:

```bash
lsusb -d 1050:
# Bus 001 Device 004: ID 1050:0407 Yubico.com Yubikey 4/5 OTP+U2F+CCID
```

That maps to `/dev/bus/usb/001/004`. Pass it through:

```yaml
devices:
  - /dev/bus/usb/001/004
```

or on `docker run` / unRAID **Extra Parameters**:

```text
--device=/dev/bus/usb/001/004
```

## Bus/device numbers are not stable

They change on reboot and replug. Options, most robust first:

- **udev rule** (host) creating a stable symlink, then pass the symlink:

  ```text
  # /etc/udev/rules.d/99-yubikey.rules
  SUBSYSTEM=="usb", ATTR{idVendor}=="1050", SYMLINK+="yubikey", MODE="0660"
  ```

- Re-check `lsusb -d 1050:` after every reboot and update the device path
  (acceptable on unRAID where the array restarts rarely; script it into the
  container's pre-start if you like).

## unRAID warnings

- The unRAID **boot flash is a USB device on the same bus**. Passing a whole
  bus or running the container privileged risks handing your boot stick to a
  container. Use `--device` with the specific YubiKey path only.
- Privileged mode is a last resort; the CCID interface works fine with a
  plain `--device` grant.

## Verifying from inside the container

```bash
docker exec signerd sh -c 'pcsc_scan -r 2>/dev/null || echo no pcsc_scan; ls /run/pcscd'
docker exec signerd osslsigncode --version
curl -fsS http://127.0.0.1:8750/health   # from the host loopback publish
```

`GET /health` fails when pcscd is up but the token is unplugged — wire that
into unRAID or Home Assistant monitoring so a dead CI run tells you why.
