#!/usr/bin/env bash
# Start pcscd, wait for it to come up, then run signerd. One pcscd owns the
# token; never run a second one (in the container or on the host).
set -euo pipefail

if [ -z "${SIGNERD_PKCS11_MODULE:-}" ] || [ ! -e "${SIGNERD_PKCS11_MODULE}" ]; then
  found="$(dpkg -L ykcs11 2>/dev/null | grep -m1 'libykcs11\.so$' || true)"
  if [ -n "${found}" ]; then
    export SIGNERD_PKCS11_MODULE="${found}"
  fi
fi

pcscd --foreground &

# Wait for pcscd to enumerate the CCID reader. Without its socket every sign
# request would fail with a confusing PKCS#11 error, so refuse to start.
for _ in $(seq 1 20); do
  [ -S /run/pcscd/pcscd.comm ] && break
  sleep 0.5
done

if [ ! -S /run/pcscd/pcscd.comm ]; then
  echo "FATAL: pcscd socket never appeared at /run/pcscd/pcscd.comm" >&2
  exit 1
fi

exec /usr/local/bin/signerd "$@"
