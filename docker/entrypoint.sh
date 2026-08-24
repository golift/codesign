#!/usr/bin/env bash
# Start pcscd, wait for it to come up, then run signerd as an unprivileged
# user. PID 1 waits on both children so a dead pcscd (or signerd) exits the
# container and the restart policy can recover. One pcscd owns the token;
# never run a second one (in the container or on the host).
set -euo pipefail

if [ -z "${SIGNERD_PKCS11_MODULE:-}" ] || [ ! -e "${SIGNERD_PKCS11_MODULE}" ]; then
  found="$(dpkg -L ykcs11 2>/dev/null | grep -m1 'libykcs11\.so$' || true)"
  if [ -n "${found}" ]; then
    export SIGNERD_PKCS11_MODULE="${found}"
  fi
fi

if ! command -v setpriv >/dev/null || ! getent passwd signerd >/dev/null; then
  echo "FATAL: cannot drop privileges (need setpriv and a signerd user)" >&2
  exit 1
fi

# Compose file secrets keep the host UID and mode. Copy so the unprivileged
# daemon can read the PIN after we drop root.
if [ -n "${SIGNERD_PIN_FILE:-}" ] && [ -e "${SIGNERD_PIN_FILE}" ]; then
  mkdir -p /run/signerd
  install -m 0400 -o signerd -g signerd "${SIGNERD_PIN_FILE}" /run/signerd/pin
  export SIGNERD_PIN_FILE=/run/signerd/pin
fi

pcscd --foreground &
pcscd_pid=$!

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

setpriv --reuid=signerd --regid=signerd --init-groups --inh-caps=-all -- \
  /usr/local/bin/signerd "$@" &
signerd_pid=$!

term() {
  kill -TERM "$signerd_pid" "$pcscd_pid" 2>/dev/null || true
}
trap term TERM INT

# Exit when either child dies so Docker can restart the container.
wait -n "$pcscd_pid" "$signerd_pid"
status=$?
term
wait || true
exit "$status"
