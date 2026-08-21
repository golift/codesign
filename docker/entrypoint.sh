#!/usr/bin/env bash
# Start pcscd, wait for it to come up, then run signerd. One pcscd owns the
# token; never run a second one (in the container or on the host).
set -e

pcscd --foreground &

# Give pcscd a moment to enumerate the CCID reader.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -S /run/pcscd/pcscd.comm ] && break
  sleep 0.5
done

exec /usr/local/bin/signerd "$@"
