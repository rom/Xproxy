#!/bin/sh
# Soak: run a moderate constant load for a long time and sample the
# process every minute from /metrics on the management socket. A leak
# shows as heap or goroutines rising without bound; descriptors should
# plateau at the idle connection count.
# Usage: test/load/soak.sh [hours] [rate]
set -eu
HOURS=${1:-24}
RATE=${2:-2000}
SOCK=${SOCK:-/tmp/xproxy-load/mgmt.sock}
OUT=${OUT:-/tmp/xproxy-load/soak.csv}
echo "time,heap_bytes,sys_bytes,goroutines,open_fds,requests,open_connections" > "$OUT"
end=$(( $(date +%s) + HOURS * 3600 ))
(
  while [ "$(date +%s)" -lt "$end" ]; do
    echo "GET ${TARGET:-http://127.0.0.1:18080/}" | vegeta attack -rate="$RATE" -duration=60s -connections=64 -keepalive=true -timeout=5s > /dev/null
  done
) &
LOAD=$!
while [ "$(date +%s)" -lt "$end" ]; do
  m=$(curl -s --unix-socket "$SOCK" http://xproxy/metrics)
  get() { echo "$m" | awk -v k="$1" '$1==k {print $2; exit}'; }
  echo "$(date -u +%FT%TZ),$(get go_memstats_heap_alloc_bytes),$(get go_memstats_sys_bytes),$(get go_goroutines),$(get process_open_fds),$(get xproxy_requests_total),$(get xproxy_connections_open)" >> "$OUT"
  sleep 60
done
wait $LOAD
echo "samples in $OUT"
