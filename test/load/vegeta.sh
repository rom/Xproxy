#!/bin/sh
# Constant rate load with vegeta against a running xproxy (see README.md).
# Usage: test/load/vegeta.sh [rate] [duration] [connections]
set -eu
RATE=${1:-5000}
DURATION=${2:-30s}
CONNS=${3:-64}
TARGET=${TARGET:-http://127.0.0.1:18080/}
echo "GET $TARGET" | vegeta attack -rate="$RATE" -duration="$DURATION" -connections="$CONNS" -max-workers="$CONNS" -keepalive=true -timeout=5s \
  | tee /tmp/xproxy-load/vegeta-"$RATE".bin | vegeta report
