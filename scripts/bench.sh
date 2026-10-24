#!/usr/bin/env bash
# Parser throughput on synthetic data (release build). Usage: scripts/bench.sh [records] [rounds]
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="${CARGO_TARGET_DIR:-target}/release/timeliner"
N="${1:-500000}"
ROUNDS="${2:-3}"
echo "machine: $(uname -sm), $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?') logical CPUs; single-threaded parse per stage"
"$BIN" bench --lines "$N" --rounds "$ROUNDS"
echo
echo "end-to-end: build of the committed fixture (14 artifacts, all threads)"
TIMEFORMAT='  wall time: %R s'
time "$BIN" build fixtures/incident/evidence -o /dev/null
