#!/usr/bin/env bash
# Offline end-to-end demo on the committed synthetic incident.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="${CARGO_TARGET_DIR:-target}/release/timeliner"
EVIDENCE=fixtures/incident/evidence
OUT=out/demo
mkdir -p "$OUT"

echo "== 1. Artifacts recognized in the evidence tree"
"$BIN" detect "$EVIDENCE"

echo
echo "== 2. Build the super-timeline (zone from the evidence's own /etc/localtime)"
"$BIN" build "$EVIDENCE" --summary -o "$OUT/timeline.jsonl"
"$BIN" build "$EVIDENCE" -o "$OUT/timeline.csv"
"$BIN" build "$EVIDENCE" -o "$OUT/timeline.l2t.csv"
"$BIN" build "$EVIDENCE" -o "$OUT/report.html" --title "web01 intrusion timeline"
wc -l "$OUT/timeline.jsonl" "$OUT/timeline.csv" "$OUT/timeline.l2t.csv" | sed 's/^/   /'
ls -l "$OUT/report.html" | awk '{print "   " $5 " bytes  " $9}'

echo
echo "== 3. Flagged events (rule hits only) from 2025-01-01T04:00Z (23:00 EST on Dec 31)"
"$BIN" build "$EVIDENCE" --only-tagged --from 2025-01-01T04:00:00Z -f text

echo
echo "== 4. Ground-truth check: every story step found, tagged and in order"
"$BIN" verify --truth fixtures/incident/GROUND_TRUTH.json "$EVIDENCE"

echo
echo "== 5. Negative control: ignore the evidence zone (--tz UTC)"
"$BIN" verify --truth fixtures/incident/GROUND_TRUTH.json "$EVIDENCE" --tz UTC | tail -1 || true

echo
echo "Outputs in $OUT/ (open report.html in a browser)."
