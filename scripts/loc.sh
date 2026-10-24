#!/usr/bin/env bash
# Counts source lines: non-test code in src/ (everything before the first
# `#[cfg(test)]` of each file), inline unit tests, integration tests, rules.
set -euo pipefail
cd "$(dirname "$0")/.."
code=0; unit=0
for f in $(find src -name '*.rs' | sort); do
  total=$(wc -l < "$f")
  cut=$(grep -n '^#\[cfg(test)\]' "$f" | head -1 | cut -d: -f1 || true)
  if [ -n "$cut" ]; then
    c=$((cut - 1)); code=$((code + c)); unit=$((unit + total - c))
  else
    code=$((code + total))
  fi
done
integ=$(cat tests/*.rs | wc -l)
rules=$(wc -l < rules/default.yml)
printf 'src (non-test):        %6d lines\n' "$code"
printf 'src inline unit tests: %6d lines\n' "$unit"
printf 'tests/ (integration):  %6d lines\n' "$integ"
printf 'rules/default.yml:     %6d lines\n' "$rules"
