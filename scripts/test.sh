#!/usr/bin/env bash
# Runs the package tests and writes a short summary to build/test-summary.md.
#   scripts/test.sh                      # every test
#   scripts/test.sh KeychainTests        # a test target, suite or test (swift test --filter)
# Set SKIP_LIVE_KEYCHAIN_TESTS=1 to skip the tests that touch the real keychain.
# Uses Xcode's toolchain on macOS (xcrun): a bare `swift` may be swiftly's.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p build
SWIFT=(swift); command -v xcrun >/dev/null && SWIFT=(xcrun swift)
FILTER="${1:-}"
LOG="build/test${FILTER:+-$FILTER}.log"
SUMMARY=build/test-summary.md

# A short digest of a failing log: xcsift (https://github.com/ldomaradzki/xcsift) when installed, else grep.
digest() {
  if command -v xcsift >/dev/null; then
    xcsift --format toon < "$1" 2>/dev/null | head -40 | sed 's/^/    /'
  else
    grep -E "error:|✘|failed" "$1" | head -20 | sed 's/^/    /'
  fi
}

# Swift Testing prints one "Test run with N tests …" line per test bundle; report each.
totals() {
  grep -Eo 'Test run with [0-9]+ tests? in [0-9]+ suites? passed' "$1" | sed 's/^Test run with //' | paste -sd ',' - |
    sed 's/,/, /g'
}

echo "▶ ${SWIFT[*]} test${FILTER:+ --filter $FILTER}"
echo "# Test summary ($(date '+%Y-%m-%d %H:%M'), $("${SWIFT[@]}" --version 2>&1 | head -1))" > "$SUMMARY"
if "${SWIFT[@]}" test ${FILTER:+--filter "$FILTER"} >"$LOG" 2>&1; then
  echo "- ✅ tests${FILTER:+ \`$FILTER\`} — $(totals "$LOG")" >> "$SUMMARY"
  STATUS=0
else
  echo "- ❌ tests${FILTER:+ \`$FILTER\`} — see $LOG" >> "$SUMMARY"
  digest "$LOG" >> "$SUMMARY"
  STATUS=1
fi
cat "$SUMMARY"
exit $STATUS
