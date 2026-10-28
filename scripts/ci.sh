#!/usr/bin/env bash
# The full gate, as CI runs it: build, tests, swift-format lint, secret scan, exposeSecret audit.
#   scripts/ci.sh                # macOS host
#   scripts/ci.sh --platforms    # also build for iOS, tvOS, watchOS and visionOS (needs their SDKs)
# Writes build/ci-summary.md and exits non-zero if any step failed.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p build
STATUS=0
SWIFT=(swift); command -v xcrun >/dev/null && SWIFT=(xcrun swift)
SUMMARY=build/ci-summary.md
echo "# CI summary ($(date '+%Y-%m-%d %H:%M'), $("${SWIFT[@]}" --version 2>&1 | head -1))" > "$SUMMARY"

step() { # $1 label, $2 log, rest: command
  local label="$1" log="$2"; shift 2
  echo "▶ $label"
  if "$@" >"$log" 2>&1; then echo "- ✅ $label" >> "$SUMMARY"; else STATUS=1; echo "- ❌ $label (see $log)" >> "$SUMMARY"; fi
}

step "build" build/build.log "${SWIFT[@]}" build --build-tests
scripts/test.sh || STATUS=1
grep -E '^- ' build/test-summary.md >> "$SUMMARY"
step "swift-format lint" build/lint.log "${SWIFT[@]}" format lint --strict --recursive Package.swift Sources Tests
step "secret scan" build/secret-scan.log scripts/secret-scan.sh
step "exposeSecret audit" build/expose-audit.log scripts/expose-audit.sh

if [[ "${1:-}" == "--platforms" ]]; then
  for platform in iOS tvOS watchOS visionOS; do
    step "build $platform" "build/build-$platform.log" xcodebuild build -scheme swift-keychain-Package \
      -destination "generic/platform=$platform" -derivedDataPath build/DerivedData -skipMacroValidation
  done
fi

cat "$SUMMARY"
exit $STATUS
