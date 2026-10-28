#!/usr/bin/env bash
# Formats every Swift file in place with .swift-format.
set -euo pipefail
cd "$(dirname "$0")/.."
SWIFT=(swift); command -v xcrun >/dev/null && SWIFT=(xcrun swift)
"${SWIFT[@]}" format format --in-place --recursive Package.swift Sources Tests
