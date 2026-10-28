#!/usr/bin/env bash
# Fails if a tracked file looks like it contains a credential.
set -uo pipefail
cd "$(dirname "$0")/.."
PATTERNS='(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|sk-[A-Za-z0-9_-]{32,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)'
HITS=$(git ls-files -z | xargs -0 grep -nIE "$PATTERNS" -- 2>/dev/null || true)
if [[ -n "$HITS" ]]; then echo "$HITS"; exit 1; fi
echo "no secrets found"
