#!/usr/bin/env bash
# Every exposeSecret() call in Sources/ is a place a secret leaves its wrapper. This script compares them
# with scripts/expose-allowlist.txt ("<file>: <count>" per file) and fails on any difference, so a new
# call site shows up in the PR diff of the allowlist, in front of the reviewer.
#   scripts/expose-audit.sh            # check
#   scripts/expose-audit.sh --update   # rewrite the allowlist from the sources
set -uo pipefail
cd "$(dirname "$0")/.."
ALLOWLIST=scripts/expose-allowlist.txt
# Count calls, not the declaration or doc comments.
CURRENT=$(grep -rnE '\.exposeSecret\(\)' Sources --include='*.swift' | grep -vE '^\S+:[0-9]+:\s*///' |
  cut -d: -f1 | sort | uniq -c | awk '{ print $2 ": " $1 }')
if [[ "${1:-}" == "--update" ]]; then
  echo "$CURRENT" > "$ALLOWLIST"
  echo "updated $ALLOWLIST"
  exit 0
fi
if ! diff -u "$ALLOWLIST" <(echo "$CURRENT"); then
  echo "exposeSecret() call sites changed. Review each new one, then run scripts/expose-audit.sh --update."
  exit 1
fi
echo "$(echo "$CURRENT" | awk -F': ' '{ n += $2 } END { print n }') exposeSecret() call sites, all reviewed"
