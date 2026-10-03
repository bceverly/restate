#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Keep the README's "## Usage" block equal to what `restate --help` prints.
#
#   scripts/gen-readme-usage.sh BINARY README.md          rewrite the block
#   scripts/gen-readme-usage.sh --check BINARY README.md  fail if it is stale
#
# The manpage is generated from --help, and so is this. A usage block pasted by
# hand documents the program as it was on the day somebody last remembered to
# paste it; `make lint` runs the --check mode so that day is always today.
#
# Only the usage line, the description, the commands and the options are taken.
# The exit statuses and the examples have their own prose sections in the
# README, and a second copy of them there would be one more thing to drift.
set -euo pipefail

CHECK=0
if [ "${1:-}" = "--check" ]; then
  CHECK=1
  shift
fi

BINARY="${1:?usage: gen-readme-usage.sh [--check] BINARY README}"
README="${2:?usage: gen-readme-usage.sh [--check] BINARY README}"

# From "Usage:" down to (but not including) the exit statuses. The version
# banner above it is deliberately dropped: it would go stale on every release
# and says nothing the README does not already say.
BLOCK="$("$BINARY" --help | awk '
  /^Usage:/        { on = 1 }
  /^Exit status:/  { on = 0 }
  on               { print }
' | sed -e 's/[[:space:]]*$//')"
# Trim the blank lines awk leaves at the end.
BLOCK="$(printf '%s\n' "$BLOCK" | sed -e :a -e '/^$/{$d;N;ba' -e '}')"

WORK="$(mktemp)"
trap 'rm -f "$WORK"' EXIT

# Replace the first fenced block after the "## Usage" heading, leaving every
# other line of the README exactly as it was.
BLOCK="$BLOCK" awk '
  BEGIN { state = 0 }
  state == 0 { print; if ($0 ~ /^## Usage$/) { state = 1 } ; next }
  state == 1 { print; if ($0 ~ /^```/) { print ENVIRON["BLOCK"]; state = 2 } ; next }
  state == 2 { if ($0 ~ /^```/) { print; state = 3 } ; next }
  { print }
' "$README" > "$WORK"

if [ "$CHECK" = "1" ]; then
  if cmp -s "$WORK" "$README"; then
    exit 0
  fi
  echo "The README's Usage block does not match '$BINARY --help'."
  echo "Regenerate it with:"
  echo "  scripts/gen-readme-usage.sh $BINARY $README"
  exit 1
fi

cat "$WORK" > "$README"
