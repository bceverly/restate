#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Fail if man/restate-proxy.8 leaves out an option restate-proxy's --help
# lists. The page is written by hand, as restate's is not: this is what keeps
# it from falling behind an option added later.
#
#   scripts/check-proxy-man.sh BINARY [PAGE]
set -eu

BIN="${1:?usage: check-proxy-man.sh BINARY [PAGE]}"
PAGE="${2:-man/restate-proxy.8}"

[ -x "$BIN" ] || { echo "check-proxy-man.sh: $BIN is not executable" >&2; exit 1; }
[ -f "$PAGE" ] || { echo "check-proxy-man.sh: no $PAGE" >&2; exit 1; }

missing=""
# Every --option the help names, once; in the page, troff writes each
# hyphen as \-.
for opt in $("$BIN" --help | sed -n 's/.*\(--[a-z][a-z-]*\).*/\1/p' | sort -u); do
  troff="$(printf '%s' "$opt" | sed 's/-/\\\\-/g')"
  grep -q -- "$troff" "$PAGE" || missing="$missing $opt"
done
if [ -n "$missing" ]; then
  echo "$PAGE does not document:$missing" >&2
  exit 1
fi
printf '  \033[92m✓\033[0m %s documents every option of %s\n' "$PAGE" "$BIN"
