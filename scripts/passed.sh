#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Runs one of the checks, and records that it passed -- on what.
#
#   scripts/passed.sh PHASE COMMAND...            run it (make lint, test, security)
#   scripts/passed.sh --fresh PHASE               has it passed on the working tree?
#   scripts/passed.sh --fresh --tree TREE PHASE   ... on a commit's tree?
#
# The record is .passed/PHASE, ignored by git: the key of the content the
# check read (scripts/tree-id.sh), written only when the check succeeded with
# nothing skipped -- a tool that is not installed passes by doing nothing,
# which proves nothing -- and only if that content did not change while it
# ran. It is deleted before the check starts, so a run that fails, or is
# stopped, leaves no record of an earlier pass behind it.
#
# So a check run by hand counts: the hooks and `make check` do not run again
# what has passed on exactly this content. Outside a git repository -- a
# release tarball -- the check runs and nothing is recorded.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

DIR=".passed"

if [ "${1:-}" = "--fresh" ]; then
  shift
  key="$(scripts/tree-id.sh "$@" 2> /dev/null)" || exit 1
  phase="${!#}"
  [ -n "$key" ] && [ "$(cat "$DIR/$phase" 2> /dev/null)" = "$key" ]
  exit
fi

PHASE="${1:?usage: passed.sh PHASE COMMAND...}"
shift
mkdir -p "$DIR"
rm -f "$DIR/$PHASE"
KEY="$(scripts/tree-id.sh "$PHASE" 2> /dev/null)" || KEY=""

"$@" 2>&1 | tee "$DIR/$PHASE.log"
STATUS=${PIPESTATUS[0]}

if [ "$STATUS" -eq 0 ] && [ -n "$KEY" ]; then
  if grep -q 'Skipped:' "$DIR/$PHASE.log"; then
    printf '  \033[2mnot recorded as passed: a tool was skipped (make install-dev)\033[0m\n'
  elif [ "$(scripts/tree-id.sh "$PHASE" 2> /dev/null)" != "$KEY" ]; then
    printf '  \033[2mnot recorded as passed: the files changed while it ran\033[0m\n'
  else
    printf '%s\n' "$KEY" > "$DIR/$PHASE"
  fi
fi
exit "$STATUS"
