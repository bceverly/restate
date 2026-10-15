#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Everything a push has to have passed, run once, on the working tree.
#
#   make check
#
#   1. make lint       unless the pre-commit hook passed it on this very tree
#   2. make test       the unit and end-to-end tests, the sanitizers and
#                      valgrind, and the coverage gate
#   3. make security   but for its sanitizers' run, which make test has just
#                      made
#
# Strictly: a tool that is not installed is a failure here, not a skip. Every
# script in this project skips what it cannot find, which keeps a fresh
# checkout usable and lets a clean run prove nothing; before a push, nothing
# is let off. `make install-dev` installs them all.
#
# On success it records the tree it passed on (scripts/tree-id.sh), and the
# pre-push hook lets through a commit with that tree and no other. So the
# order is free -- check, then commit; or commit, then check -- but what is
# pushed is what was checked, to the byte, however it was committed. The hook
# itself runs nothing long: git holds the connection to the remote open while
# a pre-push hook runs, and GitHub drops it long before this is done.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

die() { printf '\n\033[91m✗ %s\033[0m\n\n' "$*" >&2; exit 1; }

GIT_DIR="$(git rev-parse --absolute-git-dir 2> /dev/null)" || die "not a git repository"
LINTED="$GIT_DIR/restate-linted"
CHECKED="$GIT_DIR/restate-checked"
LOGS=".check"
START=$SECONDS

TREE="$(scripts/tree-id.sh)" || die "could not name the working tree (scripts/tree-id.sh)"
mkdir -p "$LOGS"
rm -f "$CHECKED"

printf '\n\033[1mcheck\033[0m \033[2m(tree %s)\033[0m\n' "${TREE:0:12}"

# Runs `make TARGET`, its output shown as it comes and kept, and fails on a
# failure or on a skip. Standard input is /dev/null: `restate diff -` reads it,
# and no test should be able to read whatever this was started with.
run() {
  local target="$1" log="$LOGS/$1.log" status
  shift
  printf '\n\033[1;95m■ make %s\033[0m\n' "$target"
  env "$@" make --no-print-directory "$target" < /dev/null 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  [ "$status" -eq 0 ] || die "make $target failed: not checked"
  if grep -q 'Skipped:' "$log"; then
    die "make $target passed, but skipped a tool, which proves nothing: make install-dev"
  fi
}

if [ "$(cat "$LINTED" 2> /dev/null)" = "$TREE" ]; then
  printf '\n\033[1;95m■ make lint\033[0m\n  \033[92m✓\033[0m passed at commit on this very tree: not run again\n'
else
  run lint
  printf '%s\n' "$TREE" > "$LINTED"
fi
run test
run security RESTATE_SECURITY_SKIP_MEMCHECK=1

# An edit made while all that ran is not what was checked. Nor is a file the
# run itself rewrote -- the coverage badge, when the coverage has moved --
# which wants committing, and checking with the rest.
AFTER="$(scripts/tree-id.sh)" || die "could not name the working tree (scripts/tree-id.sh)"
if [ "$AFTER" != "$TREE" ]; then
  printf '\n  the working tree changed while it was being checked:\n' >&2
  git diff-tree -r --name-only "$TREE" "$AFTER" | sed 's/^/      /' >&2
  die "not what was checked: run make check again"
fi
printf '%s\n' "$TREE" > "$CHECKED"

printf '\n\033[92m✓ checked in %d min: lint, tests, sanitizers, valgrind, coverage and the security scan\033[0m\n' \
  $(((SECONDS - START + 59) / 60))
printf '  \033[2mthe pre-push hook will let through a commit of exactly this tree\033[0m\n\n'
