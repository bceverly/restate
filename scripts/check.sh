#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Everything a push has to have passed, each run unless it has already
# passed on exactly this content.
#
#   make check
#
#   make test       the unit and end-to-end tests, the sanitizers and
#                   valgrind, and the coverage gate
#   make lint       the compiler, the analyzers, the house style, ...
#   make security   the security scan
#
# Test first: it rewrites the coverage badge when the coverage has moved, and
# lint reads the badge's directory with the rest. Each records its passing
# (scripts/passed.sh) -- strictly, nothing skipped -- and one run by hand
# earlier counts, so this runs only what has not passed on the files as they
# are. The pre-push hook holds a push to the same three records, compared
# with the commit being pushed; it runs nothing itself, since git holds the
# connection to the remote open while it runs and GitHub drops it long before
# these are done.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

die() { printf '\n\033[91m✗ %s\033[0m\n\n' "$*" >&2; exit 1; }

git rev-parse --git-dir > /dev/null 2>&1 || die "make check records what passed with git: this is not a git repository"
START=$SECONDS
RAN=()

for phase in test lint security; do
  printf '\n\033[1;95m■ make %s\033[0m\n' "$phase"
  if scripts/passed.sh --fresh "$phase"; then
    printf '  \033[92m✓\033[0m passed already, on exactly these files: not run again\n'
    continue
  fi
  # Standard input is /dev/null: `restate diff -` reads it, and no test
  # should be able to read whatever this was started with.
  make --no-print-directory "$phase" < /dev/null || die "make $phase failed"
  scripts/passed.sh --fresh "$phase" ||
    die "make $phase passed, but is not recorded as passing (said just above why)"
  RAN+=("$phase")
done

printf '\n\033[92m✓ test, lint and security have passed on these files'
if [ "${#RAN[@]}" -gt 0 ]; then
  printf ' (ran %s, in %d min)' "${RAN[*]}" $(((SECONDS - START + 59) / 60))
fi
printf '\033[0m\n  \033[2mthe pre-push hook lets through a commit of exactly them\033[0m\n\n'
