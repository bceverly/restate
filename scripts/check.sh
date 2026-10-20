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

# The hooks are copies, so editing .githooks/ changes nothing until they are
# installed again -- and a stale pre-push hook refuses what this records, at
# the end of a release, with the checks all passed. Whatever git would run is
# made to match what is in the tree before anything else.
STALE_HOOKS=()
if [ -d .git ]; then
  for hook in .githooks/*; do
    [ -f "$hook" ] || continue
    cmp -s "$hook" ".git/hooks/$(basename "$hook")" || STALE_HOOKS+=("$(basename "$hook")")
  done
  # And one of ours that .githooks/ no longer has, which git would still run.
  for hook in .git/hooks/*; do
    if [ -f "$hook" ] && [ ! -e ".githooks/$(basename "$hook")" ] &&
       grep -qF "# restate — installed by scripts/install-hooks.sh" "$hook" 2>/dev/null; then
      STALE_HOOKS+=("$(basename "$hook")")
    fi
  done
fi
if [ "${#STALE_HOOKS[@]}" -gt 0 ]; then
  printf '\n\033[1;95m■ the git hooks\033[0m\n'
  printf '  \033[93m!\033[0m not as .githooks/ has them: %s\n' "${STALE_HOOKS[*]}"
  scripts/install-hooks.sh || die "could not install the git hooks"
fi

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
