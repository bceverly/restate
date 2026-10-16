#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Prints the key of what one of the checks reads: a git object ID that
# changes exactly when the content of a file it covers does.
#
#   scripts/tree-id.sh PHASE                the working tree, as it stands
#   scripts/tree-id.sh --tree TREE PHASE    a commit's tree (the pre-push hook)
#
#   lint, security   every file git would commit: the docs are linted (their
#                    spelling, the manpage's freshness), and gitleaks reads
#                    them all
#   test             all of it but the prose, which no test reads: an edit to
#                    the README does not make the tests' passing stale
#
# The working tree is named as a commit made from it with `git add -A` would
# be -- edited files and new ones, nothing ignored -- in an index of its own,
# so what is staged is left alone. Content, not timestamps: a file touched,
# or edited and put back, is the same file; one checked out with an old date
# is not mistaken for the one that passed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TREE=""
if [ "${1:-}" = "--tree" ]; then
  TREE="${2:?usage: tree-id.sh [--tree TREE] lint|test|security}"
  shift 2
fi
PHASE="${1:?usage: tree-id.sh [--tree TREE] lint|test|security}"

# A name, not a file: git writes the index itself, and takes an empty file
# there for a broken one.
INDEX="$(mktemp "${TMPDIR:-/tmp}/restate-index.XXXXXX")"
rm -f "$INDEX"
trap 'rm -f "$INDEX"' EXIT
export GIT_INDEX_FILE="$INDEX"

if [ -n "$TREE" ]; then
  git read-tree "$TREE"
else
  # From HEAD, so a file committed although a pattern in .gitignore matches
  # it is still counted, as a commit would keep it; a repository with no
  # commits yet starts from nothing.
  git read-tree HEAD 2> /dev/null || rm -f "$INDEX"
  git add -A .
fi

# The version number does not count. A release writes the next one into
# VERSION and the manpage's .TH line, then runs the checks: counted, it would
# make stale every check already passed on the tree being released, and each
# release would run them all again. Left out only while the two agree, so a
# manpage not regenerated after VERSION changed is still a change, which lint
# then finds. The .TH line's date goes with it: the release regenerates the
# page, and the date is not something any check reads.
plain() {
  local path="$1" mode
  mode="$(git ls-files -s -- "$path" | awk '{print $1}')"
  git update-index --cacheinfo "$mode,$(git hash-object --stdin),$path"
}
VERSION_NOW="$(git cat-file blob :VERSION 2> /dev/null)" || VERSION_NOW=""
TH_VERSION="$(git cat-file blob :man/restate.8 2> /dev/null |
              sed -n 's/^\.TH RESTATE 8 "[^"]*" "restate \([^"]*\)".*/\1/p' | head -1)" || TH_VERSION=""
if [ -n "$VERSION_NOW" ] && [ "$TH_VERSION" = "$VERSION_NOW" ]; then
  echo - | plain VERSION
  git cat-file blob :man/restate.8 |
    sed 's/^\(\.TH RESTATE 8\) "[^"]*" "restate [^"]*"/\1 "-" "restate -"/' |
    plain man/restate.8
fi
TREE="$(git write-tree --missing-ok)"

case "$PHASE" in
  lint | security)
    git rev-parse --verify --quiet "$TREE^{tree}"
    ;;
  test)
    # The tree's top level less the prose, hashed: what is left is named by
    # its own IDs, so the key still follows every byte beneath it.
    git ls-tree "$TREE" |
      grep -Ev $'\t''([^/]*\.md|docs|\.github|debian|LICENSE)$' |
      git hash-object --stdin
    ;;
  *)
    echo "tree-id.sh: no phase called $PHASE (lint, test, security)" >&2
    exit 2
    ;;
esac
