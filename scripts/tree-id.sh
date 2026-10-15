#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Prints the git tree ID of the working tree as it stands -- every file git
# would commit with `git add -A`, edited or new, and nothing it ignores.
#
#   scripts/tree-id.sh
#
# A commit made from that working tree has exactly that tree, so the ID is
# what ties a check to what is pushed: `make check` records the tree it
# passed on, and the pre-push hook lets through a commit whose tree it is,
# and nothing else. Done in an index of its own, so the real one -- what is
# staged -- is left alone; the files are hashed into git's object store, which
# `git gc` clears of what nothing ends up using.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# A name, not a file: git writes the index itself, and takes an empty file
# there for a broken one.
INDEX="$(mktemp "${TMPDIR:-/tmp}/restate-index.XXXXXX")"
rm -f "$INDEX"
trap 'rm -f "$INDEX"' EXIT

# From HEAD, so a file committed although a pattern in .gitignore matches it
# is still counted, as a commit would keep it; a repository with no commits
# yet starts from nothing.
GIT_INDEX_FILE="$INDEX" git read-tree HEAD 2> /dev/null || rm -f "$INDEX"
GIT_INDEX_FILE="$INDEX" git add -A .
GIT_INDEX_FILE="$INDEX" git write-tree
