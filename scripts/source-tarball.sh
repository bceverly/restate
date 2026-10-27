#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# A source tarball of this tree as it is, for a package built by hand:
#
#   scripts/source-tarball.sh OUT.tar.gz
#
# restate-VERSION/ and everything in the tree but what a build, a test or a
# package left in it -- the same set .gitignore keeps out of the repository.
# The release workflow makes its own with git archive, which is exactly the
# tag; this is the tree in front of you, edits and all, so `make rpm` and
# `make apk` build what is being worked on.
set -eu

OUT="${1:?usage: source-tarball.sh OUT.tar.gz}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$REPO_ROOT/VERSION")"
case "$OUT" in
  /*) ;;
  *) OUT="$PWD/$OUT" ;;
esac
WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-tarball.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

mkdir "$WORK/restate-$VERSION"
( cd "$REPO_ROOT" &&
  tar -cf - \
    --exclude=./.git --exclude=./bin --exclude=./obj --exclude=./dist --exclude=./pkg-stage \
    --exclude=./.coverage --exclude=./.lint --exclude='./.sanitize*' --exclude=./.passed \
    --exclude=./.fuzz --exclude=./.security-reports --exclude=./.cache \
    --exclude=./debian/restate --exclude=./debian/.debhelper --exclude=./debian/changelog \
    --exclude='*.o' --exclude='*.gcno' --exclude='*.gcda' --exclude='*.deb' --exclude='*.rpm' \
    --exclude='*.apk' --exclude='restate-test.*' --exclude='restate-cli.*' . ) |
  ( cd "$WORK/restate-$VERSION" && tar -xf - )
( cd "$WORK" && tar -cf - "restate-$VERSION" ) | gzip -9n > "$OUT"
