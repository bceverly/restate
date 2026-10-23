#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Install a BSD package make bsd-pkg built, with the system's own tool, check
# what it put there, and remove it -- as a person installing it from the
# release would, on a machine with no restate on it already:
#
#   scripts/verify-bsd-pkg.sh PACKAGE
#
# Run as root (sudo or doas). It refuses a machine that has restate under
# /usr/local already, since removing the package would take that one too.
set -eu

PKG="${1:?usage: verify-bsd-pkg.sh PACKAGE}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$REPO_ROOT/VERSION")"
PREFIX=/usr/local
HOOKS="$PREFIX/libexec/restate/hooks"

ok()  { printf '  \033[92m✓\033[0m %s\n' "$*"; }
die() { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root: the package is installed and removed"
[ -f "$PKG" ] || die "no such package: $PKG"
case "$PKG" in
  /*) ;;
  *) PKG="$PWD/$PKG" ;;
esac
[ ! -e "$PREFIX/sbin/restate" ] || die "$PREFIX/sbin/restate is there already"

case "$(uname -s)" in
FreeBSD)
  pkg add "$PKG"
  remove() { pkg delete -y restate; }
  mandir="$PREFIX/share/man"
  ;;
OpenBSD)
  # Not signed by OpenBSD's means: the release's checksums and attestation
  # are what vouch for it.
  pkg_add -D unsigned "$PKG"
  remove() { pkg_delete restate; }
  mandir="$PREFIX/man"
  ;;
NetBSD)
  pkg_add "$PKG"
  remove() { pkg_delete restate; }
  mandir="$PREFIX/man"
  ;;
*)
  die "not a BSD: $(uname -s)"
  ;;
esac

# Exactly VERSION from a release's tarball; VERSION-dev from a checkout.
got="$("$PREFIX/sbin/restate" --version | head -n 1)"
case "$got" in
  "restate $VERSION" | "restate $VERSION-dev") ;;
  *) die "installed restate says \"$got\", not restate $VERSION" ;;
esac
ok "it runs: $got"
[ -f "$mandir/man8/restate.8" ] || die "no manual page at $mandir/man8/restate.8"
ok "its manual page is at $mandir/man8/restate.8"
# restate runs only hooks root owns that no one else may write: the package's
# must be such, whoever built it.
bad="$(find "$PREFIX/sbin/restate" "$HOOKS" \( ! -user 0 -o -perm -020 -o -perm -002 \) -print)"
[ -z "$bad" ] || die "not root's alone: $bad"
[ -x "$HOOKS/postgresql" ] || die "no hooks in $HOOKS"
ok "it and its hooks are root's, and no one else's to write"
"$PREFIX/sbin/restate" features --json > /dev/null
ok "restate features runs"

remove
[ ! -e "$PREFIX/sbin/restate" ] || die "removing the package left $PREFIX/sbin/restate"
[ ! -e "$PREFIX/libexec/restate" ] || die "removing the package left $PREFIX/libexec/restate"
ok "removed, and nothing of it left"
