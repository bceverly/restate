#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Build restate's binary package for the BSD this runs on, with that system's
# own tool, from a staged install (make bsd-pkg stages it):
#
#   FreeBSD   pkg create         restate-VERSION-freebsd-REL-ARCH.pkg
#   OpenBSD   pkg_create         restate-VERSION-openbsd-REL-ARCH.tgz
#   NetBSD    pkg_create         restate-VERSION-netbsd-REL-ARCH.tgz
#
#   scripts/build-bsd-pkg.sh STAGE [OUTDIR]
#
# STAGE is a DESTDIR the program, its manual page and its hooks are installed
# into under /usr/local; OUTDIR (default dist) is where the package goes. Each
# is built where it is to run: a package names the release and architecture
# it was built on, and each system's tools check them.
#
# The packages are not signed by their systems' means -- an OpenBSD one is
# installed with pkg_add -D unsigned -- since a key for each would be one more
# secret for the release to keep. The release's checksums and its signed
# build-provenance attestation cover them instead.
#
# /etc/restate/jobs.d, which make install makes, is left out: a site's jobs
# are its own, and restate run reads them from wherever they are.
set -eu

STAGE="${1:?usage: build-bsd-pkg.sh STAGE [OUTDIR]}"
OUTDIR="${2:-dist}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/usr/local
NAME=restate
VERSION="$(cat "$REPO_ROOT/VERSION")"
COMMENT="record what makes a machine different from a fresh install"
WWW="https://github.com/bceverly/restate"
MAINTAINER="bryan@theeverlys.com"

# The package tools are in sbin, which a user's PATH may leave out: the base
# system's first, as root's PATH has them, then pkgsrc's.
PATH="$PATH:/usr/sbin:/sbin:/usr/pkg/sbin"
export PATH

info() { printf '  \033[96m→\033[0m %s\n' "$*"; }
ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
die()  { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

case "$STAGE" in
  /*) ;;
  *) STAGE="$PWD/$STAGE" ;;
esac
STAGE="$(cd "$STAGE" && pwd)" || die "no such directory: $1"
[ "$STAGE" != / ] || die "the stage cannot be /: its etc is removed"
[ -x "$STAGE$PREFIX/sbin/$NAME" ] || die "$STAGE has no $PREFIX/sbin/$NAME: run make bsd-pkg"
mkdir -p "$OUTDIR"
case "$OUTDIR" in
  /*) ;;
  *) OUTDIR="$PWD/$OUTDIR" ;;
esac
rm -rf "${STAGE:?}/etc"

OS="$(uname -s)"
REL="$(uname -r | sed 's/-.*//')"
ARCH="$(uname -m)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

# The package's description: debian/control's, with its Debian markup taken
# away, so that there is one to keep up to date.
sed -n '/^Description:/,$p' "$REPO_ROOT/debian/control" | sed '1d; s/^ //; s/^\.$//' \
  > "$WORK/desc"

# Every file and directory staged under the prefix, relative to it, in order.
( cd "$STAGE$PREFIX" && find . -type f | sed 's,^\./,,' | sort ) > "$WORK/files"
( cd "$STAGE$PREFIX" && find . -type d ! -name . | sed 's,^\./,,' | sort ) > "$WORK/dirs"
# Directories restate alone puts there; the rest (sbin, man/man8, ...) are
# the system's or every package's.
grep -E '^libexec/restate(/|$)' "$WORK/dirs" > "$WORK/owndirs" || true

case "$OS" in
FreeBSD)
  OUT="$OUTDIR/$NAME-$VERSION-freebsd-$REL-$ARCH.pkg"
  {
    printf '{\n'
    printf '  "name": "%s",\n' "$NAME"
    printf '  "origin": "sysutils/%s",\n' "$NAME"
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "comment": "%s",\n' "$COMMENT"
    printf '  "maintainer": "%s",\n' "$MAINTAINER"
    printf '  "www": "%s",\n' "$WWW"
    printf '  "prefix": "%s",\n' "$PREFIX"
    printf '  "categories": ["sysutils"],\n'
    printf '  "licenselogic": "single",\n'
    printf '  "licenses": ["BSD2CLAUSE"],\n'
    # JSON strings: the description's quotes and backslashes escaped, its
    # lines joined with \n.
    printf '  "desc": "%s",\n' "$(sed 's/\\/\\\\/g; s/"/\\"/g' "$WORK/desc" | awk '{printf "%s\\n", $0}')"
    # Each root's, whoever built it: restate runs only hooks root owns.
    printf '  "files": {\n'
    while IFS= read -r f; do
      perm=0755
      case "$f" in man/* | share/*) perm=0644 ;; esac
      printf '    "%s/%s": {"sum": "-", "uname": "root", "gname": "wheel", "perm": "%s"},\n' \
        "$PREFIX" "$f" "$perm"
    done < "$WORK/files" | sed '$s/,$//'
    printf '  },\n'
    printf '  "directories": {\n'
    while IFS= read -r d; do
      printf '    "%s/%s": {"uname": "root", "gname": "wheel", "perm": "0755"},\n' "$PREFIX" "$d"
    done < "$WORK/owndirs" | sed '$s/,$//'
    printf '  }\n'
    printf '}\n'
  } > "$WORK/+MANIFEST"
  info "pkg create, for FreeBSD $REL $ARCH"
  pkg create -M "$WORK/+MANIFEST" -r "$STAGE" -o "$WORK"
  mv "$WORK/$NAME-$VERSION.pkg" "$OUT"
  ;;
OpenBSD)
  OUT="$OUTDIR/$NAME-$VERSION-openbsd-$REL-$ARCH.tgz"
  # The packing list: the program as a binary, the page as a page, the rest
  # as files, each directory restate alone owns before what is in it.
  # Each root's, whoever built it: restate runs only hooks root owns.
  {
    printf '@owner root\n@group bin\n'
    {
      while IFS= read -r d; do
        printf '%s/\n' "$d"
      done < "$WORK/owndirs"
      while IFS= read -r f; do
        case "$f" in
          sbin/*) printf '@bin %s\n' "$f" ;;
          man/*) printf '@man %s\n' "$f" ;;
          *) printf '%s\n' "$f" ;;
        esac
      done < "$WORK/files"
    } | sort -u
  } > "$WORK/plist"
  info "pkg_create, for OpenBSD $REL $ARCH"
  pkg_create \
    -D COMMENT="$COMMENT" \
    -D FULLPKGPATH="sysutils/$NAME" \
    -D HOMEPAGE="$WWW" \
    -D MAINTAINER="$MAINTAINER" \
    -d "$WORK/desc" \
    -f "$WORK/plist" \
    -B "$STAGE" \
    -p "$PREFIX" \
    "$WORK/$NAME-$VERSION.tgz"
  mv "$WORK/$NAME-$VERSION.tgz" "$OUT"
  ;;
NetBSD)
  OUT="$OUTDIR/$NAME-$VERSION-netbsd-$REL-$ARCH.tgz"
  # What pkg_add checks the package against: the system it was built for.
  {
    printf 'OPSYS=NetBSD\n'
    printf 'OS_VERSION=%s\n' "$(uname -r)"
    printf 'MACHINE_ARCH=%s\n' "$(uname -p)"
    printf 'PKGTOOLS_VERSION=%s\n' "$(pkg_create -V)"
    printf 'PKGPATH=sysutils/%s\n' "$NAME"
    printf 'HOMEPAGE=%s\n' "$WWW"
    printf 'MAINTAINER=%s\n' "$MAINTAINER"
    printf 'LICENSE=2-clause-bsd\n'
  } > "$WORK/build-info"
  # Each root's, whoever built it: restate runs only hooks root owns. Its
  # directories are removed with the last file in them, as pkg_delete does.
  {
    printf '@owner root\n@group wheel\n'
    cat "$WORK/files"
  } > "$WORK/plist"
  info "pkg_create, for NetBSD $REL $ARCH"
  # The file's name says how to compress it: .tgz, gzip.
  ( cd "$WORK" && pkg_create \
      -B "$WORK/build-info" \
      -c "-$COMMENT" \
      -d "$WORK/desc" \
      -f "$WORK/plist" \
      -I "$PREFIX" \
      -p "$STAGE$PREFIX" \
      "$NAME-$VERSION.tgz" )
  mv "$WORK/$NAME-$VERSION.tgz" "$OUT"
  ;;
*)
  die "not a BSD: $OS (make deb builds Ubuntu's package)"
  ;;
esac
ok "$OUT"
