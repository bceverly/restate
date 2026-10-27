#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Build restate's Alpine package on the Alpine this runs on, with abuild:
#
#   scripts/build-apk.sh [TARBALL] [OUTDIR]
#
# TARBALL is restate-VERSION.tar.gz, the release's (default: one made from
# this tree, scripts/source-tarball.sh); OUTDIR (default dist) gets
#
#   restate-VERSION-r0-alpineREL-ARCH.apk       the program, its hooks
#   restate-doc-VERSION-r0-alpineREL-ARCH.apk   its manual, as Alpine splits it
#
# named for the release and architecture they were built on. Run as root, in
# a throwaway container (abuild -F): it installs what the build needs.
#
# Signed with a key made for the build and thrown away, unless
# ABUILD_PRIVKEY names a private key to sign with, its public half beside it
# as KEY.pub: Alpine's own packages are signed by Alpine's means, which these
# are not -- installed with apk add --allow-untrusted, as OpenBSD's are with
# pkg_add -D unsigned, the release's checksums and attestation vouching for
# them instead.
set -eu

TARBALL="${1:-}"
OUTDIR="${2:-dist}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$REPO_ROOT/VERSION")"

ok()  { printf '  \033[92m✓\033[0m %s\n' "$*"; }
die() { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

[ -f /etc/alpine-release ] || die "not Alpine"
command -v abuild > /dev/null 2>&1 || apk add -q alpine-sdk
mkdir -p "$OUTDIR"
case "$OUTDIR" in
  /*) ;;
  *) OUTDIR="$PWD/$OUTDIR" ;;
esac
WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-apk.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/build" "$WORK/packages" "$WORK/keys"

if [ -n "$TARBALL" ]; then
  cp "$TARBALL" "$WORK/build/restate-$VERSION.tar.gz"
else
  "$REPO_ROOT/scripts/source-tarball.sh" "$WORK/build/restate-$VERSION.tar.gz"
fi
sed "s|@VERSION@|$VERSION|g" "$REPO_ROOT/packaging/alpine/APKBUILD.in" > "$WORK/build/APKBUILD"

if [ -n "${ABUILD_PRIVKEY:-}" ]; then
  if [ ! -f "$ABUILD_PRIVKEY" ] || [ ! -f "$ABUILD_PRIVKEY.pub" ]; then
    die "ABUILD_PRIVKEY: $ABUILD_PRIVKEY and $ABUILD_PRIVKEY.pub are not both there"
  fi
  PACKAGER_PRIVKEY="$ABUILD_PRIVKEY"
else
  # A key for this build alone, its public half where apk looks, so the
  # build can install what it made to check it.
  openssl genrsa -out "$WORK/keys/restate-build.rsa" 2048 2> /dev/null
  openssl rsa -in "$WORK/keys/restate-build.rsa" -pubout -out "$WORK/keys/restate-build.rsa.pub" 2> /dev/null
  PACKAGER_PRIVKEY="$WORK/keys/restate-build.rsa"
fi
cp "$PACKAGER_PRIVKEY.pub" /etc/apk/keys/ 2> /dev/null || true
export PACKAGER_PRIVKEY
export REPODEST="$WORK/packages"
export SRCDEST="$WORK/build"

( cd "$WORK/build" && abuild -F checksum && abuild -F -r )

rel="$(cut -d. -f1,2 /etc/alpine-release)"
arch="$(apk --print-arch)"
for f in "$WORK"/packages/*/"$arch"/restate-*.apk; do
  name="$(basename "$f" .apk)"
  cp "$f" "$OUTDIR/$name-alpine$rel-$arch.apk"
done
made=""
for f in "$OUTDIR"/restate*-"$VERSION"-r*-alpine"$rel"-"$arch".apk; do
  made="$made$(basename "$f") "
done
ok "${made}in $OUTDIR"
