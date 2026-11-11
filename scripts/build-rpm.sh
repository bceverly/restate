#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Build restate's RPM on the distribution this runs on -- Fedora, RHEL or a
# rebuild of it, or openSUSE -- with rpmbuild:
#
#   scripts/build-rpm.sh [--deps] [TARBALL] [OUTDIR]
#   scripts/build-rpm.sh [--deps] --source [TARBALL] [OUTDIR]
#
# --deps installs what the spec's BuildRequires name, and nothing else, with
# dnf or zypper, as root: a container as bare as COPR's and OBS's build roots
# then proves the list is whole. TARBALL is restate-VERSION.tar.gz, the release's (default: one made from
# this tree, scripts/source-tarball.sh); OUTDIR (default dist) gets the
# binary package and the source package, or with --source the source package
# alone, which is what COPR builds from.
#
# packaging/rpm/restate.spec.in is written out as restate.spec with the
# version from VERSION, so that number lives in one place. The binary package
# is named for the distribution it was built on, whose own tag (fc44, el9)
# is in its name already; openSUSE has none, so its name and release go in.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE=binary
DEPS=no
if [ "${1:-}" = --deps ]; then
  DEPS=yes
  shift
fi
if [ "${1:-}" = --source ]; then
  MODE=source
  shift
fi
TARBALL="${1:-}"
OUTDIR="${2:-$REPO_ROOT/dist}"
VERSION="$(cat "$REPO_ROOT/VERSION")"

info() { printf '  \033[96m→\033[0m %s\n' "$*"; }
ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
die()  { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

# A package manager's command, tried again when it fails: a mirror partway
# through a sync serves an empty or half-written repomd.xml ("Document is
# empty") or a repository with packages missing, and the next try, with the
# metadata cleared, asks afresh of whichever mirror the redirector picks then.
# Five tries, 30 seconds apart, as CI's own setup does. A failure that is not
# the mirror's fails all five, a couple of minutes later than it would have.
pm() {
  pm_n=1
  until "$@"; do
    if [ "$pm_n" -ge 5 ]; then
      echo "$1 failed $pm_n times: $*" >&2
      return 1
    fi
    echo "$1 attempt $pm_n failed; clearing its metadata and trying again in 30s" >&2
    pm_n=$((pm_n + 1))
    sleep 30
    case "$1" in
      dnf) dnf clean metadata > /dev/null 2>&1 || true ;;
      zypper) zypper --non-interactive clean --all > /dev/null 2>&1 || true ;;
    esac
  done
}

if [ "$DEPS" = yes ]; then
  if command -v dnf > /dev/null 2>&1; then
    pm dnf install -y -q rpm-build 'dnf-command(builddep)'
  else
    pm zypper --non-interactive -q install -y rpm-build
  fi
fi
command -v rpmbuild > /dev/null 2>&1 || die "rpmbuild is not installed (dnf install rpm-build, zypper install rpm-build)"
TOP="$(mktemp -d "${TMPDIR:-/tmp}/restate-rpm.XXXXXX")"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,RPMS,SRPMS} "$OUTDIR"
case "$OUTDIR" in
  /*) ;;
  *) OUTDIR="$PWD/$OUTDIR" ;;
esac

if [ -n "$TARBALL" ]; then
  cp "$TARBALL" "$TOP/SOURCES/restate-$VERSION.tar.gz"
else
  info "a source tarball of this tree"
  "$REPO_ROOT/scripts/source-tarball.sh" "$TOP/SOURCES/restate-$VERSION.tar.gz"
fi
sed -e "s|@VERSION@|$VERSION|g" -e "s|@DATE@|$(LC_ALL=C date -u '+%a %b %d %Y')|g" \
  "$REPO_ROOT/packaging/rpm/restate.spec.in" > "$TOP/SPECS/restate.spec"

if [ "$DEPS" = yes ]; then
  if command -v dnf > /dev/null 2>&1; then
    pm dnf builddep -y -q "$TOP/SPECS/restate.spec"
  else
    # shellcheck disable=SC2046
    pm zypper --non-interactive -q install -y $(rpmspec -q --buildrequires "$TOP/SPECS/restate.spec")
  fi
fi
if [ "$MODE" = source ]; then
  rpmbuild --define "_topdir $TOP" -bs "$TOP/SPECS/restate.spec"
else
  rpmbuild --define "_topdir $TOP" -ba "$TOP/SPECS/restate.spec"
fi

# The distribution's tag, or openSUSE's name and release where there is none.
dist="$(rpm --eval '%{?dist}')"
if [ -z "$dist" ]; then
  # shellcheck source=/dev/null
  dist=".$(. /etc/os-release && printf '%s%s' "$ID" "${VERSION_ID:-}" | sed 's/-//g')"
fi
cp "$TOP"/SRPMS/restate-"$VERSION"-*.src.rpm "$OUTDIR/"
if [ "$MODE" = binary ]; then
  for f in "$TOP"/RPMS/*/restate-"$VERSION"-*.rpm "$TOP"/RPMS/*/restate-proxy-"$VERSION"-*.rpm; do
    case "$f" in
      *-debuginfo-* | *-debugsource-*) continue ;;
    esac
    name="$(rpm -qp --qf '%{NAME}' "$f" 2> /dev/null)"
    arch="$(rpm -qp --qf '%{ARCH}' "$f" 2> /dev/null)"
    cp "$f" "$OUTDIR/$name-$VERSION-1${dist}.$arch.rpm"
  done
fi
made=""
for f in "$OUTDIR"/restate-"$VERSION"-*.rpm "$OUTDIR"/restate-proxy-"$VERSION"-*.rpm; do
  [ -e "$f" ] || continue
  made="$made$(basename "$f") "
done
ok "${made}in $OUTDIR"
