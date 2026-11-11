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
#   scripts/build-bsd-pkg.sh [--proxy] STAGE [OUTDIR]
#
# STAGE is a DESTDIR the program, its manual page and its hooks are installed
# into under /usr/local; OUTDIR (default dist) is where the package goes.
#
# With --proxy, the package is restate-proxy's (restate-proxy-VERSION-...),
# from a stage of make install-proxy-tree: the program and its manual, with
# the service for this system's rc added here, and its user made as the
# package goes in --
#
#   FreeBSD   restate-proxy, by pw in the package's pre-install script;
#             the service in /usr/local/etc/rc.d (sysrc restate_proxy_enable)
#   OpenBSD   _restate-proxy, uid and gid 993, by @newuser and @newgroup;
#             the service in /etc/rc.d (rcctl enable restate_proxy)
#   NetBSD    restate-proxy, by useradd in the package's +INSTALL; the
#             service in /usr/local/share/examples/rc.d, as pkgsrc's are,
#             to copy into /etc/rc.d
#
# and /etc/restate/proxy.d, its grants, made for it. None is enabled: it needs
# a certificate, its key and a grant first. 993 is OpenBSD's ports registry's
# (infrastructure/db/user.list) first free id far enough past its last (905,
# in November 2026) that the ports are not soon to reach it. Each
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

PROXY=0
if [ "${1:-}" = --proxy ]; then
  PROXY=1
  shift
fi
STAGE="${1:?usage: build-bsd-pkg.sh [--proxy] STAGE [OUTDIR]}"
OUTDIR="${2:-dist}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/usr/local
NAME=restate
COMMENT="record what makes a machine different from a fresh install"
if [ "$PROXY" = 1 ]; then
  NAME=restate-proxy
  COMMENT="serve restate repositories over HTTPS, append-only"
fi
VERSION="$(cat "$REPO_ROOT/VERSION")"
PROXY_UID=993
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

# The package's description: debian/control's for the package of this name,
# with its Debian markup taken away, so that there is one to keep up to date.
awk -v name="$NAME" '
  /^Package:/ { this = ($2 == name); within = 0; next }
  this && /^Description:/ { within = 1; next }
  within && /^[^ ]/ { within = 0 }
  within && /^$/ { within = 0 }
  within { print }
' "$REPO_ROOT/debian/control" | sed 's/^ //; s/^\.$//' > "$WORK/desc"
[ -s "$WORK/desc" ] || die "no description for $NAME in debian/control"

# restate-proxy's service, for this system's rc, into the stage, with the
# prefix it is installed under; where each system keeps its own.
if [ "$PROXY" = 1 ]; then
  case "$(uname -s)" in
    FreeBSD) rc="$STAGE$PREFIX/etc/rc.d/restate_proxy" src=freebsd ;;
    OpenBSD) rc="$STAGE/etc/rc.d/restate_proxy" src=openbsd ;;
    NetBSD) rc="$STAGE$PREFIX/share/examples/rc.d/restate_proxy" src=netbsd ;;
    *) die "not a BSD: $(uname -s)" ;;
  esac
  mkdir -p "$(dirname "$rc")"
  sed "s|%%PREFIX%%|$PREFIX|g" "$REPO_ROOT/packaging/bsd/restate_proxy.$src" > "$rc"
  chmod 0755 "$rc"
fi

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
    if [ "$PROXY" = 1 ]; then
      # restate-proxy's user, before its files; its grants' directory after.
      cat > "$WORK/pre-install" <<'SCRIPT'
pw groupshow restate-proxy > /dev/null 2>&1 || pw groupadd restate-proxy
pw usershow restate-proxy > /dev/null 2>&1 ||
  pw useradd restate-proxy -g restate-proxy -d /var/db/restate-proxy -s /usr/sbin/nologin \
     -c "restate-proxy, restate repositories over HTTPS"
SCRIPT
      printf 'install -d -m 0755 /etc/restate /etc/restate/proxy.d\n' > "$WORK/post-install"
      printf '  },\n'
      printf '  "scripts": {\n'
      printf '    "pre-install": "%s",\n' "$(sed 's/\\/\\\\/g; s/"/\\"/g' "$WORK/pre-install" | awk '{printf "%s\\n", $0}')"
      printf '    "post-install": "%s"\n' "$(sed 's/\\/\\\\/g; s/"/\\"/g' "$WORK/post-install" | awk '{printf "%s\\n", $0}')"
    fi
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
    # restate-proxy's user, its service and its grants' directory: pkg_add
    # makes the user before the files, puts the rc script in /etc/rc.d, and
    # makes the directory, which pkg_delete removes only if it is empty.
    if [ "$PROXY" = 1 ]; then
      printf '@newgroup _restate-proxy:%s\n' "$PROXY_UID"
      printf '@newuser _restate-proxy:%s:_restate-proxy:daemon:restate-proxy:/var/empty:/sbin/nologin\n' \
        "$PROXY_UID"
      printf '@rcscript /etc/rc.d/restate_proxy\n'
      printf '@sample /etc/restate/\n@sample /etc/restate/proxy.d/\n'
    fi
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
  # restate-proxy's user before its files, and its grants' directory after:
  # pkg_add runs +INSTALL with PRE-INSTALL, then POST-INSTALL.
  INSTALL_SCRIPT=""
  if [ "$PROXY" = 1 ]; then
    cat > "$WORK/+INSTALL" <<'SCRIPT'
#!/bin/sh
case "$2" in
PRE-INSTALL)
  groupinfo -e restate-proxy || groupadd restate-proxy
  userinfo -e restate-proxy ||
    useradd -g restate-proxy -d /var/db/restate-proxy -s /sbin/nologin \
      -c "restate-proxy, restate repositories over HTTPS" restate-proxy
  ;;
POST-INSTALL)
  install -d -m 0755 /etc/restate /etc/restate/proxy.d
  ;;
esac
exit 0
SCRIPT
    INSTALL_SCRIPT="$WORK/+INSTALL"
  fi
  info "pkg_create, for NetBSD $REL $ARCH"
  # The file's name says how to compress it: .tgz, gzip.
  ( cd "$WORK" && pkg_create \
      ${INSTALL_SCRIPT:+-i "$INSTALL_SCRIPT"} \
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
