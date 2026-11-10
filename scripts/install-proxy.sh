#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Install restate-proxy into the filesystem, or take it back out again.
#
#   scripts/install-proxy.sh             install under $prefix (default /usr/local)
#   scripts/install-proxy.sh --uninstall remove what the above put there
#
# Separate from scripts/install.sh because the proxy is installed on the
# storage host, and restate on the machines that capture: either without the
# other. Reads the same variables the Makefile exports, so
# `make install-proxy prefix=...` and `DESTDIR=...` behave as `make install`'s do.
#
# What it installs: the binary, and where its grants go (/etc/restate/proxy.d,
# root's and writable by no one else, which the proxy insists on). Not a
# certificate, not a staging directory and not a service: the staging belongs
# to whichever user the proxy runs as, which is the site's to choose, and a
# service that would start serving on an install is not one to put there
# unasked.
set -euo pipefail

UNINSTALL=0
if [ "${1:-}" = "--uninstall" ]; then
  UNINSTALL=1
fi

PREFIX="${prefix:-/usr/local}"
BINDIR="${sbindir:-$PREFIX/sbin}"
DESTDIR="${DESTDIR:-}"
PROXY="restate-proxy"

BIN_TARGET="$DESTDIR$BINDIR/$PROXY"
GRANTS_TARGET="$DESTDIR/etc/restate/proxy.d"

ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
note() { printf '    \033[2m%s\033[0m\n' "$*"; }
die()  { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

# The nearest ancestor that exists is the one that has to be writable.
writable() {
  local dir="$1"
  while [ ! -d "$dir" ] && [ "$dir" != "/" ]; do
    dir="$(dirname "$dir")"
  done
  [ -w "$dir" ]
}

# sudo, or doas where that is what the system has (OpenBSD), asked for up
# front whenever a target is not writable already: `make install-proxy` then
# works as `sudo make install-proxy` does. The grants' directory counts too
# -- a /usr/local its group can write is still root's, and wants them in
# /etc -- but not for a staged install, or one into a prefix of one's own
# (prefix=$HOME/.local), which has no business in /etc.
own_prefix() {
  local dir="$PREFIX"
  while [ ! -d "$dir" ] && [ "$dir" != "/" ]; do
    dir="$(dirname "$dir")"
  done
  [ -O "$dir" ]
}
need_root() {
  writable "$(dirname "$BIN_TARGET")" || return 0
  [ -z "$DESTDIR" ] || return 1
  own_prefix && return 1
  ! writable "$GRANTS_TARGET"
}
SUDO=""
if [ "$(id -u)" != "0" ] && need_root; then
  if command -v sudo > /dev/null 2>&1; then
    SUDO="sudo"
  elif command -v doas > /dev/null 2>&1; then
    SUDO="doas"
  else
    die "$BINDIR is not writable and neither sudo nor doas is installed.
       Either run this as root, or choose somewhere you can write:
         make install-proxy prefix=\$HOME/.local"
  fi
fi

WHAT="$([ "$UNINSTALL" = 1 ] && echo Uninstalling || echo Installing) $PROXY"
if [ -n "$SUDO" ]; then
  printf '\n\033[1m%s\033[0m \033[2m(needs root for %s)\033[0m\n\n' "$WHAT" "$PREFIX"
  $SUDO true || die "could not obtain the privileges to write to $PREFIX"
else
  printf '\n\033[1m%s\033[0m\n\n' "$WHAT"
fi

if [ "$UNINSTALL" = "1" ]; then
  $SUDO rm -f "$BIN_TARGET"
  ok "removed $BIN_TARGET"
  # The grants, the certificate, the key and the staging are the site's, and
  # stay; the grants' directory goes only if it is empty.
  if $SUDO rmdir "$GRANTS_TARGET" 2> /dev/null; then
    ok "removed $GRANTS_TARGET, which was empty"
  elif [ -d "$GRANTS_TARGET" ]; then
    note "$GRANTS_TARGET kept: it holds grants"
  fi
  printf '\n'
  exit 0
fi

[ -x "bin/$PROXY" ] || die "bin/$PROXY is not built — run 'make proxy' first"

$SUDO install -d "$(dirname "$BIN_TARGET")"
$SUDO install -m 0755 "bin/$PROXY" "$BIN_TARGET"
ok "installed $BIN_TARGET"

if [ -n "$DESTDIR" ] || [ -n "$SUDO" ] || [ "$(id -u)" = "0" ]; then
  $SUDO install -d -m 0755 "$GRANTS_TARGET"
  ok "made $GRANTS_TARGET"
else
  note "$GRANTS_TARGET not made: that needs root (--grants DIR names another)"
fi

if [ -z "$DESTDIR" ]; then
  printf '\n'
  ok "$("$BIN_TARGET" --version | head -1)"
  note "it needs a certificate and key (--cert, --key; /etc/restate/proxy.crt"
  note "and proxy.key by default), a grant per client (restate-proxy --new-token),"
  note "and a staging directory, 0700 and its own user's (--staging;"
  note "/var/lib/restate-proxy/staging by default) before restate-proxy --serve"
  printf '\n'
fi
