#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Install restate into the filesystem, or take it back out again.
#
#   scripts/install.sh             install under $prefix (default /usr/local)
#   scripts/install.sh --uninstall remove what the above put there
#
# Reads the same variables the Makefile uses, so `make install prefix=...` and
# `make install DESTDIR=...` both behave the way every other package expects.
#
# The default prefix is /usr/local, not /usr, and that is the important part.
# /usr belongs to the distribution's package manager: a file written there by
# hand is a file dpkg does not know about, and the eventual `apt install
# restate` from the PPA would either overwrite it or fight it. /usr/local is the place the
# Filesystem Hierarchy Standard sets aside for exactly this -- software the
# administrator installed themselves -- and it is on PATH ahead of /usr/bin on
# every distribution worth the name.
set -euo pipefail

UNINSTALL=0
if [ "${1:-}" = "--uninstall" ]; then
  UNINSTALL=1
fi

PREFIX="${prefix:-/usr/local}"
# sbin and section 8: restate is a system administration tool, and a scan
# worth having reads every file on the machine, which means running as root.
BINDIR="${sbindir:-$PREFIX/sbin}"

# Where a manpage goes under a local prefix, which is not the same everywhere.
#
#   Linux, macOS, FreeBSD   $PREFIX/share/man
#   NetBSD, OpenBSD         $PREFIX/man
#
# Not a style preference -- it is where each system's man(1) actually looks.
# OpenBSD's ports install to ${PREFIX}/man and its man.conf reads
# /usr/local/man; NetBSD's pkgsrc sets PKGMANDIR=man for the same reason. On
# those two, share/man puts a perfectly good file somewhere nothing reads, so
# the install would report success and `man restate` would answer "No manual
# entry" -- the worst shape a bug can take, because it looks like it worked.
#
# An explicit `make install mandir=...` still wins. The Makefile exports its
# own default for mandir, which is always $prefix/share/man, so it is ignored
# here unless the caller changed it.
case "$(uname -s)" in
NetBSD | OpenBSD)
    DEFAULT_MANDIR="$PREFIX/man"
    ;;
*)
    DEFAULT_MANDIR="$PREFIX/share/man"
    ;;
esac
MANDIR="$DEFAULT_MANDIR"
if [ -n "${mandir:-}" ] && [ "$mandir" != "$PREFIX/share/man" ]; then
  MANDIR="$mandir"
fi
DESTDIR="${DESTDIR:-}"
PROG="${PROG:-restate}"
MAN_PAGE="${MAN_PAGE:-man/$PROG.8}"

BIN_TARGET="$DESTDIR$BINDIR/$PROG"
MAN_TARGET="$DESTDIR$MANDIR/man8/$PROG.8"
# The hooks capture --quiesce runs: restate looks for them in
# libexec/restate/hooks beside the directory it is installed in, so they go
# there whatever the prefix -- /usr/local/sbin/restate finds
# /usr/local/libexec/restate/hooks.
HOOKS_TARGET="$DESTDIR$(dirname "$BINDIR")/libexec/$PROG/hooks"

ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
note() { printf '    \033[2m%s\033[0m\n' "$*"; }
die()  { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Whether this needs to be root, and how it gets there.
#
# Asked rather than assumed. Running the whole thing under sudo when the target
# is already writable -- a prefix under $HOME, a staged DESTDIR, a container
# running as root -- would create files owned by root that the user then cannot
# remove, which is a worse outcome than the permission error it was avoiding.
# ---------------------------------------------------------------------------
writable() {
  # The nearest ancestor that exists is the one that has to be writable, since
  # everything below it is about to be created.
  local dir="$1"
  while [ ! -d "$dir" ] && [ "$dir" != "/" ]; do
    dir="$(dirname "$dir")"
  done
  [ -w "$dir" ]
}

# sudo, or doas where that is what the system has. OpenBSD ships doas and no
# sudo at all -- sudo left the base system in 5.8 -- so insisting on sudo would
# make `make install` impossible there on a stock machine, for no reason beyond
# the name of the program.
SUDO=""
if [ "$(id -u)" != "0" ] \
   && { ! writable "$(dirname "$BIN_TARGET")" \
        || ! writable "$(dirname "$MAN_TARGET")"; }; then
  if command -v sudo > /dev/null 2>&1; then
    SUDO="sudo"
  elif command -v doas > /dev/null 2>&1; then
    SUDO="doas"
  else
    die "$BINDIR is not writable and neither sudo nor doas is installed.
       Either run this as root, or choose somewhere you can write:
         make install prefix=\$HOME/.local"
  fi
fi

if [ -n "$SUDO" ]; then
  printf '\n\033[1mInstalling\033[0m \033[2m(needs root for %s)\033[0m\n\n' "$PREFIX"
  # Ask once, up front, so the password prompt does not appear in the middle of
  # the work with no explanation of what wants it.
  #
  # `$SUDO true` rather than `sudo -v`, which is the natural spelling and which
  # doas does not have: -v is sudo's "refresh the timestamp and run nothing".
  # Running true through the escalation does the same job in a way both
  # programs understand.
  $SUDO true || die "could not obtain the privileges to write to $PREFIX"
else
  printf '\n\033[1m%s\033[0m\n\n' "$([ "$UNINSTALL" = 1 ] && echo Uninstalling || echo Installing)"
fi

# ---------------------------------------------------------------------------
if [ "$UNINSTALL" = "1" ]; then
  $SUDO rm -f "$BIN_TARGET" "$MAN_TARGET" "$MAN_TARGET.gz"
  ok "removed $BIN_TARGET"
  ok "removed $MAN_TARGET"
  for hook in hooks/*; do
    $SUDO rm -f "$HOOKS_TARGET/$(basename "$hook")"
  done
  $SUDO rmdir "$HOOKS_TARGET" "$(dirname "$HOOKS_TARGET")" 2> /dev/null || true
  ok "removed $HOOKS_TARGET"
else
  [ -x "bin/$PROG" ] || die "bin/$PROG is not built — run 'make build' first"
  [ -f "$MAN_PAGE" ] || die "$MAN_PAGE is missing — run 'make build' first"

  $SUDO install -d "$(dirname "$BIN_TARGET")"
  $SUDO install -m 0755 "bin/$PROG" "$BIN_TARGET"
  ok "installed $BIN_TARGET"

  $SUDO install -d "$(dirname "$MAN_TARGET")"
  $SUDO install -m 0644 "$MAN_PAGE" "$MAN_TARGET"
  ok "installed $MAN_TARGET"

  # 0755 and root's, directory too: restate runs a hook only if no one but
  # root could have changed it.
  $SUDO install -d -m 0755 "$HOOKS_TARGET"
  for hook in hooks/*; do
    $SUDO install -m 0755 "$hook" "$HOOKS_TARGET/$(basename "$hook")"
  done
  ok "installed the hooks in $HOOKS_TARGET"
fi

# ---------------------------------------------------------------------------
# The man database, so `man restate` works now rather than after the nightly cron.
#
# Skipped for a staged install: DESTDIR is a directory being assembled for a
# package, and indexing it would describe a filesystem that does not exist yet.
#
# Two spellings: mandb is the man-db one that Linux ships, makewhatis is the
# mandoc one on the BSDs and macOS. They also disagree about arguments --
# mandb rebuilds everything it knows about, makewhatis is told which directory
# -- so they cannot share a line.
if [ -z "$DESTDIR" ]; then
  # Claimed only when it actually happened. Either one fails for an
  # unprivileged install into a private prefix, and saying "refreshed" anyway
  # would be a small lie in the one place a reader is checking whether
  # `man restate` will work.
  if command -v mandb > /dev/null 2>&1; then
    if $SUDO mandb -q > /dev/null 2>&1; then
      note "man database refreshed"
    fi
  elif command -v makewhatis > /dev/null 2>&1; then
    if $SUDO makewhatis "$MANDIR" > /dev/null 2>&1; then
      note "man database refreshed"
    fi
  fi
fi

if [ "$UNINSTALL" = "0" ] && [ -z "$DESTDIR" ]; then
  printf '\n'
  # Report what the shell will actually run, which is not always what was just
  # installed: sbin is not on an ordinary user's PATH on every system, and
  # another copy may be ahead of this one. Saying so beats a confusing
  # "command not found" or version number later.
  FOUND="$(command -v "$PROG" 2>/dev/null || true)"
  if [ "$FOUND" = "$BIN_TARGET" ]; then
    ok "$($BIN_TARGET --version | head -1)"
  elif [ -n "$FOUND" ]; then
    ok "$("$BIN_TARGET" --version | head -1) installed"
    note "note: '$PROG' on your PATH is $FOUND, not the copy just installed"
    note "$BINDIR comes later in PATH, or another copy is installed"
  else
    ok "$("$BIN_TARGET" --version | head -1) installed"
    note "note: $BINDIR is not on your PATH"
  fi
  printf '\n'
fi
