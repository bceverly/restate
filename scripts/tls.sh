#!/usr/bin/env sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# The TLS library restate-proxy is built with, for this platform.
#
#   scripts/tls.sh --cflags     what to compile proxy/ with
#   scripts/tls.sh --libs       what to link restate-proxy with
#   scripts/tls.sh --check      exit 0 if those build and link here, 1 if not
#   scripts/tls.sh --name       "OpenSSL" or "libtls", for messages
#
# Only restate-proxy links a TLS library. restate itself links nothing beyond
# the C library -- `make security` checks it -- and reaches a proxy by running
# curl. So nothing here is part of `make build`, and a machine without these
# headers builds restate exactly as before.
#
#   OpenBSD     libtls, in the base system (LibreSSL's own API)
#   macOS       Homebrew's openssl@3, which is keg-only: never on the default
#               search path, so its prefix is asked of brew
#   elsewhere   OpenSSL 3, by pkg-config where there is one, else -lssl
#               -lcrypto from the default paths (the BSDs' base OpenSSL)
#
# RS_TLS=openssl or RS_TLS=libtls picks one by hand, for a system with both.
#
# One place, as scripts/features.sh is, because the Makefile and every
# analysis script compile proxy/ and must agree on how.
#
# sh rather than bash: the Makefile runs this.
set -eu

backend="${RS_TLS:-}"
if [ -z "$backend" ]; then
    case "$(uname -s)" in
    OpenBSD) backend=libtls ;;
    *)       backend=openssl ;;
    esac
fi

cflags=""
libs=""
case "$backend" in
libtls)
    cflags="-DRS_TLS_LIBTLS"
    libs="-ltls"
    if command -v pkg-config > /dev/null 2>&1 && pkg-config --exists libtls 2> /dev/null; then
        extra="$(pkg-config --cflags libtls)"
        cflags="$cflags${extra:+ $extra}"
        libs="$(pkg-config --libs libtls)"
    fi
    ;;
openssl)
    prefix=""
    if [ "$(uname -s)" = Darwin ] && command -v brew > /dev/null 2>&1; then
        prefix="$(brew --prefix openssl@3 2> /dev/null || true)"
        [ -d "$prefix/include/openssl" ] || prefix=""
    fi
    if [ -n "$prefix" ]; then
        cflags="-I$prefix/include"
        libs="-L$prefix/lib -lssl -lcrypto"
    elif command -v pkg-config > /dev/null 2>&1 && pkg-config --exists openssl 2> /dev/null; then
        cflags="$(pkg-config --cflags openssl)"
        libs="$(pkg-config --libs openssl)"
    else
        libs="-lssl -lcrypto"
    fi
    ;;
*)
    echo "scripts/tls.sh: RS_TLS is openssl or libtls, not $backend" >&2
    exit 2
    ;;
esac

case "${1:-}" in
--cflags)
    echo "$cflags"
    ;;
--libs)
    echo "$libs"
    ;;
--name)
    if [ "$backend" = libtls ]; then echo libtls; else echo OpenSSL; fi
    ;;
--check)
    # Built and linked, not only preprocessed: headers without the library,
    # or a library too old for the calls proxy/tls.c makes, is the failure
    # worth finding here rather than halfway through a build.
    dir="$(mktemp -d "${TMPDIR:-/tmp}/restate-tls.XXXXXX")"
    trap 'rm -rf "$dir"' EXIT
    if [ "$backend" = libtls ]; then
        printf '%s\n' '#include <tls.h>' \
            'int main(void) { return tls_init() == 0 && tls_config_new() != 0 ? 0 : 1; }' \
            > "$dir/probe.c"
    else
        printf '%s\n' '#include <openssl/ssl.h>' \
            '#if OPENSSL_VERSION_NUMBER < 0x30000000L' \
            '#error OpenSSL 3 or newer' \
            '#endif' \
            'int main(void) { return SSL_CTX_new(TLS_server_method()) != 0 ? 0 : 1; }' \
            > "$dir/probe.c"
    fi
    # $cflags and $libs unquoted: each is a list of flags.
    # shellcheck disable=SC2086
    ${CC:-cc} $cflags -o "$dir/probe" "$dir/probe.c" $libs > /dev/null 2>&1
    ;;
*)
    echo "usage: scripts/tls.sh --cflags | --libs | --check | --name" >&2
    exit 2
    ;;
esac
