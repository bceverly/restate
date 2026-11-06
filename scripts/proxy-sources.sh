# shellcheck shell=bash
# shellcheck disable=SC2034  # every variable here is for the script sourcing it
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# restate-proxy's sources and flags, for the scripts that analyze or test the
# code: sourced, not run, by lint, coverage, memcheck and security.
#
#   . scripts/proxy-sources.sh
#
# Sets, where the TLS library is here to build against (scripts/tls.sh):
#
#   PROXY_OK          1, or empty where it is not
#   PROXY_LIB         proxy/*.c but main.c, which the unit tests link
#   PROXY_MAIN        proxy/main.c
#   PROXY_TESTS       tests/proxy/*.c
#   PROXY_CPPFLAGS    -Iproxy and the library's own -I, as an array
#   PROXY_LIBS        the library, as an array
#   PROXY_NAME        OpenSSL or libtls, for messages
#
# Where it is not, PROXY_OK is empty and every array is too, so that
# "${PROXY_LIB[@]+"${PROXY_LIB[@]}"}" adds nothing -- unless RS_REQUIRE_PROXY
# is set, as CI sets it, where that is a failure (exit 1), since CI installs
# the library and a skip there is a broken install.
#
# The arrays are written out in that form at every use because bash 3.2,
# macOS's, calls an empty array unset under `set -u`.

PROXY_OK=""
PROXY_LIB=()
PROXY_MAIN=()
PROXY_TESTS=()
PROXY_CPPFLAGS=()
PROXY_LIBS=()
PROXY_NAME="$(scripts/tls.sh --name)"

if scripts/tls.sh --check; then
  PROXY_OK=1
  for f in proxy/*.c; do
    [ "$f" = proxy/main.c ] || PROXY_LIB+=("$f")
  done
  PROXY_MAIN=(proxy/main.c)
  PROXY_TESTS=(tests/proxy/*.c)
  read -r -a PROXY_CPPFLAGS <<< "-Iproxy -DRS_WITH_PROXY $(scripts/tls.sh --cflags)"
  read -r -a PROXY_LIBS <<< "$(scripts/tls.sh --libs)"
elif [ -n "${RS_REQUIRE_PROXY:-}" ]; then
  printf '  \033[91m✗\033[0m restate-proxy: %s is not installed, and RS_REQUIRE_PROXY is set\n' \
         "$PROXY_NAME" >&2
  exit 1
else
  printf '  \033[93m-\033[0m restate-proxy passed over: %s is not installed (make install-dev)\n' \
         "$PROXY_NAME"
fi
