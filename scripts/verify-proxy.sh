#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Check an installed restate-proxy package: what each verify script runs once
# it has installed the package with its system's own installer, and before it
# removes it.
#
#   sh verify-proxy.sh SBINDIR USER SERVICE
#
# SBINDIR is where the package put restate-proxy, USER the user it made for
# the service, SERVICE the service file it installed for its init system. As
# root. It checks:
#
#   - the program runs, and says its version and its TLS library
#   - its manual page is there (man -w)
#   - the user is there, and the service file runs the program
#   - --new-token and --check-grants, on a grant made here
#   - where openssl is, that it serves: a certificate made here, the proxy
#     started on a free port of 127.0.0.1, its log saying where it listens
#   - and where curl is too (restate runs it to reach a proxy), that restate,
#     installed beside it, captures through it into a repository made here,
#     which then lists the snapshot and checks whole
#
# A Linux container has openssl and curl when the verify script installs
# them; a BSD has openssl in its base system and no curl, so there the
# capture is passed over, and says so.
set -eu

SBINDIR="${1:?usage: verify-proxy.sh SBINDIR USER SERVICE}"
USER_NAME="${2:?usage: verify-proxy.sh SBINDIR USER SERVICE}"
SERVICE="${3:?usage: verify-proxy.sh SBINDIR USER SERVICE}"
PROXY="$SBINDIR/restate-proxy"
RESTATE="$SBINDIR/restate"

ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
skip() { printf '  \033[93m-\033[0m %s\n' "$*"; }
die()  { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-proxy-verify.XXXXXX")"
SERVER=""
cleanup() {
  [ -z "$SERVER" ] || kill "$SERVER" 2> /dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

[ -x "$PROXY" ] || die "no $PROXY"
got="$("$PROXY" --version | head -n 1)"
case "$got" in
  "restate-proxy "*"(protocol "*) ok "it runs: $got" ;;
  *) die "restate-proxy --version says \"$got\"" ;;
esac
"$PROXY" --help > /dev/null
# man -w's answer if it is a path; a minimized Ubuntu's man is a stub that
# says only that it is one, so then where the systems put pages.
page="$(man -w restate-proxy 2> /dev/null || true)"
case "$page" in
  /*) ;;
  *) page="$(find /usr/share/man /usr/local/man /usr/local/share/man /usr/pkg/man \
               -name 'restate-proxy.8*' 2> /dev/null | head -n 1)" ;;
esac
[ -n "$page" ] && [ -f "$page" ] || die "no manual page for restate-proxy"
ok "its manual page: $page"

id "$USER_NAME" > /dev/null 2>&1 || die "no user $USER_NAME"
ok "its user: $(id "$USER_NAME")"
[ -f "$SERVICE" ] || die "no service file $SERVICE"
grep -q "restate-proxy" "$SERVICE" || die "$SERVICE does not run restate-proxy"
ok "its service: $SERVICE"
[ -d /etc/restate/proxy.d ] || die "no /etc/restate/proxy.d"

# A grant, as a site would write one: the token's hash, from --new-token.
mkdir "$WORK/proxy.d" "$WORK/staging"
chmod 0700 "$WORK/staging"
"$PROXY" --new-token "$WORK/c01.token" > "$WORK/hash" || die "--new-token failed"
grep -q '^token_sha256 = [0-9a-f]\{64\}$' "$WORK/hash" || die "--new-token printed $(cat "$WORK/hash")"
{
  printf 'repository = %s/repo\noperations = read, append\n' "$WORK"
  cat "$WORK/hash"
} > "$WORK/proxy.d/c01.conf"
chmod 0644 "$WORK/proxy.d/c01.conf"
"$PROXY" --check-grants "$WORK/proxy.d" > "$WORK/check" || {
  cat "$WORK/check"
  die "--check-grants refused a good grant"
}
ok "--new-token and --check-grants"

if ! command -v openssl > /dev/null 2>&1; then
  skip "no openssl here to make a certificate with: serving passed over"
  exit 0
fi
# An address in the certificate, for curl to check it against, where this
# openssl can say one (-addext); LibreSSL's may not, and then the name alone.
# And where this openssl has no openssl.cnf of its own (NetBSD's may not),
# with the least one there can be.
printf '[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n%s\n' \
  'basicConstraints = critical, CA:true' > "$WORK/openssl.cnf"
made=""
for config in "" "-config $WORK/openssl.cnf"; do
  for addext in "-addext subjectAltName=IP:127.0.0.1" ""; do
    # shellcheck disable=SC2086  # each is its words, or none
    if openssl req $config -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 $addext \
         -keyout "$WORK/key.pem" -out "$WORK/cert.pem" > /dev/null 2>> "$WORK/openssl.err"; then
      made=1
      break 2
    fi
  done
done
if [ -z "$made" ]; then
  sed 's/^/    openssl: /' "$WORK/openssl.err" | head -8
  die "openssl could not make a certificate"
fi
if [ -x "$RESTATE" ]; then
  "$RESTATE" init -q "$WORK/repo" || die "restate init failed"
else
  mkdir "$WORK/repo"
fi
"$PROXY" --serve --listen 127.0.0.1:0 --cert "$WORK/cert.pem" --key "$WORK/key.pem" \
  --grants "$WORK/proxy.d" --staging "$WORK/staging" 2> "$WORK/log" &
SERVER=$!
PORT=""
n=0
while [ -z "$PORT" ] && [ "$n" -lt 40 ]; do
  PORT="$(sed -n 's/.*listening on 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$WORK/log")"
  [ -n "$PORT" ] || sleep 0.25
  n=$((n + 1))
done
[ -n "$PORT" ] || { cat "$WORK/log"; die "it did not say where it listens"; }
grep -q 'started version=' "$WORK/log" || { cat "$WORK/log"; die "it did not say it started"; }
ok "it serves on 127.0.0.1:$PORT ($(sed -n 's/.*confinement="\([^"]*\)".*/\1/p' "$WORK/log"))"

if [ ! -x "$RESTATE" ]; then
  skip "restate is not installed beside it: the capture through it passed over"
elif ! command -v curl > /dev/null 2>&1; then
  skip "no curl here, which restate runs to reach a proxy: the capture through it passed over"
else
  mkdir -p "$WORK/tree/etc"
  echo 'through the proxy' > "$WORK/tree/etc/motd"
  URL="https://127.0.0.1:$PORT/v1/c01"
  ON="--repository-token-file $WORK/c01.token --repository-ca-file $WORK/cert.pem"
  # $ON unquoted: two options and their files, none with a space.
  # shellcheck disable=SC2086
  "$RESTATE" capture -q --root "$WORK/tree" $ON -o "$URL" || {
    cat "$WORK/log"
    die "restate could not capture through it"
  }
  # shellcheck disable=SC2086
  "$RESTATE" snapshots $ON "$URL" > "$WORK/snapshots" || die "restate snapshots failed"
  [ -s "$WORK/snapshots" ] || die "no snapshot listed after the capture"
  "$RESTATE" check "$WORK/repo" > /dev/null || die "the repository is not whole"
  ok "restate captured through it, and the repository checks whole"
fi
kill "$SERVER"
wait "$SERVER" || true
SERVER=""
grep -q 'stopped' "$WORK/log" || { cat "$WORK/log"; die "it did not stop as SIGTERM asks"; }
ok "it stops on SIGTERM"
