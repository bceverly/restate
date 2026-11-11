#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# End-to-end tests of restate-proxy's command line.
#
#   tests/cli/proxy.sh ./bin/restate-proxy
#
# What it promises before there is a server to run: --check-grants as
# docs/proxy-protocol.md says it, and --new-token writing a token that only
# its owner can read, never printing it, and refusing to overwrite one.
set -uo pipefail

BIN="${1:?usage: proxy.sh BINARY}"
case "$BIN" in
  /*) ;;
  *) BIN="$PWD/$BIN" ;;
esac
[ -x "$BIN" ] || { echo "proxy.sh: $BIN is not executable" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-proxy-cli.XXXXXX")" || exit 2
WORK="$(printf '%s' "$WORK" | tr -s /)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || exit 2

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); printf '  \033[91mFAIL\033[0m %s\n' "$*"; }

# expect STATUS DESCRIPTION -- COMMAND...: stdout and stderr in $OUT and $ERR.
expect() {
  local want="$1" what="$2"
  shift 3
  "$@" > out.txt 2> err.txt < /dev/null
  local got=$?
  OUT="$(cat out.txt)"
  ERR="$(cat err.txt)"
  if [ "$got" -eq "$want" ]; then
    ok
  else
    fail "$what: exit $got, wanted $want"
    sed 's/^/        /' err.txt | head -5
  fi
}

contains() {
  case "$1" in
    *"$2"*) ok ;;
    *) fail "$3: no \"$2\" in output"; printf '%s\n' "$1" | head -5 | sed 's/^/        /' ;;
  esac
}

lacks() {
  case "$1" in
    *"$2"*) fail "$3: unexpected \"$2\" in output" ;;
    *) ok ;;
  esac
}

# A file's permission bits, on every system here.
file_mode() {
  stat -c '%a' "$1" 2> /dev/null || stat -f '%Lp' "$1"
}

# Whether restate will run a program: where it looks, root's, and writable by
# no one else (see run.c).
usable() {
  for d in /usr/bin /usr/local/bin /bin; do
    if [ -n "$(find -L "$d/$1" -prune -type f -user 0 ! -perm -020 ! -perm -002 2> /dev/null)" ]; then
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
expect 0 "--version" -- "$BIN" --version
contains "$OUT" "restate-proxy " "--version names the program"
contains "$OUT" "protocol 1" "--version names the protocol"
expect 0 "--help" -- "$BIN" --help
contains "$OUT" "--check-grants" "--help lists --check-grants"
expect 2 "no arguments" -- "$BIN"
contains "$ERR" "usage:" "no arguments prints the usage"
expect 2 "an unknown option" -- "$BIN" --serve-forever
contains "$ERR" "usage:" "an unknown option prints the usage"

# --new-token: the token in the file, its digest on stdout, nothing else.
expect 0 "--new-token" -- "$BIN" --new-token web01.token
TOKEN="$(cat web01.token)"
case "$TOKEN" in
  rsp_???????????????????????????????????????????) ok ;;
  *) fail "the token file holds a token: $TOKEN" ;;
esac
if [ "$(file_mode web01.token)" = 600 ]; then ok; else fail "the token file is 0600: $(file_mode web01.token)"; fi
# The digest by a tool of the system's, where it has one: sha256sum (Linux),
# shasum (macOS), sha256 (FreeBSD, OpenBSD), cksum -a (NetBSD), or openssl.
# Each prints it differently; the 64 hex digits are taken from what it says.
sha256_of() {
  local tool
  for tool in "sha256sum" "shasum -a 256" "sha256 -q" "cksum -a SHA256" "openssl dgst -sha256"; do
    # shellcheck disable=SC2086  # each is a command and its options
    if command -v ${tool%% *} > /dev/null 2>&1 &&
      printf '%s' "$1" | $tool 2> /dev/null | grep -oE '[0-9a-f]{64}' | head -n 1 | grep .; then
      return 0
    fi
  done
  return 1
}
if DIGEST="$(sha256_of "$TOKEN")"; then
  contains "$OUT" "token_sha256 = $DIGEST" "--new-token prints the token's digest"
else
  # No tool here to check it by: the grants below use the line it printed.
  DIGEST="$(printf '%s\n' "$OUT" | sed -n 's/^token_sha256 = //p')"
  printf '  - no SHA-256 tool here to check the digest --new-token printed\n'
fi
lacks "$OUT$ERR" "$TOKEN" "--new-token never prints the token"
expect 2 "--new-token over a file" -- "$BIN" --new-token web01.token
contains "$ERR" "web01.token" "--new-token over a file says which"
if [ "$(cat web01.token)" = "$TOKEN" ]; then ok; else fail "--new-token left the old token alone"; fi
expect 2 "--new-token with no file" -- "$BIN" --new-token
ln -s nowhere link.token
expect 2 "--new-token through a symlink" -- "$BIN" --new-token link.token
if [ ! -e nowhere ]; then ok; else fail "--new-token wrote through a symlink"; fi

# --check-grants: a good grant, a bad one, and what is passed over.
mkdir -m 0755 proxy.d
cat > proxy.d/web01.conf << EOF
repository   = /srv/restate/web01
operations   = append, read
token_sha256 = $DIGEST
label        = written by tests/cli/proxy.sh
EOF
printf 'repository = /srv/restate/db01\noperations = delete\n' > proxy.d/db01.conf
printf 'ignored\n' > proxy.d/.web02.conf.tmp
printf 'ignored\n' > proxy.d/README
chmod 0644 proxy.d/*.conf

expect 2 "--check-grants with a bad grant" -- "$BIN" --check-grants proxy.d
contains "$OUT" "web01.conf" "--check-grants names the good grant"
contains "$OUT" "db01.conf" "--check-grants names the bad one"
contains "$OUT" "line 2" "--check-grants says where the bad one is wrong"
lacks "$OUT" ".web02.conf.tmp" "--check-grants passes over a dotfile"
lacks "$OUT$ERR" "$TOKEN" "--check-grants never prints a token"

expect 2 "--check-grants --json with a bad grant" -- "$BIN" --check-grants --json proxy.d
contains "$OUT" '"schema": 1' "--json is schema 1"
contains "$OUT" '"ok": false' "--json marks the bad grant"
contains "$OUT" '"client": "web01"' "--json names the client"

rm proxy.d/db01.conf
expect 0 "--check-grants with good grants only" -- "$BIN" --check-grants proxy.d --json
contains "$OUT" '"ok": true' "--json marks the good grant"
expect 2 "--check-grants on no directory" -- "$BIN" --check-grants "$WORK/missing"
contains "$ERR" "missing" "--check-grants on no directory says which"
expect 2 "--check-grants given two directories" -- "$BIN" --check-grants proxy.d proxy.d
expect 2 "--check-grants given --json twice" -- "$BIN" --check-grants --json --json

# ---------------------------------------------------------------------------
# --serve: the server, with a certificate made for the run, asked by curl.

expect 2 "--serve with a --listen that is not one" -- "$BIN" --serve --listen nowhere
contains "$ERR" "not HOST:PORT" "says what it takes"
expect 2 "--serve with no certificate" -- \
  "$BIN" --serve --listen 127.0.0.1:0 --cert "$WORK/none.pem" --key "$WORK/none.pem"
contains "$ERR" "none.pem" "says which file"
expect 2 "--serve with an option it does not have" -- "$BIN" --serve --forever
expect 2 "--serve --max-connections 0" -- "$BIN" --serve --max-connections 0
contains "$ERR" "is not a number from 1 to" "is refused"
expect 2 "--serve --idle-timeout with no value" -- "$BIN" --serve --idle-timeout

# self_signed ARGS...: `openssl req -x509` with ARGS, and a configuration of
# the test's own rather than the system's (NetBSD may have none), its errors
# in openssl.err. The certificate names 127.0.0.1 as well as localhost: what
# restate is pointed at is https://127.0.0.1:PORT, never localhost, which
# resolves to ::1 too, where nothing listens. NetBSD gives out ports in turn,
# from the top down, and a fresh one's next IPv6 port comes round to the
# proxy's: curl's try at [::1]:PORT is then from [::1]:PORT, a socket
# connected to itself, which answers its own TLS hello -- and fails.
self_signed() {
  printf '[req]\ndistinguished_name = dn\nx509_extensions = v3\n[dn]\n[v3]\n%s\n%s\n' \
    'basicConstraints = critical, CA:true' 'subjectAltName = DNS:localhost, IP:127.0.0.1' \
    > openssl.cnf
  openssl req -config openssl.cnf -x509 -newkey rsa:2048 -nodes -days 2 "$@" \
    > /dev/null 2> openssl.err
}
if command -v curl > /dev/null 2>&1 && command -v openssl > /dev/null 2>&1 &&
  self_signed -subj /CN=localhost -keyout key.pem -out cert.pem; then
  # A repository for the sessions to open: its marker, its lock files, and a
  # pack's files and a snapshot's.
  mkdir -p repo/packs repo/snapshots/20261020T030000Z
  printf 'restate-repository 2\nid 0123456789abcdef0123456789abcdef\n' > repo/restate-repository
  : > repo/lock
  : > repo/readers
  printf 'index' > repo/packs/20261020T030000Z-1-0001.idx
  printf '0123456789' > repo/packs/20261020T030000Z-1-0001.tar.gz
  printf 'info' > repo/snapshots/20261020T030000Z/info
  sed "s|^repository .*|repository   = $WORK/repo|" proxy.d/web01.conf > proxy.d/.web01.tmp
  mv proxy.d/.web01.tmp proxy.d/web01.conf
  chmod 0644 proxy.d/web01.conf
  SERVER_PID=

  # start [OPTION...]: the server, on a port of the system's choosing, whose
  # number is left in $PORT; its log is server.log. Its staging is its own,
  # never a proxy's installed on this machine, unless told otherwise.
  start() {
    : > server.log
    "$BIN" --serve --listen 127.0.0.1:0 --cert cert.pem --key key.pem --grants proxy.d \
      --staging "$WORK/staging" "$@" 2> server.log &
    SERVER_PID=$!
    PORT=
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
      PORT="$(sed -n 's/.*listening on 127\.0\.0\.1:\([0-9]*\).*/\1/p' server.log)"
      [ -n "$PORT" ] && break
      sleep 0.25
    done
  }
  stop() {
    kill "$SERVER_PID" 2> /dev/null
    wait "$SERVER_PID"
    STOPPED=$?
  }
  # ask [CURL OPTION...] PATH: the status in $CODE, the headers and body in $OUT.
  ask() {
    local path="${*: -1}"
    set -- "${@:1:$(($# - 1))}"
    OUT="$(curl -s -i --cacert cert.pem --resolve "localhost:$PORT:127.0.0.1" "$@" \
      "https://localhost:$PORT$path" 2> /dev/null | tr -d '\r')"
    # The final answer's status: a curl that sent Expect: 100-continue (an
    # older one does for any body past 1 KiB) shows the 100 before it.
    CODE="$(printf '%s\n' "$OUT" | sed -n '/^HTTP\/1\.1 1[0-9][0-9]/d; s/^HTTP\/1\.1 \([0-9]*\).*/\1/p' | head -n 1)"
  }
  is() { if [ "$CODE" = "$1" ]; then ok; else fail "$2: $CODE, wanted $1"; fi; }

  start --max-sessions 4
  if [ -n "$PORT" ]; then ok; else fail "the server says where it listens"; cat server.log; fi
  contains "$(cat server.log)" "grants dir=proxy.d clients=1 refused=0" "it reads the grants"
  ask /v1/
  is 200 "GET /v1/"
  contains "$OUT" "restate-proxy 1" "says what it is"
  ask /v1/web01/list/
  is 401 "no token"
  contains "$OUT" "Restate-Reason: unauthorized" "with its reason"
  contains "$OUT" "WWW-Authenticate: Bearer" "and how to authenticate"
  ask -H "Authorization: Bearer $TOKEN" /v1/web01/list/
  is 401 "a good token, and no session"
  ask -H "Authorization: Bearer $TOKEN" /v1/db01/list/
  is 401 "a good token for another client"
  ask -H "Authorization: Bearer $TOKEN" /v1/web01/lock
  is 404 "a name it does not serve"
  ask -X DELETE -H "Authorization: Bearer $TOKEN" /v1/web01/f/restate-repository
  is 405 "DELETE"
  ask --http1.0 /v1/
  is 505 "HTTP/1.0"
  contains "$(cat server.log)" "request peer=127.0.0.1:" "each request is logged"
  lacks "$(cat server.log)" "$TOKEN" "never with its token"

  # A second client, by SIGHUP; and one gone, seen in the directory.
  expect 0 "a second client's token" -- "$BIN" --new-token db01.token
  printf 'repository = %s/repo\noperations = read\n%s\n' "$WORK" "$OUT" > proxy.d/.db01.tmp
  chmod 0644 proxy.d/.db01.tmp
  mv proxy.d/.db01.tmp proxy.d/db01.conf
  kill -HUP "$SERVER_PID"
  sleep 1
  contains "$(cat server.log)" "SIGHUP: reading the grants again" "SIGHUP reads them again"
  ask -H "Authorization: Bearer $(cat db01.token)" -d look /v1/db01/sessions
  is 201 "the new client is admitted"
  DB01_SESSION="$(printf '%s\n' "$OUT" | tail -n 1)"
  rm proxy.d/db01.conf
  sleep 3
  ask -H "Authorization: Bearer $(cat db01.token)" /v1/db01/list/
  is 401 "and once its grant is gone, refused, with no signal"

  # Sessions: opened, read in, renewed and ended; the repository's real lock
  # held by an append session; another client's session not this one's.
  AUTH="Authorization: Bearer $TOKEN"
  ask -H "$AUTH" -d read /v1/web01/sessions
  is 201 "a read session"
  SESSION="$(printf '%s\n' "$OUT" | tail -n 1)"
  contains "$OUT" "Restate-Session: $SESSION" "its id, in a header too"
  contains "$OUT" "Restate-Lease: 300" "and its lease"
  ask -H "$AUTH" -H "Restate-Session: $SESSION" /v1/web01/list/packs/
  is 200 "a listing in it"
  contains "$OUT" " 20261020T030000Z-1-0001.idx" "names the pack's files"
  ask -H "$AUTH" -H "Restate-Session: $SESSION" -r 2-4 /v1/web01/f/packs/20261020T030000Z-1-0001.tar.gz
  is 206 "a range of a pack"
  contains "$OUT" "234" "is what it holds"
  ask -X POST -H "$AUTH" "/v1/web01/sessions/$SESSION/renew"
  is 204 "renewed"
  ask -H "$AUTH" -H "Restate-Session: $DB01_SESSION" /v1/web01/list/
  is 401 "another client's session"
  ask -X POST -H "$AUTH" "/v1/web01/sessions/$SESSION/end"
  is 204 "ended"
  ask -H "$AUTH" -H "Restate-Session: $SESSION" /v1/web01/list/
  is 404 "and nothing after it"
  contains "$(cat server.log)" "session-end client=web01 kind=read" "its end is logged"
  contains "$(cat server.log)" "result=ok" "as a good one"
  ask -H "$AUTH" -d append /v1/web01/sessions
  is 201 "an append session"
  APPEND="$(printf '%s\n' "$OUT" | tail -n 1)"
  ask -H "$AUTH" -d append /v1/web01/sessions
  is 423 "and another while it is open: busy"
  contains "$OUT" "Restate-Reason: busy" "says so"
  if command -v flock > /dev/null 2>&1; then
    if flock -n repo/lock true 2> /dev/null; then
      fail "a prune on the storage host would find the lock free"
    else
      ok
    fi
  fi
  ask -H "$AUTH" -H "Restate-Session: $APPEND" /v1/web01/f/packs/20261020T030000Z-1-0001.tar.gz
  is 403 "a pack's content, in an append session"
  ask -H "$AUTH" -d write /v1/web01/sessions
  is 400 "a kind there is not"
  stop
  contains "$(cat server.log)" "session-end client=web01 kind=append" \
    "the sessions still open end as it stops"
  if command -v flock > /dev/null 2>&1; then
    if flock -n repo/lock true 2> /dev/null; then ok; else fail "and their locks with them"; fi
  fi

  # A lease: idle past it, a session is ended; renewed, it is not.
  # Every margin a second and a half or more, for a busy machine: renewed
  # every 2 seconds of a 4-second lease, the one kept is never idle past 2;
  # the other, never renewed, is idle 5 by the time it is asked for.
  start --lease 4
  ask -H "$AUTH" -d look /v1/web01/sessions
  KEPT="$(printf '%s\n' "$OUT" | tail -n 1)"
  ask -H "$AUTH" -d look /v1/web01/sessions
  LAPSED="$(printf '%s\n' "$OUT" | tail -n 1)"
  sleep 2
  ask -X POST -H "$AUTH" "/v1/web01/sessions/$KEPT/renew"
  is 204 "renewed inside its lease"
  sleep 2
  ask -X POST -H "$AUTH" "/v1/web01/sessions/$KEPT/renew"
  is 204 "and again"
  sleep 1
  ask -X POST -H "$AUTH" "/v1/web01/sessions/$LAPSED/renew"
  is 404 "one not renewed is gone"
  contains "$(cat server.log)" "result=expired" "and logged as expired"
  ask -X POST -H "$AUTH" "/v1/web01/sessions/$KEPT/end"
  is 204 "the renewed one is still there to end"
  stop
  if [ "$STOPPED" = 0 ]; then ok; else fail "SIGTERM stops it, exiting 0: $STOPPED"; fi
  contains "$(cat server.log)" "stopped" "and it says so"

  # Uploads and commits: a capture made by restate, its files sent through
  # the proxy into another repository, committed, and that repository then
  # checked by restate itself -- whole, and with nothing of the sessions'
  # staging left. restate is the program beside this one, of the same build.
  RESTATE="$(dirname "$BIN")/$(basename "$BIN" | sed 's/restate-proxy/restate/')"
  if [ -x "$RESTATE" ] && "$RESTATE" init src > /dev/null 2>&1 &&
    "$RESTATE" init dst > /dev/null 2>&1; then
    mkdir -p tree/etc tree2/etc
    printf 'one\n' > tree/etc/one.conf
    printf 'two\n' > tree/etc/two.conf
    printf 'other\n' > tree2/etc/other.conf
    expect 0 "a capture to send" -- "$RESTATE" capture -r tree --os=linux -q -o src
    SNAP=
    for d in src/snapshots/*; do
      [ -z "$SNAP" ] && SNAP="$(basename "$d")"
    done
    expect 0 "the capture's client's token" -- "$BIN" --new-token up01.token
    printf 'repository = %s/dst\noperations = read, append\n%s\n' "$WORK" "$OUT" \
      > proxy.d/.up01.tmp
    chmod 0644 proxy.d/.up01.tmp
    mv proxy.d/.up01.tmp proxy.d/up01.conf
    UP="Authorization: Bearer $(cat up01.token)"
    # What a session before this start left, which the start clears; and
    # what is not a session's, which it leaves.
    mkdir -p staging/up01/0123456789abcdef0123456789abcdef/packs staging/up01/keep
    chmod -R 0700 staging
    printf 'x' > staging/up01/0123456789abcdef0123456789abcdef/packs/.P.up
    start --staging staging --max-staging 1
    contains "$(cat server.log)" "removed=1" "what earlier sessions left in staging is removed"
    if [ ! -e staging/up01/0123456789abcdef0123456789abcdef ] && [ -d staging/up01/keep ]; then
      ok
    else
      fail "only a session's staging is removed"
    fi
    contains "$(cat server.log)" "confinement=\"" "it says how it confines"

    ask -H "$UP" -d append /v1/up01/sessions
    is 201 "an append session to send a capture in"
    CAP="$(printf '%s\n' "$OUT" | tail -n 1)"
    if [ -d "staging/up01/$CAP" ]; then ok; else fail "its staging is made"; fi
    for idx in src/packs/*.idx; do
      pack="$(basename "$idx" .idx)"
      for ext in tar.gz sum idx seek; do
        [ -f "src/packs/$pack.$ext" ] || continue
        ask -H "$UP" -T "src/packs/$pack.$ext" "/v1/up01/sessions/$CAP/files/packs/$pack.$ext"
        is 201 "the upload of a pack's $ext"
      done
      ask -X POST -H "$UP" "/v1/up01/sessions/$CAP/commit/packs/$pack"
      is 201 "the commit of a pack"
      # Sent again, as when a commit's answer was lost: there already.
      for ext in tar.gz sum idx; do
        ask -H "$UP" -T "src/packs/$pack.$ext" "/v1/up01/sessions/$CAP/files/packs/$pack.$ext"
      done
      ask -X POST -H "$UP" "/v1/up01/sessions/$CAP/commit/packs/$pack"
      is 200 "the same pack committed again"
    done
    for f in index.json.gz index.sig kit info packs; do
      [ -f "src/snapshots/$SNAP/$f" ] || continue
      ask -H "$UP" -T "src/snapshots/$SNAP/$f" "/v1/up01/sessions/$CAP/files/snapshots/$SNAP/$f"
      is 201 "the upload of the snapshot's $f"
    done
    ask -X POST -H "$UP" "/v1/up01/sessions/$CAP/commit/snapshots/$SNAP"
    is 201 "the commit of the snapshot, last"
    [ "$CODE" = 201 ] || printf '%s\n' "$OUT" | tail -n 2 | sed 's/^/        /'
    ask -X POST -H "$UP" "/v1/up01/sessions/$CAP/commit/snapshots/NOTHING"
    is 422 "a snapshot not uploaded"
    contains "$OUT" "Restate-Reason: invalid" "is not one"
    lacks "$OUT" "$WORK" "and what is said of it names no path of the host's"
    ask -X POST -H "$UP" "/v1/up01/sessions/$CAP/end"
    is 204 "the capture's session ended"
    contains "$(cat server.log)" "snapshot=$SNAP result=ok" "logged as a capture that finished"
    contains "$(cat server.log)" "kind=append seconds=" "with what it took"
    lacks "$(sed -n '/session-end client=up01/p' server.log)" "bytes_in=0 " "and what it sent"
    if [ ! -e "staging/up01/$CAP" ]; then ok; else fail "its staging is gone with it"; fi
    expect 0 "the repository it went into is whole" -- "$RESTATE" check dst
    expect 0 "and has the snapshot" -- "$RESTATE" snapshots dst
    contains "$OUT" "$SNAP" "by its name"

    # A capture that dies before its snapshot: what it committed is taken
    # out again as its session ends, as a local capture's packs are.
    expect 0 "a second capture" -- "$RESTATE" capture -r tree2 --os=linux -q -o src
    NEW=
    for idx in src/packs/*.idx; do
      pack="$(basename "$idx" .idx)"
      [ -e "dst/packs/$pack.idx" ] || NEW="$pack"
    done
    ask -H "$UP" -d append /v1/up01/sessions
    DIES="$(printf '%s\n' "$OUT" | tail -n 1)"
    for ext in tar.gz sum idx seek; do
      [ -f "src/packs/$NEW.$ext" ] || continue
      ask -H "$UP" -T "src/packs/$NEW.$ext" "/v1/up01/sessions/$DIES/files/packs/$NEW.$ext"
    done
    ask -X POST -H "$UP" "/v1/up01/sessions/$DIES/commit/packs/$NEW"
    is 201 "a pack of a capture that will not finish"
    if [ -e "dst/packs/$NEW.idx" ]; then ok; else fail "is in the repository while it runs"; fi
    ask -X POST -H "$UP" "/v1/up01/sessions/$DIES/end"
    is 204 "and its session ended with no snapshot"
    if [ ! -e "dst/packs/$NEW.idx" ] && [ ! -e "dst/packs/$NEW.tar.gz" ]; then
      ok
    else
      fail "takes the pack it committed out again"
    fi
    contains "$(cat server.log)" "packs=1 result=ended" "logged as ended, with its pack"
    expect 0 "the repository is still whole" -- "$RESTATE" check dst

    # Refused: past a file's size, past the session's staging, in a session
    # that only reads, and anything after a connection is another client's.
    ask -H "$UP" -d append /v1/up01/sessions
    REF="$(printf '%s\n' "$OUT" | tail -n 1)"
    dd if=/dev/zero of=big.sum bs=5000 count=1 2> /dev/null
    ask -H "$UP" -T big.sum "/v1/up01/sessions/$REF/files/packs/P-1.sum"
    is 413 "a .sum larger than restate writes one"
    contains "$OUT" "Restate-Reason: too-large" "says so"
    dd if=/dev/zero of=big.idx bs=1000 count=2000 2> /dev/null
    ask -H "$UP" -T big.idx "/v1/up01/sessions/$REF/files/packs/P-1.idx"
    is 507 "more than --max-staging"
    contains "$OUT" "Restate-Reason: storage-full" "says so"
    ask -X POST -H "$UP" "/v1/up01/sessions/$REF/end"
    ask -H "$UP" -d read /v1/up01/sessions
    RD="$(printf '%s\n' "$OUT" | tail -n 1)"
    ask -H "$UP" -T tree/etc/one.conf "/v1/up01/sessions/$RD/files/packs/P-1.sum"
    is 403 "an upload in a read session"
    ask -X POST -H "$UP" "/v1/up01/sessions/$RD/end"
    OUT="$(curl -s --cacert cert.pem --resolve "localhost:$PORT:127.0.0.1" \
      -H "$UP" "https://localhost:$PORT/v1/up01/list/" \
      --next -s --cacert cert.pem --resolve "localhost:$PORT:127.0.0.1" -o /dev/null \
      -w 'second=%{http_code} connects=%{num_connects}' -H "Authorization: Bearer $TOKEN" \
      -d look "https://localhost:$PORT/v1/web01/sessions" 2> /dev/null)"
    # Only where curl kept the one connection for both, as it does.
    case "$OUT" in
      *"connects=0"*) contains "$OUT" "second=401" "a connection bound to one client is no other's" ;;
      *) printf '  - curl made a second connection; the binding was not tried\n' ;;
    esac
    lacks "$(cat server.log)" "confine-failed" "every connection was confined"
    lacks "$(cat server.log)" "commit-failed" "and no commit failed"
    stop

    # An encrypted repository for a capture through the proxy to sign and
    # encrypt into, where gpg is one restate will run: a key to sign with and
    # one to encrypt to, in a GnuPG home of the test's own, and a grant.
    ENC=
    if usable gpg && usable gpgconf && mkdir -m 700 gnupg; then
      gk() { GNUPGHOME="$WORK/gnupg" gpg --batch --quiet --pinentry-mode loopback --passphrase '' "$@"; }
      gk --quick-gen-key 'restate test <signer@example.invalid>' ed25519 sign never 2> /dev/null
      gk --quick-gen-key 'restate test <enc@example.invalid>' default default never 2> /dev/null
      gk --export-secret-keys --armor signer@example.invalid > signer.sec 2> /dev/null
      gk --export signer@example.invalid > signer.pub 2> /dev/null
      gk --export enc@example.invalid > enc.pub 2> /dev/null
      if [ -s signer.sec ] && [ -s enc.pub ] && "$RESTATE" init -q --encrypt-to enc.pub edst; then
        expect 0 "the encrypted repository's client's token" -- "$BIN" --new-token en01.token
        printf 'repository = %s/edst\noperations = read, append\n%s\n' "$WORK" "$OUT" \
          > proxy.d/.en01.tmp
        chmod 0644 proxy.d/.en01.tmp
        mv proxy.d/.en01.tmp proxy.d/en01.conf
        ENC=1
      fi
    fi

    # restate itself through the proxy: what reads a repository, with the
    # client's token on a file and the proxy's certificate trusted by
    # --repository-ca-file. Its own files for curl go in a TMPDIR of the
    # test's, which has to be empty again after each run.
    start --max-sessions 2
    mkdir -m 0700 rtmp
    URL="https://127.0.0.1:$PORT/v1/up01"
    ON=(--repository-token-file "$WORK/up01.token" --repository-ca-file "$WORK/cert.pem")
    RUN=(env TMPDIR="$WORK/rtmp" XDG_CACHE_HOME="$WORK/rcache" "$RESTATE")
    left() { if [ -z "$(ls rtmp)" ]; then ok; else fail "$1: left $(ls rtmp)"; fi; }
    expect 0 "snapshots through the proxy" -- "${RUN[@]}" snapshots "${ON[@]}" "$URL"
    contains "$OUT" "$SNAP" "lists the snapshot"
    left "snapshots"
    expect 0 "list through the proxy" -- "${RUN[@]}" list "${ON[@]}" "$URL::$SNAP"
    contains "$OUT" "etc" "lists what it holds"
    rm -rf rout && mkdir rout
    expect 0 "restore through the proxy" -- \
      "${RUN[@]}" restore -q --allow-unverified --root rout "${ON[@]}" "$URL::$SNAP"
    if cmp -s tree/etc/one.conf rout/etc/one.conf; then ok; else fail "puts its files back"; fi
    left "restore"
    # restore --check-first reads every file twice, and the snapshot's index
    # for whose it is and then for its files, its accounts once more: in one
    # session, each file fetched from the proxy once. fetched_once WHAT
    # [CLIENT]: the server's log since $MARK has one session of CLIENT's
    # (up01's), and no file asked for twice.
    fetched_once() {
      local since opened twice client="${2:-up01}"
      since="$(tail -n "+$MARK" server.log)"
      opened="$(printf '%s\n' "$since" | grep -c "session-open client=$client")"
      if [ "$opened" = 1 ]; then ok; else fail "$1: one session, not $opened"; fi
      twice="$(printf '%s\n' "$since" | sed -n "s/.*method=GET target=\\(\\/v1\\/$client\\/f\\/[^ ]*\\) status=20.*/\\1/p" |
        sort | uniq -d)"
      if [ -z "$twice" ]; then ok; else fail "$1: fetched twice: $twice"; fi
    }
    rm -rf rout && mkdir rout
    MARK=$(($(wc -l < server.log) + 1))
    expect 0 "restore --check-first through the proxy" -- \
      "${RUN[@]}" restore -q --allow-unverified --check-first --root rout "${ON[@]}" "$URL::$SNAP"
    if cmp -s tree/etc/one.conf rout/etc/one.conf; then ok; else fail "checks it, then puts it back"; fi
    fetched_once "restore --check-first"
    left "restore --check-first"
    expect 0 "check through the proxy" -- "${RUN[@]}" check "${ON[@]}" "$URL"
    contains "$ERR" "the repository is whole" "reads it all, and finds it whole"
    expect 0 "copy out of the proxy, into a repository here" -- \
      "${RUN[@]}" copy "${ON[@]}" "$URL::$SNAP" "$WORK/pulled"
    expect 0 "which has the snapshot" -- "$RESTATE" snapshots pulled
    contains "$OUT" "$SNAP" "named as it was"
    # Every repository's cache: kept, so a second run asks only for what is new.
    # Root's is in the system's place, whatever XDG_CACHE_HOME says.
    CACHED=rcache/restate/repositories
    if [ "$(id -u)" = 0 ]; then
      case "$(uname -s)" in
        Darwin) CACHED=/Library/Caches/restate/repositories ;;
        *) CACHED=/var/cache/restate/repositories ;;
      esac
    fi
    if [ -n "$(ls "$CACHED" 2> /dev/null)" ]; then
      ok
    else
      fail "what was read is cached"
    fi

    # A capture through the proxy: made here, sent a pack at a time and
    # committed, and its snapshot last -- then found whole by restate on the
    # storage host, and read back through the proxy.
    mkdir -p tree3/etc
    printf 'three\n' > tree3/etc/three.conf
    # dd, not head -c, which OpenBSD's head does not have.
    dd if=/dev/urandom of=tree3/etc/big.bin bs=1000 count=300 2> /dev/null
    expect 0 "features says a capture can go through the proxy" -- "$RESTATE" features --json
    contains "$OUT" '"remote_capture": true' "says so"
    expect 0 "capture through the proxy" -- \
      "${RUN[@]}" capture -r tree3 --os=linux --result "$WORK/c.json" "${ON[@]}" -o "$URL"
    contains "$ERR" "restate: snapshot $URL::" "names the snapshot it made"
    contains "$(cat c.json)" "\"snapshot\": \"$URL::" "and so does its result"
    left "capture"
    SNAP3="$(sed -n 's/.*"snapshot": "[^"]*::\([^"]*\)".*/\1/p' c.json)"
    if [ -n "$SNAP3" ] && [ -d "dst/snapshots/$SNAP3" ]; then ok; else fail "it is there: $SNAP3"; fi
    expect 0 "the storage host finds it whole" -- "$RESTATE" check dst
    contains "$ERR" "the repository is whole" "every pack and snapshot"
    rm -rf rout3 && mkdir rout3
    expect 0 "restore what was captured through it" -- \
      "${RUN[@]}" restore -q --allow-unverified --root rout3 "${ON[@]}" "$URL::$SNAP3"
    if cmp -s tree3/etc/big.bin rout3/etc/big.bin; then ok; else fail "its files come back"; fi
    PACKS="$(find dst/packs -name '*.idx' | wc -l)"
    expect 0 "capture the same again through the proxy" -- \
      "${RUN[@]}" capture -r tree3 --os=linux "${ON[@]}" -o "$URL"
    contains "$ERR" "0 bytes new to the repository" "stores nothing twice"
    if [ "$(find dst/packs -name '*.idx' | wc -l)" = "$PACKS" ]; then ok; else fail "and adds no pack"; fi
    left "a capture with nothing new"
    if [ -z "$(find staging -type f 2> /dev/null)" ]; then ok; else fail "the proxy's staging is left empty"; fi

    # A copy into it, as a capture is made: packs, then the snapshot.
    SRC2=
    for d in src/snapshots/*; do SRC2="$(basename "$d")"; done
    expect 0 "copy into the proxy" -- "${RUN[@]}" copy "${ON[@]}" "src::$SRC2" "$URL"
    if [ -d "dst/snapshots/$SRC2" ]; then ok; else fail "the copy is there"; fi
    expect 0 "and still whole" -- "$RESTATE" check dst
    left "copy into the proxy"

    # What compares and plans reads through it as from a path: diff of two of
    # its snapshots, status of a tree against one, du, and restore --plan.
    expect 1 "diff of two snapshots through the proxy" -- \
      "${RUN[@]}" diff "${ON[@]}" "$URL::$SNAP" "$URL::$SNAP3"
    contains "$OUT" "/etc/big.bin" "finds what the second added"
    left "diff"
    expect 0 "status of a tree against its snapshot through the proxy" -- \
      "${RUN[@]}" status -r tree3 "${ON[@]}" "$URL::$SNAP3"
    expect 1 "and of one it differs from" -- "${RUN[@]}" status -r tree3 "${ON[@]}" "$URL::$SNAP"
    contains "$OUT" "/etc/big.bin" "finds what is not in it"
    left "status"
    expect 0 "du through the proxy" -- "${RUN[@]}" du "${ON[@]}" "$URL"
    contains "$OUT" "$SNAP3" "accounts for each snapshot"
    left "du"
    rm -rf rout5 && mkdir rout5
    expect 0 "restore --plan through the proxy" -- \
      "${RUN[@]}" restore --plan --allow-unverified --root rout5 "${ON[@]}" "$URL::$SNAP3"
    contains "$OUT" "would restore /etc/big.bin" "says what it would put back"
    if [ -z "$(ls -A rout5)" ]; then ok; else fail "and puts nothing back"; fi
    left "restore --plan"

    # A job's repository can be the proxy, its token in repository_token_file
    # -- held to what passphrase_file is: nobody else may read it.
    cat > restore.job << EOF
command = restore
snapshot = $URL::$SNAP3
repository_token_file = $WORK/up01.token
repository_ca_file = $WORK/cert.pem
restore_root = $WORK/rout5
allow_unverified = true
EOF
    chmod 0600 restore.job
    expect 0 "a restore job through the proxy" -- "${RUN[@]}" run restore.job
    if cmp -s tree3/etc/big.bin rout5/etc/big.bin; then ok; else fail "puts its files back"; fi
    left "a restore job"
    chmod 0644 up01.token
    expect 2 "a job whose token file others can read" -- "${RUN[@]}" run restore.job
    contains "$ERR" "repository_token_file" "is not run, and says why"
    expect 2 "and the same on the command line" -- "${RUN[@]}" snapshots "${ON[@]}" "$URL"
    contains "$ERR" "no one else can read" "is refused"
    chmod 0600 up01.token

    # Busy: another append session holds its lock, so exit 5, for a job to
    # try again.
    ask -H "$UP" -d append /v1/up01/sessions
    HOLD="$(printf '%s\n' "$OUT" | tail -n 1)"
    expect 5 "a capture while another holds the lock" -- \
      "${RUN[@]}" capture -q -r tree3 --os=linux "${ON[@]}" -o "$URL"
    contains "$ERR" "423 busy" "says so"
    ask -X POST -H "$UP" "/v1/up01/sessions/$HOLD/end"
    left "a capture that was busy"

    if [ -n "$ENC" ]; then
      EURL="https://127.0.0.1:$PORT/v1/en01"
      EON=(--repository-token-file "$WORK/en01.token" --repository-ca-file "$WORK/cert.pem")
      expect 0 "capture --encrypt-to --sign-with through the proxy" -- \
        "${RUN[@]}" capture -q -r tree3 --os=linux --encrypt-to enc.pub --sign-with signer.sec \
        "${EON[@]}" -o "$EURL"
      if [ -f edst/chunk-key ]; then ok; else fail "its chunking key is put there"; fi
      if [ -n "$(find edst/snapshots -name index.sig)" ]; then ok; else fail "its index is signed"; fi
      printf 'more\n' > tree3/etc/more.conf
      expect 0 "and again, with something new" -- \
        "${RUN[@]}" capture -q -r tree3 --os=linux --encrypt-to enc.pub "${EON[@]}" -o "$EURL"
      expect 0 "the encrypted repository is whole on the storage host" -- \
        "$RESTATE" check --metadata-only edst
      expect 0 "its signature holds, read through the proxy" -- \
        "${RUN[@]}" snapshots --json --trusted-key signer.pub "${EON[@]}" "$EURL"
      contains "$OUT" '"trusted": true' "by the key that signed it"
      left "an encrypted capture"
      # What a restore of an encrypted repository fetches is whole packs, to
      # decrypt: with --check-first, each still crosses once.
      ESNAP="$(find edst/snapshots -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
      rm -rf rout4 && mkdir rout4
      MARK=$(($(wc -l < server.log) + 1))
      expect 0 "restore --check-first of an encrypted snapshot through the proxy" -- \
        env GNUPGHOME="$WORK/gnupg" "${RUN[@]}" restore -q --allow-unverified --check-first \
        --root rout4 "${EON[@]}" "$EURL::${ESNAP##*/}"
      if cmp -s tree3/etc/big.bin rout4/etc/big.bin; then ok; else fail "decrypts it, checks it, puts it back"; fi
      fetched_once "an encrypted restore --check-first" en01
      left "an encrypted restore"
      GNUPGHOME="$WORK/gnupg" gpgconf --kill gpg-agent 2> /dev/null || true
    else
      printf '  - encrypted captures through the proxy not run: they need gpg\n'
    fi

    # What changes what a repository holds is the storage host's.
    expect 2 "prune through the proxy" -- "${RUN[@]}" prune --keep-last 1 "${ON[@]}" "$URL"
    contains "$ERR" "run on the storage host" "is the storage host's"
    expect 2 "sign through the proxy" -- \
      "${RUN[@]}" sign --sign-with x "${ON[@]}" "$URL::$SNAP"
    contains "$ERR" "capture --sign-with" "says how to sign instead"
    expect 2 "init through the proxy" -- "${RUN[@]}" init "$URL"
    expect 2 "protect through the proxy" -- "${RUN[@]}" protect "${ON[@]}" "$URL"
    contains "$ERR" "run on the storage host" "is the storage host's"
    left "what is refused"

    # Its token: needed, the client's own, and never on a command line.
    expect 2 "no token" -- "${RUN[@]}" snapshots --repository-ca-file "$WORK/cert.pem" "$URL"
    contains "$ERR" "--repository-token-file" "says what it needs"
    expect 2 "another client's token" -- \
      "${RUN[@]}" snapshots --repository-token-file "$WORK/db01.token" \
      --repository-ca-file "$WORK/cert.pem" --result "$WORK/r.json" "$URL"
    contains "$ERR" "401 unauthorized" "is refused"
    contains "$(cat r.json)" '"proxy_reason": "unauthorized"' "and its result says why"
    expect 2 "a proxy it does not trust" -- \
      "${RUN[@]}" snapshots --repository-token-file "$WORK/up01.token" "$URL"
    contains "$ERR" "the proxy did not answer" "is not asked"
    expect 2 "a key that is not the proxy's" -- "${RUN[@]}" snapshots "${ON[@]}" \
      --repository-pin-sha256 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU= "$URL"
    expect 2 "a URL with more after the client" -- "${RUN[@]}" snapshots "${ON[@]}" "$URL/x"
    contains "$ERR" "https://HOST[:PORT]/v1/CLIENT" "says what one is"
    # A proxy at an IPv6 address: "::" of its own, and REPO::NAME after it.
    expect 2 "a snapshot behind a proxy at an IPv6 address" -- \
      "${RUN[@]}" list "${ON[@]}" "https://[::1]:1/v1/up01::$SNAP"
    contains "$ERR" "the proxy did not answer" "is taken for the proxy and the snapshot"
    left "what failed"

    # A proxy at its limit of sessions: busy, exit 5, for a job to try again.
    ask -H "$UP" -d look /v1/up01/sessions
    S1="$(printf '%s\n' "$OUT" | tail -n 1)"
    ask -H "$UP" -d look /v1/up01/sessions
    S2="$(printf '%s\n' "$OUT" | tail -n 1)"
    expect 5 "a proxy with no session to spare" -- "${RUN[@]}" snapshots "${ON[@]}" "$URL"
    contains "$ERR" "503 sessions-full" "says so"
    ask -X POST -H "$UP" "/v1/up01/sessions/$S1/end"
    ask -X POST -H "$UP" "/v1/up01/sessions/$S2/end"

    # A run stopped as it reads ends its session all the same: the child
    # that renews the lease ends it once restate is gone, however it went.
    "${RUN[@]}" restore -q --allow-unverified --root rout --plan "${ON[@]}" "$URL::$SNAP" \
      > /dev/null 2>&1 &
    RPID=$!
    kill -KILL "$RPID" 2> /dev/null
    wait "$RPID" 2> /dev/null
    sleep 1
    stop
    OPENED="$(grep -c 'session-open client=up01' server.log)"
    ENDED="$(grep -c 'session-end client=up01' server.log)"
    if [ "$OPENED" -gt 0 ] && [ "$OPENED" = "$ENDED" ]; then
      ok
    else
      fail "every session opened is ended ($OPENED opened, $ENDED ended)"
    fi
    if grep -Eq '/sessions/[0-9a-f]{32}' server.log; then
      fail "the log names a session"
    else
      ok
    fi
    lacks "$(cat server.log)" "$(cat up01.token)" "nor its token"

    # A capture cut off part way, once a pack is committed and before the
    # snapshot is. capture_cut STOPHOW: restate run in a process group of
    # its own (set -m), to be killed as the machine it runs on would stop --
    # "all", restate, its renewer and curl at once, as a crash or a cut
    # cable does, so nothing ends its session; "restate", restate alone, as
    # the OOM killer does, so its renewer ends it; "term", SIGTERM to restate
    # alone, which it stops on. $CUT is 1 if it was cut off where it should
    # be, and the session's id is left in $CUTSESS.
    mkdir -p tree4/etc
    for n in 1 2 3; do dd if=/dev/urandom of="tree4/etc/big$n.bin" bs=1048576 count=40 2> /dev/null; done
    capture_cut() {
      local mark
      CUT=0
      CUTSESS=
      # Only what the server logs from here on: an earlier capture's
      # commits are in its log too. grep reads it all, not -q: under
      # pipefail, a grep -q that stops at its match can leave tail killed by
      # SIGPIPE, and the pipeline false for what it found.
      mark=$(($(wc -l < server.log) + 1))
      since() { tail -n "+$mark" server.log | grep -- "$1" > /dev/null; }
      set -m
      "${RUN[@]}" capture -q -r tree4 --os=linux "${ON[@]}" -o "$URL" > /dev/null 2>&1 &
      CPID=$!
      set +m
      for _ in $(seq 1 600); do
        if since 'target=/v1/up01/sessions/[^ ]*/commit/packs/.* status=201'; then
          break
        fi
        sleep 0.1
      done
      case "$1" in
        all) kill -KILL -- "-$CPID" 2> /dev/null ;;
        term) kill -TERM "$CPID" 2> /dev/null ;;
        *) kill -KILL "$CPID" 2> /dev/null ;;
      esac
      wait "$CPID" 2> /dev/null
      if since 'commit/packs/.* status=201' && ! since 'commit/snapshots/'; then
        CUT=1
      fi
      CUTSESS="$(sessions_staged | head -n 1)"
      # With everything killed, nothing is left to remove restate's own
      # files for curl. Otherwise its renewer still needs them -- its token
      # among them -- to end the session, and removes them itself after.
      if [ "$1" = all ]; then
        rm -rf rtmp/* 2> /dev/null
      fi
    }
    # cut_ended: restate's renewer has ended the session cut off -- its packs
    # taken out, its staging and restate's own files gone -- within ten
    # seconds, however slow the machine.
    cut_ended() {
      local _
      for _ in $(seq 1 100); do
        [ "$(packs_of)" = "$BEFORE" ] && [ -z "$(sessions_staged)" ] && [ -z "$(ls rtmp)" ] &&
          return 0
        sleep 0.1
      done
      return 1
    }
    # dst's packs before, to see that a cut-off capture leaves none behind;
    # and the sessions' staging directories in the proxy's staging.
    packs_of() { find dst/packs -name '*.idx' | sort; }
    sessions_staged() {
      local d
      for d in staging/up01/*; do
        case "${d##*/}" in
          [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) [ -d "$d" ] && printf '%s\n' "${d##*/}" ;;
        esac
      done
    }
    BEFORE="$(packs_of)"

    # Everything killed at once: the session is left open, its lock held and
    # its packs in, until its lease runs out; then the proxy takes it all out.
    # A lease of 12 seconds: longer than the renewer's least interval (5), so
    # the session cannot lapse in a pause before it is cut off, however slow
    # the build (coverage is); and short enough to wait out.
    start --lease 12
    URL="https://127.0.0.1:$PORT/v1/up01"
    capture_cut all
    if [ "$CUT" = 1 ]; then ok; else fail "the capture was cut off between a pack's commit and its snapshot's"; fi
    if [ -n "$CUTSESS" ]; then ok; else fail "the cut-off session's staging is still there while its lease runs"; fi
    if [ "$(packs_of)" != "$BEFORE" ]; then ok; else fail "the pack it committed is in the repository until then"; fi
    for _ in $(seq 1 120); do
      grep -q 'session-end client=up01 kind=append.*result=expired' server.log && break
      sleep 0.25
    done
    contains "$(cat server.log)" "result=expired" "the lease runs out, and the proxy ends the session"
    if [ -z "$CUTSESS" ] || [ ! -e "staging/up01/$CUTSESS" ]; then ok; else fail "its staging is removed when it expires"; fi
    if [ "$(packs_of)" = "$BEFORE" ]; then ok; else fail "the packs it committed are taken out again"; fi
    expect 0 "the repository is whole after a capture cut off" -- "$RESTATE" check dst
    if flock -n dst/lock true 2> /dev/null || ! command -v flock > /dev/null 2>&1; then
      ok
    else
      fail "its lock is let go"
    fi
    expect 0 "the next capture goes in" -- \
      "${RUN[@]}" capture -q -r tree3 --os=linux "${ON[@]}" -o "$URL"
    left "the capture after one cut off"

    # restate alone killed: its renewer ends the session at once, with no
    # lease to wait out, and the same is taken out again. A lease of its own,
    # 30 seconds: one of 4 is shorter than the renewer's least interval (5),
    # so a pause in the capture could let it lapse before it is cut off; and
    # 30 is longer than this waits, so only the renewer could end it in time.
    stop
    start --lease 30
    URL="https://127.0.0.1:$PORT/v1/up01"
    BEFORE="$(packs_of)"
    capture_cut restate
    if [ "$CUT" = 1 ]; then ok; else fail "the second capture was cut off between a pack's commit and its snapshot's"; fi
    if cut_ended; then ok; else fail "with restate alone killed, its packs are taken out at once"; fi
    contains "$(grep 'session-end client=up01 kind=append' server.log)" "result=ended" \
      "ended by its renewer, not by the lease"
    expect 0 "and the repository is whole" -- "$RESTATE" check dst

    # SIGTERM, as a service manager or a job's timeout stops it: restate
    # stops, and its session is ended and its packs taken out, as above.
    BEFORE="$(packs_of)"
    ENDED="$(grep -c 'session-end client=up01 kind=append.*result=ended' server.log)"
    capture_cut term
    if [ "$CUT" = 1 ]; then ok; else fail "the third capture was cut off between a pack's commit and its snapshot's"; fi
    if cut_ended; then ok; else fail "with SIGTERM, its packs are taken out at once"; fi
    if [ "$(grep -c 'session-end client=up01 kind=append.*result=ended' server.log)" -gt "$ENDED" ]; then
      ok
    else
      fail "a capture stopped by SIGTERM has its session ended"
    fi
    expect 0 "and the repository is whole after it" -- "$RESTATE" check dst
    stop
    rm -rf tree4

    # A grant's own limits -- sessions at once, and bandwidth by the hour --
    # and the quota hook. up01_grant LINE...: up01's grant, with LINEs.
    UPTOK="$(grep '^token_sha256' proxy.d/up01.conf)"
    up01_grant() {
      {
        printf 'repository = %s/dst\noperations = read, append\n%s\n' "$WORK" "$UPTOK"
        [ "$#" -gt 0 ] && printf '%s\n' "$@"
      } > proxy.d/.up01.tmp
      chmod 0644 proxy.d/.up01.tmp
      mv proxy.d/.up01.tmp proxy.d/up01.conf
    }
    up01_grant "bandwidth = 08-18 1KiB/s"
    expect 2 "--check-grants with a bandwidth less than there can be" -- \
      "$BIN" --check-grants proxy.d
    contains "$OUT" "64KiB/s at the least" "says what the least is"
    up01_grant "bandwidth = 08-18 1MiB/s" "bandwidth = 08-09 2MiB/s"
    expect 2 "--check-grants with an hour in two ranges" -- "$BIN" --check-grants proxy.d
    contains "$OUT" "the hour from 08:00 is in two of its ranges" "says which"
    up01_grant "max_sessions = 1" "bandwidth = 128KiB/s"
    expect 0 "--check-grants with max_sessions and a bandwidth" -- "$BIN" --check-grants proxy.d

    expect 2 "--quota-hook that is not an absolute path" -- \
      "$BIN" --serve --listen 127.0.0.1:0 --cert cert.pem --key key.pem --grants proxy.d \
      --quota-hook quota.sh
    contains "$ERR" "not an absolute path" "is refused as it starts"
    expect 2 "--quota-hook that is not there" -- \
      "$BIN" --serve --listen 127.0.0.1:0 --cert cert.pem --key key.pem --grants proxy.d \
      --quota-hook "$WORK/none.sh"
    # The hook: what it is asked, kept; and no to an upload while "over" is.
    # shellcheck disable=SC2016  # its variables are the hook's, expanded as it runs
    {
      printf '#!/bin/sh\n'
      printf 'printf "%%s %%s %%s\\n" "$RESTATE_PROXY_EVENT" "$RESTATE_PROXY_CLIENT" '
      printf '"$RESTATE_PROXY_BYTES" >> "%s/quota.log"\n' "$WORK"
      printf 'if [ -e "%s/over" ] && [ "$RESTATE_PROXY_EVENT" = upload ]; then\n' "$WORK"
      printf '  echo "up01 is over its 1 GiB"\n  exit 1\nfi\nexit 0\n'
    } > quota.sh
    chmod 0755 quota.sh
    : > quota.log
    start --quota-hook "$WORK/quota.sh"
    URL="https://127.0.0.1:$PORT/v1/up01"
    contains "$(cat server.log)" "quota_hook=$WORK/quota.sh" "it says it has a quota hook"

    # max_sessions = 1: with one open, the next is refused, exit 5.
    ask -H "$UP" -d look /v1/up01/sessions
    S1="$(printf '%s\n' "$OUT" | tail -n 1)"
    expect 5 "a session past the grant's max_sessions" -- \
      "${RUN[@]}" snapshots --result "$WORK/r.json" "${ON[@]}" "$URL"
    contains "$ERR" "503 client-sessions-full" "says so"
    contains "$(cat r.json)" '"proxy_reason": "client-sessions-full"' "and its result says why"
    ask -X POST -H "$UP" "/v1/up01/sessions/$S1/end"
    expect 0 "and once it ends, there is room" -- "${RUN[@]}" snapshots "${ON[@]}" "$URL"
    left "a session past max_sessions"

    # 128KiB/s: a restore of 300,000 bytes takes two seconds at the least.
    rm -rf rout6 && mkdir rout6
    BEGAN=$SECONDS
    expect 0 "a restore at the grant's bandwidth" -- \
      "${RUN[@]}" restore -q --allow-unverified --root rout6 "${ON[@]}" "$URL::$SNAP3"
    if [ $((SECONDS - BEGAN)) -ge 2 ]; then ok; else fail "is paced: $((SECONDS - BEGAN)) s"; fi
    if cmp -s tree3/etc/big.bin rout6/etc/big.bin; then ok; else fail "and puts it back whole"; fi
    left "a restore at a bandwidth"

    # The quota hook: asked as a capture opens its session and before each
    # upload; a no stops the capture, with what the hook said.
    up01_grant
    sleep 3
    printf 'over quota\n' > tree3/etc/quota.conf
    : > quota.log
    expect 0 "a capture the quota hook says yes to" -- \
      "${RUN[@]}" capture -q -r tree3 --os=linux "${ON[@]}" -o "$URL"
    contains "$(head -n 1 quota.log)" "open up01 0" "it is asked as the session opens"
    contains "$(cat quota.log)" "upload up01 " "and before each upload"
    : > over
    printf 'more\n' > tree3/etc/quota2.conf
    PACKS="$(find dst/packs -name '*.idx' | wc -l)"
    expect 2 "a capture the quota hook says no to" -- \
      "${RUN[@]}" capture -q -r tree3 --os=linux --result "$WORK/r.json" "${ON[@]}" -o "$URL"
    contains "$ERR" "up01 is over its 1 GiB" "says what the hook said"
    contains "$ERR" "507 quota-exceeded" "and why"
    contains "$(cat r.json)" '"proxy_reason": "quota-exceeded"' "and so does its result"
    contains "$(cat server.log)" 'quota-refused client=up01 event=upload message="up01 is over its 1 GiB"' \
      "the proxy's log says so"
    if [ "$(find dst/packs -name '*.idx' | wc -l)" = "$PACKS" ]; then ok; else fail "and nothing is stored"; fi
    left "a capture over its quota"
    rm -f over tree3/etc/quota.conf tree3/etc/quota2.conf
    stop
  else
    printf '  - uploads not run: restate is not beside %s\n' "$BIN"
  fi

  # A connection that says nothing: refused past --max-connections, and
  # dropped after --idle-timeout.
  start --max-connections 1 --idle-timeout 2
  exec 3<> "/dev/tcp/127.0.0.1/$PORT"
  sleep 0.5
  ask /v1/
  if [ "$CODE" != 200 ]; then ok; else fail "a second connection past --max-connections 1"; fi
  contains "$(cat server.log)" "connection-refused" "is refused"
  sleep 3
  contains "$(cat server.log)" "tls-refused" "the silent one is dropped once idle"
  exec 3>&-
  ask /v1/
  is 200 "and then there is room again"
  stop
else
  printf '  - --serve not run: it needs curl and openssl(1)\n'
  [ -s openssl.err ] && sed 's/^/      openssl: /' openssl.err | head -5
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '  \033[92m✓\033[0m %d restate-proxy checks passed\n\n' "$PASS"
  exit 0
fi
printf '  \033[91m✗\033[0m %d of %d restate-proxy checks failed\n\n' "$FAIL" $((PASS + FAIL))
exit 1
