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

if command -v curl > /dev/null 2>&1 && command -v openssl > /dev/null 2>&1 &&
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
    -keyout key.pem -out cert.pem > /dev/null 2>&1; then
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
    CODE="$(printf '%s\n' "$OUT" | sed -n '1s/^HTTP\/1\.1 \([0-9]*\).*/\1/p')"
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
    head -c 5000 /dev/zero > big.sum
    ask -H "$UP" -T big.sum "/v1/up01/sessions/$REF/files/packs/P-1.sum"
    is 413 "a .sum larger than restate writes one"
    contains "$OUT" "Restate-Reason: too-large" "says so"
    head -c 2000000 /dev/zero > big.idx
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
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '  \033[92m✓\033[0m %d restate-proxy checks passed\n\n' "$PASS"
  exit 0
fi
printf '  \033[91m✗\033[0m %d of %d restate-proxy checks failed\n\n' "$FAIL" $((PASS + FAIL))
exit 1
