#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# MITRE's "Lucky 13", checked one by one.
#
#   make lucky13
#
# Steve Christey's "Unforgivable Vulnerabilities" (MITRE, Black Hat USA 2007)
# lists thirteen vulnerability classes so well documented and so easy to find
# that shipping one is unforgivable:
#
#    1. buffer overflow           CWE-120     8. authentication bypass   CWE-472
#    2. cross-site scripting      CWE-79      9. grow-your-own crypto    CWE-327
#    3. directory traversal       CWE-23     10. privilege escalation    CWE-271
#    4. remote file inclusion     CWE-98     11. symlink following       CWE-61
#    5. SQL injection             CWE-89     12. hard-coded password     CWE-259
#    6. world-writable files      CWE-276    13. integer overflow        CWE-190
#    7. direct request            CWE-425
#
# Every one is accounted for here, by number. Where a class can occur in a
# program like this one it is tested -- against the source, against the built
# binary, or both. Where it cannot (restate has no web interface, no database
# and no login) the line says so and why, and a close analogue is tested
# instead where one applies.
#
# Static checks read the source with comments removed, by the compiler's own
# preprocessor, so a comment explaining why strcpy is not used does not count
# as a use of strcpy.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

CC="${CC:-cc}"
RESTATE="${RESTATE:-$REPO_ROOT/bin/restate}"
FAILURES=()
SKIPPED=()

section() { printf '\n\033[1;94m▸ %s\033[0m\n' "$*"; }
ok()      { printf '  \033[92m✓\033[0m %s\n' "$*"; }
bad()     { printf '  \033[91m✗\033[0m %s\n' "$*"; FAILURES+=("$1"); }
skip()    { printf '  \033[93m-\033[0m %s\n' "$*"; SKIPPED+=("$1"); }
na()      { printf '  \033[96m○\033[0m %s\n' "$*"; }
note()    { printf '    \033[2m%s\033[0m\n' "$*"; }

printf '\n\033[1mMITRE "Lucky 13"\033[0m \033[2m(Christey, Unforgivable Vulnerabilities, 2007)\033[0m\n'

if [ ! -x "$RESTATE" ]; then
  printf '  \033[91m✗\033[0m %s is not built — run make build first\n\n' "$RESTATE"
  exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-lucky13.XXXXXX")" || exit 1
trap 'chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

# The program's source with every comment gone, one file after another.
# The #include lines are dropped first, so what comes out is only our own
# code and not the system headers the preprocessor would paste in.
SOURCE="$WORK/source.i"
: > "$SOURCE"
for f in src/*.c; do
  sed -e 's|^#include.*||' "$f" \
    | "$CC" -E -P -x c - 2>/dev/null | sed "s|^|$f: |" >> "$SOURCE"
done

# Every static check below passes on an empty file, so an empty file is itself
# a failure: a preprocessor that silently produced nothing would otherwise make
# this whole report a list of green ticks about nothing.
if [ "$(grep -c 'rs_xmalloc' "$SOURCE")" -lt 2 ]; then
  printf '  \033[91m✗\033[0m could not read the source through %s -E\n\n' "$CC"
  exit 1
fi

# grep_source PATTERN -- the matching lines of comment-free source, if any.
grep_source() { grep -nE "$1" "$SOURCE" || true; }

# verdict GOOD-MESSAGE BAD-MESSAGE COMMAND... -- ok if the command succeeds.
verdict() {
  local good="$1" badmsg="$2"
  shift 2
  if "$@"; then
    ok "$good"
  else
    bad "$badmsg"
  fi
}

# no_hits GOOD-MESSAGE BAD-MESSAGE HITS -- ok if HITS is empty, else show them.
no_hits() {
  if [ -z "$3" ]; then
    ok "$1"
  else
    bad "$2"
    printf '%s\n' "$3" | head -5 | sed 's/^/      /'
  fi
}

export SOURCE_DATE_EPOCH=1700000000

# ---------------------------------------------------------------------------
section "1. buffer overflow (CWE-120)"
HITS="$(grep_source '\b(strcpy|strcat|sprintf|vsprintf|gets|stpcpy|wcscpy|scanf)[[:space:]]*\(')"
if [ -z "$HITS" ]; then
  ok "no unbounded copy, concatenation or formatting in the source"
else
  bad "unbounded string functions are used"
  printf '%s\n' "$HITS" | head -5 | sed 's/^/      /'
fi
# A path a thousand times longer than any real one, through every parser.
INDEX_HEAD='{"format": "restate-index", "version": 1, "entries": ['
INDEX_TAIL=', "type": "file", "class": "state", "mode": "0644", "uid": 0, "gid": 0, "size": 0, "mtime": "2026-01-01T00:00:00.000000000Z"}]}'
LONG="$(head -c 200000 /dev/zero | tr '\0' 'a')"
printf '%s{"path": "/%s"%s' "$INDEX_HEAD" "$LONG" "$INDEX_TAIL" > "$WORK/long.json"
"$RESTATE" diff "$WORK/long.json" "$WORK/long.json" > /dev/null 2>&1
status=$?
verdict "a 200 KB path is handled whole" "a 200 KB path made restate exit $status" \
  test "$status" -eq 0
note "the sanitizers and the fuzzer cover the rest: make test-memory, make fuzz"

# ---------------------------------------------------------------------------
section "2. cross-site scripting (CWE-79)"
na "not applicable: restate produces no HTML and serves nothing"
note "the closest thing is injection into its own JSON: a hostile file name"
note "must not be able to add a field or an entry to the index:"
mkdir -p "$WORK/xss/tree"
: > "$WORK/xss/tree/$(printf 'a", "class": "ephemeral\n<script>"')"
if "$RESTATE" -N -r "$WORK/xss/tree" scan -q > "$WORK/xss.json" 2>/dev/null \
   && "$RESTATE" diff "$WORK/xss.json" "$WORK/xss.json" > /dev/null 2>&1 \
   && [ "$(grep -c '"class": "ephemeral' "$WORK/xss.json")" -eq 0 ]; then
  ok "a file name full of quotes and a newline stays one escaped string"
else
  bad "a file name with quotes and a newline broke the index"
fi

# ---------------------------------------------------------------------------
section "3. directory traversal (CWE-23)"
for path in '/etc/../../root/.ssh/id_rsa' '/./etc' 'etc/passwd' '//etc' '/etc/'; do
  printf '%s{"path": "%s"%s' "$INDEX_HEAD" "$path" "$INDEX_TAIL" > "$WORK/trav.json"
  if "$RESTATE" diff "$WORK/trav.json" "$WORK/trav.json" > /dev/null 2> "$WORK/trav.err"; then
    bad "an index naming $path was accepted"
  elif grep -q "not a clean absolute path" "$WORK/trav.err"; then
    ok "an index naming $path is refused"
  else
    bad "an index naming $path failed, but not for the right reason"
  fi
done
# The same, smuggled in exact bytes: "/etc/../x" in base64.
printf '%s{"path": "/ok", "path_base64": "L2V0Yy8uLi94"%s' "$INDEX_HEAD" "$INDEX_TAIL" > "$WORK/trav.json"
if "$RESTATE" diff "$WORK/trav.json" "$WORK/trav.json" > /dev/null 2>&1; then
  bad "a traversal path hidden in path_base64 was accepted"
else
  ok "a traversal path hidden in path_base64 is refused"
fi
if "$RESTATE" classify /etc/../x > /dev/null 2>&1; then
  bad "classify accepted a path with .."
else
  ok "classify refuses a path with .."
fi

# ---------------------------------------------------------------------------
section "4. remote file inclusion (CWE-98)"
# restate loads no code and opens no connection itself. The one download --
# `restate installer fetch` -- is curl's, HTTPS only, and nothing it fetches
# is used until its signature has been checked against a pinned key.
HITS="$(grep_source '\b(dlopen|dlsym|socket|connect|getaddrinfo|curl_)[[:space:]]*\(')"
no_hits "no dynamic loading and no networking in the source" \
  "dynamic loading or networking found" "$HITS"
if grep -q '"=https"' src/installer.c && grep -q '"--proto-redir"' src/installer.c \
   && grep -q '"-q"' src/installer.c; then
  ok "curl is held to HTTPS, redirects included, and ignores ~/.curlrc"
else
  bad "curl is no longer held to HTTPS with ~/.curlrc ignored"
fi
if grep -q 'VALIDSIG' src/installer.c && grep -q 'key->fingerprint' src/installer.c; then
  ok "a download counts only when gpgv names the pinned key's fingerprint"
else
  bad "the signature check no longer requires the pinned fingerprint"
fi
HITS="$(grep -n 'rs_installer_set_key' src/*.c | grep -v '^src/installer.c:' || true)"
no_hits "nothing in the program can change which key is trusted" \
  "the signing key is changed outside the tests" "$HITS"

# ---------------------------------------------------------------------------
section "5. SQL injection (CWE-89)"
na "not applicable: restate has no database; a manifest is a sorted text file"
HITS="$(grep_source '\bsqlite3?_|\bmysql_|\bPQexec')"
no_hits "no database client in the source" "a database client appeared in the source" "$HITS"

# ---------------------------------------------------------------------------
section "6. world-writable files (CWE-276)"
mkdir -p "$WORK/ww/tree"
echo x > "$WORK/ww/tree/f"
( umask 000 && "$RESTATE" -N -r "$WORK/ww/tree" -o "$WORK/ww/out.json" scan -q )
MODE="$(stat -c '%a' "$WORK/ww/out.json" 2>/dev/null || stat -f '%Lp' "$WORK/ww/out.json")"
verdict "an index is created 0600 even under umask 000" \
  "an index written under umask 000 is mode $MODE" test "$MODE" = "600"
( umask 000 && "$RESTATE" -N -r "$WORK/ww/tree" -o "$WORK/ww/out.tgz" capture -q )
MODE="$(stat -c '%a' "$WORK/ww/out.tgz" 2>/dev/null || stat -f '%Lp' "$WORK/ww/out.tgz")"
verdict "an image is created 0600 even under umask 000" \
  "an image written under umask 000 is mode $MODE" test "$MODE" = "600"
( umask 000 && "$RESTATE" -N -r "$WORK/ww/tree" scan -q > /dev/null )
if grep -qE 'install -m 0?7?77|chmod [0-7]*[2367][^ ]*\b' scripts/install.sh; then
  bad "the installer creates something world-writable"
else
  ok "the installer installs 0755 and 0644, nothing writable by others"
fi

# ---------------------------------------------------------------------------
section "7. direct request (CWE-425)"
na "not applicable: restate is a command, not a service, and has no endpoints"

# ---------------------------------------------------------------------------
section "8. authentication bypass (CWE-472)"
na "not applicable: restate authenticates nobody; it runs with the caller's"
note "own privileges and never raises them (see 10)"

# ---------------------------------------------------------------------------
section "9. grow-your-own crypto (CWE-327)"
ok "SHA-256 is FIPS 180-4, checked against the published vectors in the unit tests"
note "not MD5: an MD5 collision can be manufactured, so a planted file could pass"
printf 'The quick brown fox jumps over the lazy dog' > "$WORK/fox"
mkdir -p "$WORK/crypto/tree"
cp "$WORK/fox" "$WORK/crypto/tree/fox"
OURS="$("$RESTATE" -N -r "$WORK/crypto/tree" scan -q | grep '"path": "/fox"' \
        | sed 's/.*"sha256": "\([0-9a-f]*\)".*/\1/')"
if command -v sha256sum > /dev/null 2>&1; then
  THEIRS="$(sha256sum "$WORK/fox" | cut -d' ' -f1)"
elif command -v shasum > /dev/null 2>&1; then
  THEIRS="$(shasum -a 256 "$WORK/fox" | cut -d' ' -f1)"
elif command -v sha256 > /dev/null 2>&1; then
  THEIRS="$(sha256 -q "$WORK/fox")"
else
  THEIRS=""
fi
if [ -z "$THEIRS" ]; then
  skip "no system sha256 tool to compare the binary's digest against"
elif [ "$OURS" = "$THEIRS" ]; then
  ok "the binary's digest of a real file agrees with the system's"
else
  bad "the binary's digest ($OURS) disagrees with the system's ($THEIRS)"
fi
note "the digest identifies content; nothing here encrypts, signs or authenticates"

# ---------------------------------------------------------------------------
section "10. privilege escalation (CWE-271)"
HITS="$(grep_source '\b(setuid|seteuid|setreuid|setresuid|setgid|setegid|setregid|setresgid)[[:space:]]*\(')"
no_hits "restate never changes identity" "identity changes found" "$HITS"
# Four programs are run -- gzip, curl, gpgv and gpg -- from one file, by
# absolute path, only if root owns them and their directory, with posix_spawn,
# no shell and a fixed environment. Anything more is a finding.
HITS="$(grep_source '\b(system|popen|execl|execlp|execle|execv|execvp|execvpe|execve|posix_spawnp|fork|vfork)[[:space:]]*\(')"
no_hits "no shell, no exec family, and no program found through PATH" \
  "a shell, an exec or a PATH lookup is used to run something" "$HITS"
HITS="$(grep_source '\bposix_spawn[[:space:]]*\(' | grep -v '^[0-9]*:src/run.c: ')"
no_hits "posix_spawn appears only in src/run.c" "posix_spawn is called outside src/run.c" "$HITS"
if grep -q '"/usr/bin/gzip", "/bin/gzip"' src/run.c \
   && grep -q '"/usr/bin/curl", "/usr/local/bin/curl", "/bin/curl"' src/run.c \
   && grep -q '"/usr/bin/gpgv", "/usr/local/bin/gpgv", "/bin/gpgv"' src/run.c \
   && grep -q '"/usr/bin/gpg", "/usr/local/bin/gpg", "/bin/gpg"' src/run.c \
   && grep -q 'PATH=/usr/bin:/bin' src/run.c; then
  ok "gzip, curl, gpgv and gpg are run from fixed absolute paths, with a fixed environment"
else
  bad "a program is no longer run from a fixed path with a fixed environment"
fi
if grep -q 'st->st_uid == 0 && (st->st_mode & (S_IWGRP | S_IWOTH)) == 0' src/run.c; then
  ok "a program is run only if root owns it and its directory, and nobody else can write them"
else
  bad "programs are no longer required to be root's"
fi
HITS="$(grep -n 'rs_gzip_set_paths\|rs_program_set_paths' src/*.c \
        | grep -v '^src/gzip.c:\|^src/run.c:' || true)"
no_hits "nothing in the program can change which programs are run" \
  "program paths are changed outside the tests" "$HITS"

# ---------------------------------------------------------------------------
section "11. symlink following (CWE-61)"
mkdir -p "$WORK/sym/tree/home/u" "$WORK/sym/outside"
echo "the contents of somebody else's file" > "$WORK/sym/outside/secret"
ln -s "$WORK/sym/outside" "$WORK/sym/tree/home/u/escape"
ln -s "$WORK/sym/outside/secret" "$WORK/sym/tree/home/u/file"
"$RESTATE" -N -r "$WORK/sym/tree" scan -q > "$WORK/sym.json" 2>/dev/null
if grep -q "home/u/escape/secret" "$WORK/sym.json"; then
  bad "the walk went through a symlink"
elif grep -q '"path": "/home/u/escape", "name": "escape", "type": "symlink"' "$WORK/sym.json"; then
  ok "a symlink to a directory is recorded as a link and not entered"
else
  bad "the symlink to a directory was not recorded as a link"
fi
"$RESTATE" -N -r "$WORK/sym/tree" -o "$WORK/sym.tgz" capture -q
if gzip -dc "$WORK/sym.tgz" | tar -tf - 2>/dev/null | grep -q secret; then
  bad "the image holds content from behind a symlink"
else
  ok "the image holds nothing from behind a symlink"
fi
if grep -q '"path": "/home/u/file", "name": "file", "type": "symlink"' "$WORK/sym.json"; then
  ok "a symlink to a file is recorded as a link, its target's content unread"
else
  bad "the symlink to a file was not recorded as a link"
fi
# The output file: a symlink planted where the image is to be written must be
# replaced, not written through.
echo "precious" > "$WORK/sym/victim"
ln -s "$WORK/sym/victim" "$WORK/sym/out.tgz"
"$RESTATE" -N -r "$WORK/sym/tree" -o "$WORK/sym/out.tgz" capture -q
if [ "$(cat "$WORK/sym/victim")" = "precious" ] && [ ! -L "$WORK/sym/out.tgz" ]; then
  ok "a symlink planted at the output path is replaced, not followed"
else
  bad "writing the manifest followed a planted symlink"
fi

# ---------------------------------------------------------------------------
section "12. hard-coded password (CWE-259)"
HITS="$(grep_source '(password|passwd|secret|token|api_?key)[[:space:]]*=[[:space:]]*"' )"
no_hits "no credential is assigned a literal in the source" \
  "a credential-like literal was found" "$HITS"
note "restate uses no credentials at all; gitleaks (make security) scans history"

# ---------------------------------------------------------------------------
section "13. integer overflow (CWE-190)"
# Each a number that does not fit, or is not a number at all, where the index
# wants a count. Every one has to be refused, not wrapped or truncated.
for field in '"uid": 99999999999999999999' '"size": 18446744073709551616' \
             '"size": -1' '"nlink": 1.5' '"inode": 1e3' '"mode": "77777777"'; do
  printf '{"format": "restate-index", "version": 1, "entries": [{"path": "/a", "type": "file", "class": "state", "mode": "0644", "gid": 0, "mtime": "2026-01-01T00:00:00.000000000Z", "uid": 0, "size": 0, %s}]}' \
    "$field" > "$WORK/int.json"
  # The field being tested replaces the default: a JSON object may not hold
  # one key twice, so the defaults above are dropped for whichever it is.
  case "$field" in
    '"uid"'*)  sed -i.bak 's/"uid": 0, //' "$WORK/int.json" ;;
    '"size"'*) sed -i.bak 's/"size": 0, //' "$WORK/int.json" ;;
    '"mode"'*) sed -i.bak 's/"mode": "0644", //' "$WORK/int.json" ;;
  esac
  if "$RESTATE" diff "$WORK/int.json" "$WORK/int.json" > /dev/null 2> "$WORK/int.err"; then
    bad "$field was accepted"
  elif grep -q "duplicate key" "$WORK/int.err"; then
    bad "$field was refused, but only as a duplicate key -- the test is wrong"
  else
    ok "$field is refused rather than wrapped"
  fi
done
HITS="$(grep_source '\b(malloc|realloc)[[:space:]]*\([^)]*\*')"
no_hits "every count-times-size allocation goes through an overflow-checked helper" \
  "an allocation multiplies without an overflow check" "$HITS"

# ---------------------------------------------------------------------------
printf '\n'
if [ ${#SKIPPED[@]} -gt 0 ]; then
  printf '  \033[93mSkipped:\033[0m %s\n' "${SKIPPED[*]}"
fi
if [ ${#FAILURES[@]} -eq 0 ]; then
  printf '  \033[92m✓ all 13 accounted for, none found\033[0m\n\n'
  exit 0
fi
printf '  \033[91m✗ %d Lucky 13 check(s) failed\033[0m\n\n' "${#FAILURES[@]}"
exit 1
