#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# A repository on whatever storage DIR is on, used as a machine uses one, and
# read back bit for bit:
#
#   tests/cli/share.sh ./bin/restate DIR
#
# The repository format promises to assume nothing of the filesystem it is on
# (ROADMAP.md, "A repository format free of any system's assumptions"): no
# case, no Unix owners or modes, no hard links, no symlinks, no long names.
# Paths, their case and every kind of metadata are data inside the indexes.
# This holds restate to that: run by make test-cli on a local directory, and
# by CI on exFAT, FAT and an SMB share that ignores case (make test-share
# SHARE=DIR runs it on any other).
#
# Two things are checked. The repository is captured into twice, checked,
# pruned, repacked and restored from, and what comes back is the tree that
# went in -- content, modes, times, symlinks and hard links, paths that differ
# only in case where the tree's own filesystem can hold them. And every name
# restate wrote is one any filesystem keeps as it is: letters, digits, '.',
# '-' and '_', short, none differing from another in the same directory only
# in case, none a name Windows reserves, and nothing but plain files and
# directories, each file with one name.
set -uo pipefail
BIN="${1:?usage: share.sh BINARY DIR}"
DIR="${2:?usage: share.sh BINARY DIR}"
case "$BIN" in
  /*) ;;
  *) BIN="$PWD/$BIN" ;;
esac
[ -x "$BIN" ] || { echo "share.sh: $BIN is not executable" >&2; exit 2; }
[ -d "$DIR" ] && [ -w "$DIR" ] || { echo "share.sh: $DIR is not a directory to write in" >&2; exit 2; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-share.XXXXXX")" || exit 2
WORK="$(printf '%s' "$WORK" | tr -s /)"
REPO="$(mktemp -d "$DIR/restate-share.XXXXXX")" || exit 2
REPO="$(printf '%s' "$REPO" | tr -s /)/repo"
trap 'chmod -R u+rwx "$WORK" 2> /dev/null; rm -rf "$WORK" "${REPO%/repo}"' EXIT
cd "$WORK" || exit 2
export SOURCE_DATE_EPOCH=1700000000
# Its own cache, so a machine's earlier runs are not what is read back.
export XDG_CACHE_HOME="$WORK/cache"
PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); printf '  \033[91mFAIL\033[0m %s\n' "$*"; }
# expect STATUS DESCRIPTION -- COMMAND...
expect() {
  local want="$1" what="$2"
  shift 3
  "$@" > out.txt 2> err.txt < /dev/null
  local got=$?
  if [ "$got" -eq "$want" ]; then
    ok
  else
    fail "$what: exit $got, wanted $want"
    sed 's/^/        /' err.txt | head -5
  fi
}
check() {
  local what="$1"
  shift
  if "$@"; then
    ok
  else
    fail "$what"
  fi
}

printf '\n\033[1mA repository on %s\033[0m \033[2m(%s)\033[0m\n\n' "$DIR" "$BIN"

# --- The tree --------------------------------------------------------------
# What a filesystem without case, Unix permissions or links could not hold
# itself, and the repository has to: it is data there.
mkdir -p tree/etc/app tree/home/pat/docs tree/srv
echo one > tree/etc/one
printf 'secret\n' > tree/etc/app/key && chmod 0600 tree/etc/app/key
printf '#!/bin/sh\nexit 0\n' > tree/srv/run && chmod 0755 tree/srv/run
: > tree/etc/empty
dd if=/dev/urandom of=tree/home/pat/big bs=1000 count=3000 2> /dev/null
long="$(printf '%200s' '' | tr ' ' n)"
echo long > "tree/home/pat/docs/$long"
echo accents > "tree/home/pat/docs/café ü.txt"
echo colon > "tree/home/pat/docs/a:b?c*d"
echo dot > "tree/home/pat/docs/trailing."
echo con > tree/home/pat/docs/CON
ln -s ../etc/one tree/srv/link
echo linked > tree/srv/first && ln tree/srv/first tree/srv/second
# Paths that differ only in case, where this tree's filesystem can hold both.
echo upper > tree/etc/Case
if [ ! -e tree/etc/case ]; then
  echo lower > tree/etc/case
  cased=yes
else
  cased=no
fi
touch -t 202001020304.05 tree/etc/one tree/home/pat/big

# --- Used as a machine uses one ---------------------------------------------
expect 0 "capture --create into it" -- "$BIN" capture -N -q -r tree -o "$REPO" --create
expect 0 "check --read-all" -- "$BIN" check -q --read-all "$REPO"
echo two > tree/etc/two
dd if=/dev/urandom bs=1000 count=1 2> /dev/null >> tree/home/pat/big
touch -t 202001020304.05 tree/home/pat/big
expect 0 "capture into it again" -- "$BIN" capture -N -q -r tree -o "$REPO"
expect 0 "list its snapshots" -- "$BIN" snapshots "$REPO"
check "both of them" test "$(grep -c . out.txt)" -eq 2
expect 0 "check --read-all, both" -- "$BIN" check -q --read-all "$REPO"
expect 0 "prune it to the newest" -- "$BIN" prune -q --keep-last 1 "$REPO"
expect 0 "repack it" -- "$BIN" repack -q "$REPO"
expect 0 "check --read-all, after" -- "$BIN" check -q --read-all "$REPO"

# --- Read back bit for bit ----------------------------------------------------
mkdir back
expect 0 "restore from it" -- "$BIN" restore -q --allow-unverified --root back "$REPO"
expect 0 "and what came back is what went in, as the index says" -- \
  "$BIN" verify -N --root back "$REPO"
same=yes
while IFS= read -r f; do
  cmp -s "tree/$f" "back/$f" || { same=no; echo "        differs: $f"; }
done < <(cd tree && find . -type f)
check "every file's content, byte for byte" test "$same" = yes
check "the symlink, as it was" test "$(readlink back/srv/link)" = ../etc/one
check "the hard link, still one" test back/srv/first -ef back/srv/second
check "a name Windows reserves, a colon and a trailing dot" \
  test -f back/home/pat/docs/CON -a -f "back/home/pat/docs/a:b?c*d" -a -f back/home/pat/docs/trailing.
if [ "$cased" = yes ]; then
  check "paths that differ only in case, both" \
    test "$(cat back/etc/Case)" = upper -a "$(cat back/etc/case)" = lower
else
  echo "  (paths differing only in case: skipped, as this tree's filesystem ignores case)"
fi

# --- Encrypted, whose chunking key is kept beside the packs -----------------
if command -v gpg > /dev/null 2>&1; then
  mkdir -m 700 gnupg nokey
  gk() { GNUPGHOME="$WORK/gnupg" gpg --batch --quiet --pinentry-mode loopback --passphrase '' "$@"; }
  gk --quick-gen-key 'restate share <share@example.invalid>' default default never 2> /dev/null
  gk --export share@example.invalid > enc.pub 2> /dev/null
  expect 0 "an encrypted one, captured into with no secret key" -- \
    env GNUPGHOME="$WORK/nokey" \
    "$BIN" capture -N -q -r tree -o "$REPO-enc" --create --encrypt-to enc.pub
  expect 0 "and again, from another machine's cache" -- \
    env GNUPGHOME="$WORK/nokey" XDG_CACHE_HOME="$WORK/cache2" \
    "$BIN" capture -N -q -r tree -o "$REPO-enc" --encrypt-to enc.pub
  check "its chunking key is in the repository, for every machine" \
    test -s "$REPO-enc/chunk-key"
  mkdir eback
  expect 0 "restored with the secret key" -- \
    env GNUPGHOME="$WORK/gnupg" XDG_CACHE_HOME="$WORK/cache3" \
    "$BIN" restore -q --allow-unverified --root eback "$REPO-enc"
  check "and its files are back" cmp tree/home/pat/big eback/home/pat/big
  gpgconf --homedir "$WORK/gnupg" --kill gpg-agent 2> /dev/null || true
else
  echo "  (encrypted repository: skipped, as it needs gpg)"
fi

# --- Every name restate wrote -------------------------------------------------
# audit ROOT -- prints what in ROOT is not a name every filesystem keeps.
audit() {
  local root="$1"
  ( cd "$root" && find . -mindepth 1 \( ! -type f ! -type d \) -print | sed 's/^/not a file or directory: /'
    cd "$root" && find . -type f -links +1 -print | sed 's/^/more than one name: /'
    cd "$root" && find . -mindepth 1 -print ) |
  awk '
    /^(not a file or directory|more than one name): / { print; next }
    {
      path = substr($0, 3)
      if (length(path) > 160) print "a long path: " path
      n = split(path, part, "/")
      name = part[n]
      dir = substr(path, 1, length(path) - length(name))
      if (name !~ /^[A-Za-z0-9._-]+$/) print "not letters, digits, \".\", \"-\" and \"_\": " path
      if (length(name) > 64) print "a long name: " path
      if (name ~ /[. ]$/) print "ends in a dot: " path
      stem = toupper(name); sub(/\..*/, "", stem)
      if (stem ~ /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/) print "a name Windows reserves: " path
      key = dir tolower(name)
      if (key in seen) print "differs only in case from " seen[key] ": " path
      seen[key] = path
    }'
}
# A FUSE or SMB client caches what it was told of a file for a second, by
# default: a name just removed can still be counted.
sleep 2
for r in "$REPO" "$REPO-enc"; do
  [ -d "$r" ] || continue
  found="$(audit "$r")"
  if [ -z "$found" ]; then
    ok
  else
    fail "$(basename "$r"): names a filesystem may not keep"
    printf '%s\n' "$found" | head -10 | sed 's/^/        /'
  fi
  left="$(cd "$r" && find . -mindepth 1 -name '.*' -print)"
  check "$(basename "$r"): nothing half-written left behind${left:+: $left}" test -z "$left"
done

printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '  \033[92m✓\033[0m %d repository checks passed\n\n' "$PASS"
  exit 0
fi
printf '  \033[91m✗\033[0m %d of %d repository checks failed\n\n' "$FAIL" $((PASS + FAIL))
exit 1
