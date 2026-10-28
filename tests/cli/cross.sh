#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# What one restate writes, another reads -- one built for another processor:
#
#   tests/cli/cross.sh ./bin/restate OTHER-RESTATE
#
# Every on-disk format restate has -- an image's tar and pax headers, the
# index, a repository's packs, .idx and .sum files, its snapshots, the
# chunking key -- is meant to be the same bytes whichever machine wrote it.
# CI runs this with the amd64 build and a big-endian s390x one (under QEMU),
# each writing what the other reads: an image, a repository captured into by
# both in turn, checked, pruned and restored from by each, and an encrypted
# one where gpg is there to use.
set -uo pipefail
A="${1:?usage: cross.sh BINARY OTHER-BINARY}"
B="${2:?usage: cross.sh BINARY OTHER-BINARY}"
for v in A B; do
  case "${!v}" in
    /*) ;;
    *) printf -v "$v" '%s' "$PWD/${!v}" ;;
  esac
  [ -x "${!v}" ] || { echo "cross.sh: ${!v} is not executable" >&2; exit 2; }
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-cross.XXXXXX")" || exit 2
trap 'chmod -R u+rwx "$WORK" 2> /dev/null; rm -rf "$WORK"' EXIT
cd "$WORK" || exit 2
export SOURCE_DATE_EPOCH=1700000000
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
# same TREE BACK -- whether every file in TREE is in BACK, byte for byte.
same() {
  local f bad=0
  while IFS= read -r f; do
    cmp -s "$1/$f" "$2/$f" || { bad=1; echo "        differs: $f"; }
  done < <(cd "$1" && find . -type f)
  return "$bad"
}

printf '\n\033[1mOne restate writes, another reads\033[0m\n'
printf '  \033[2m%s: %s\033[0m\n' "$("$A" --version | head -1)" "$A"
printf '  \033[2m%s: %s\033[0m\n\n' "$("$B" --version | head -1)" "$B"

# --- The tree -----------------------------------------------------------------
# Big enough for several chunks and packs, with every kind of entry and the
# numbers an index holds -- sizes past 32 bits' worth of bytes aside -- that
# would come out wrong read in the other byte order.
mkdir -p tree/etc/app tree/home/pat tree/srv
echo one > tree/etc/one
printf 'secret\n' > tree/etc/app/key && chmod 0600 tree/etc/app/key
printf '#!/bin/sh\nexit 0\n' > tree/srv/run && chmod 4755 tree/srv/run
: > tree/etc/empty
dd if=/dev/urandom of=tree/home/pat/big bs=1000 count=5000 2> /dev/null
ln -s ../etc/one tree/srv/link
echo linked > tree/srv/first && ln tree/srv/first tree/srv/second
mkfifo tree/srv/fifo
touch -t 202001020304.05 tree/etc/one tree/home/pat/big

# by WRITER READER: the image and the repository, one way round.
by() {
  local w="$1" r="$2" name="$3"
  printf '  \033[1m%s writes, the other reads\033[0m\n' "$name"
  expect 0 "an image" -- "$w" capture -N -q -r tree --os=linux -o "img-$name.tar"
  mkdir "back-$name"
  expect 0 "restored" -- "$r" restore -q --allow-unverified --root "back-$name" "img-$name.tar"
  expect 0 "and verified" -- "$r" verify -N --root "back-$name" "img-$name.tar"
  check "every file, byte for byte" same tree "back-$name"
  check "the symlink" test "$(readlink "back-$name/srv/link")" = ../etc/one
  check "the hard link" test "back-$name/srv/first" -ef "back-$name/srv/second"
  check "the setuid bit" test -u "back-$name/srv/run"
  check "the FIFO" test -p "back-$name/srv/fifo"
  expect 0 "and its index listed" -- "$r" list "img-$name.tar" /home/pat
  check "with the big file at its size" grep -q " $(wc -c < tree/home/pat/big | tr -d ' ') .*big\$" out.txt
}
by "$A" "$B" first
by "$B" "$A" second

# --- A repository both capture into ------------------------------------------
printf '  \033[1mA repository both write to\033[0m\n'
expect 0 "captured into by the first" -- "$A" capture -N -q -r tree -o repo --create
echo two > tree/etc/two
dd if=/dev/urandom bs=1000 count=1 2> /dev/null >> tree/home/pat/big
expect 0 "and by the second, on top" -- "$B" capture -N -q -r tree -o repo
expect 0 "checked whole by the first" -- "$A" check -q --read-all repo
expect 0 "and by the second" -- "$B" check -q --read-all repo
expect 0 "its snapshots, as the first lists them" -- "$A" snapshots repo
check "both of them" test "$(grep -c . out.txt)" -eq 2
mkdir rback
expect 0 "restored by the first from what the second wrote" -- \
  "$A" restore -q --allow-unverified --root rback repo
check "every file, byte for byte" same tree rback
expect 0 "pruned by the second" -- "$B" prune -q --keep-last 1 repo
expect 0 "repacked by the first" -- "$A" repack -q repo
expect 0 "checked whole by the second" -- "$B" check -q --read-all repo
mkdir rback2
expect 0 "restored by the second" -- "$B" restore -q --allow-unverified --root rback2 repo
check "every file, byte for byte" same tree rback2

# --- Encrypted ----------------------------------------------------------------
if command -v gpg > /dev/null 2>&1; then
  printf '  \033[1mAn encrypted repository both write to\033[0m\n'
  mkdir -m 700 gnupg
  gk() { GNUPGHOME="$WORK/gnupg" gpg --batch --quiet --pinentry-mode loopback --passphrase '' "$@"; }
  gk --quick-gen-key 'restate cross <cross@example.invalid>' default default never 2> /dev/null
  gk --export cross@example.invalid > enc.pub 2> /dev/null
  export GNUPGHOME="$WORK/gnupg"
  expect 0 "captured into by the first" -- \
    "$A" capture -N -q -r tree -o erepo --create --encrypt-to enc.pub
  echo three > tree/etc/three
  expect 0 "and by the second, with another machine's cache" -- \
    env XDG_CACHE_HOME="$WORK/cache2" "$B" capture -N -q -r tree -o erepo --encrypt-to enc.pub
  mkdir eback
  expect 0 "restored by the first, with a cache of neither" -- \
    env XDG_CACHE_HOME="$WORK/cache3" "$A" restore -q --allow-unverified --root eback erepo
  check "every file, byte for byte" same tree eback
  gpgconf --homedir "$WORK/gnupg" --kill gpg-agent 2> /dev/null || true
else
  echo "  (encrypted repository: skipped, as there is no gpg)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  printf '  \033[92m✓\033[0m %d checks, all passed\n' "$PASS"
else
  printf '  \033[91m✗\033[0m %d of %d checks failed\n' "$FAIL" "$((PASS + FAIL))"
  exit 1
fi
