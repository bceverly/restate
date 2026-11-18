#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# capture --from-snapshot on real ZFS, as root:
#
#   sudo tests/cli/zfs.sh ./bin/restate
#
# Run by CI in FreeBSD's VM and on Ubuntu, and by hand on any machine with
# ZFS. It touches nothing but what it makes: two pools of its own, each on a
# sparse file in a directory of its own under /var/tmp, named for this run
# and destroyed by those names when it ends. Every capture is of the first
# pool's mount alone, checked to be that pool before each one, so no other
# dataset on the machine is ever snapshotted. A pool by either name already
# there stops it before it starts.
#
# What it holds restate to: every dataset under the root snapshotted and read
# from its snapshot, at its live path, and what is not ZFS read as it is;
# the image what the tree was when the snapshots were taken, not what it
# became while it was read; every snapshot restate took destroyed after,
# after a SIGTERM too, and none it did not take ever destroyed -- one an
# earlier capture left is said and kept.
set -uo pipefail
BIN="${1:?usage: zfs.sh BINARY}"
case "$BIN" in
  /*) ;;
  *) BIN="$PWD/$BIN" ;;
esac
[ -x "$BIN" ] || { echo "zfs.sh: $BIN is not executable" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "zfs.sh: run it as root" >&2; exit 2; }
if ! command -v zpool > /dev/null || ! command -v zfs > /dev/null; then
  echo "zfs.sh: there is no zpool and zfs here" >&2
  exit 2
fi

WORK="$(mktemp -d /var/tmp/restate-zfs.XXXXXX)" || exit 2
tag="$(basename "$WORK" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]')"
P1="rstest${tag}a"
P2="rstest${tag}b"
MNT="$WORK/mnt"
MADE=()
TMPFS=""

# Destroys the pools this run made, by their names, and nothing else.
# shellcheck disable=SC2329  # run by the EXIT trap
finish() {
  local p
  cd / || true
  [ -n "$TMPFS" ] && umount "$TMPFS" 2> /dev/null
  for ((i = ${#MADE[@]} - 1; i >= 0; i--)); do
    p="${MADE[$i]}"
    case "$p" in
      rstest*) zpool destroy -f "$p" || echo "zfs.sh: zpool destroy $p failed" >&2 ;;
    esac
  done
  rm -rf "$WORK"
}
trap finish EXIT

for p in "$P1" "$P2"; do
  if zpool list "$p" > /dev/null 2>&1; then
    echo "zfs.sh: a pool named $p is there already; leaving it alone" >&2
    exit 2
  fi
done
cd "$WORK" || exit 2
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
    sed 's/^/        /' err.txt | head -8
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
contains() {
  if grep -qF -- "$2" "$1"; then
    ok
  else
    fail "$3: no \"$2\""
    sed 's/^/        /' "$1" | head -8
  fi
}
# Whether the snapshot `$1` is there.
# shellcheck disable=SC2329  # run by check
there() { zfs list -H -o name "$1" > /dev/null 2>&1; }
# This run's snapshots of its own pools that restate made: restate-*.
restate_snapshots() {
  zfs list -H -t snapshot -o name -r "$P1" "$P2" 2> /dev/null | grep '@restate-' | grep -v '@restate-old-'
}
# That the root restate is to capture is the first pool's, and nothing else
# of the machine's: what a capture of it snapshots is this run's alone.
guard() {
  local on
  on="$(zfs list -H -o name "$MNT" 2> /dev/null)"
  if [ "$on" != "$P1" ]; then
    echo "zfs.sh: $MNT is on \"$on\", not $P1; stopping before restate runs" >&2
    exit 2
  fi
}

printf '\n\033[1mcapture --from-snapshot on ZFS\033[0m \033[2m(%s)\033[0m\n\n' "$BIN"

# --- Two pools, three datasets under one, something that is not ZFS ---------
truncate -s 512M "$WORK/disk1" "$WORK/disk2" || exit 2
zpool create -m "$MNT" "$P1" "$WORK/disk1" || exit 2
MADE+=("$P1")
zfs create "$P1/data" && zfs create "$P1/data/logs" || exit 2
zpool create -m "$MNT/other" "$P2" "$WORK/disk2" || exit 2
MADE+=("$P2")
mkdir -p "$MNT/etc" "$MNT/scratch" "$MNT/zzz"
if mount -t tmpfs tmpfs "$MNT/scratch" 2> /dev/null; then
  TMPFS="$MNT/scratch"
  echo tmpfs > "$MNT/scratch/note"
fi
echo hosts > "$MNT/etc/hosts"
echo row > "$MNT/data/table"
echo line > "$MNT/data/logs/today"
echo far > "$MNT/other/far"
echo before > "$MNT/zzz/changes"
echo here > "$MNT/zzz/goes"
# Enough to read that the walk takes a while: what changes meanwhile does so
# after the snapshot, and before the walk reaches it.
mkdir -p "$MNT/aaa"
for d in $(seq 1 30); do
  mkdir "$MNT/aaa/$d"
  dd if=/dev/urandom of="$MNT/aaa/$d/blob" bs=1M count=4 2> /dev/null
done

# --- A capture of it --------------------------------------------------------
guard
expect 0 "capture --from-snapshot" -- \
  "$BIN" capture -N --from-snapshot -r "$MNT" -o one.tar --result one.json
contains err.txt "reading from the snapshot restate-" "reads from its snapshots"
contains err.txt "of 4 ZFS datasets" "every dataset under the root, in both pools"
if [ -n "$TMPFS" ]; then
  contains err.txt "read as they are, not from a snapshot (not ZFS): $MNT/scratch" \
    "and says what it reads as it is"
fi
check "and leaves no snapshot behind" test -z "$(restate_snapshots)"
mkdir back1
expect 0 "restore it" -- "$BIN" restore -q --allow-unverified --root back1 one.tar
check "a dataset's file" test "$(cat back1/data/table 2> /dev/null)" = row
check "a dataset's dataset's" test "$(cat back1/data/logs/today 2> /dev/null)" = line
check "another pool's" test "$(cat back1/other/far 2> /dev/null)" = far
if [ -n "$TMPFS" ]; then
  check "and what is not ZFS" test "$(cat back1/scratch/note 2> /dev/null)" = tmpfs
fi
check "the whole tree, as it was" diff -r -x scratch -x '.zfs' "$MNT" back1

# --- What changes while it is read ------------------------------------------
# Changed once the snapshots are there and the walk is reading aaa: the image
# is the tree as it was when they were taken.
guard
"$BIN" capture -N -q --from-snapshot -r "$MNT" -o two.tar 2> two.err &
pid=$!
for _ in $(seq 1 400); do
  [ -n "$(restate_snapshots)" ] && break
  sleep 0.05
done
changed=no
if [ -n "$(restate_snapshots)" ] && kill -0 "$pid" 2> /dev/null; then
  echo after > "$MNT/zzz/changes"
  rm "$MNT/zzz/goes"
  echo new > "$MNT/zzz/came"
  changed=yes
fi
wait "$pid"
status=$?
check "capture while the tree changes" test "$status" -eq 0
check "changed while its snapshots were there" test "$changed" = yes
mkdir back2
expect 0 "restore it" -- "$BIN" restore -q --allow-unverified --root back2 two.tar
check "a file as it was before" test "$(cat back2/zzz/changes 2> /dev/null)" = before
check "one removed since, there" test -f back2/zzz/goes
check "one made since, not" test ! -e back2/zzz/came
check "and its snapshots destroyed" test -z "$(restate_snapshots)"

# --- Stopped ----------------------------------------------------------------
# SIGTERM, as a service manager stops it: a script's background job ignores
# SIGINT, and restate holds and acts on both alike.
guard
"$BIN" capture -N -q --from-snapshot -r "$MNT" -o three.tar 2> three.err &
pid=$!
for _ in $(seq 1 400); do
  [ -n "$(restate_snapshots)" ] && break
  sleep 0.05
done
kill -TERM "$pid" 2> /dev/null
wait "$pid"
status=$?
check "a SIGTERM ends it, by the signal" test "$status" -eq 143
check "and its snapshots are destroyed first" test -z "$(restate_snapshots)"
check "and it writes no image" test ! -e three.tar

# --- One an earlier capture left ---------------------------------------------
zfs snapshot -o restate:capture=restate-old-1 "$P1/data@restate-old-1"
zfs snapshot "$P1/data@daily"
guard
expect 0 "capture with one left from before" -- \
  "$BIN" capture -N --from-snapshot -r "$MNT" -o four.tar
contains err.txt "$P1/data@restate-old-1 is a snapshot an earlier capture left behind" \
  "says so"
contains err.txt "zfs destroy $P1/data@restate-old-1 removes it" "and how to remove it"
check "and keeps it" there "$P1/data@restate-old-1"
check "and one of someone else's" there "$P1/data@daily"
if grep -qF "daily" err.txt; then
  fail "says nothing of a snapshot that is not restate's"
else
  ok
fi

# --- --one-file-system --------------------------------------------------------
guard
expect 0 "capture --from-snapshot --one-file-system" -- \
  "$BIN" capture -N --from-snapshot --one-file-system -r "$MNT" -o five.tar
contains err.txt "of 1 ZFS dataset" "the root's own dataset alone"

printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '  \033[92m✓\033[0m %d ZFS checks passed\n\n' "$PASS"
  exit 0
fi
printf '  \033[91m✗\033[0m %d of %d ZFS checks failed\n\n' "$FAIL" "$((PASS + FAIL))"
exit 1
