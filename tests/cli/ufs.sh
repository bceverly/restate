#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# capture --from-snapshot on real UFS, as root, on FreeBSD:
#
#   sudo tests/cli/ufs.sh ./bin/restate
#
# Run by CI in FreeBSD's VM, and by hand on any FreeBSD. The built-in rules
# are used, as they leave out .snap and .sujournal. It touches nothing
# but what it makes: two UFS filesystems, each on a memory disk attached to a
# sparse file in a directory of its own under /var/tmp, mounted there, and
# unmounted and detached by their own names when it ends. Every capture is
# of the first filesystem's mount alone, checked to be that memory disk
# before each one, so no other filesystem on the machine is ever
# snapshotted.
#
# What it holds restate to: each filesystem under the root snapshotted with
# mksnap_ffs and read from its snapshot, at its live path, and what is not
# UFS read as it is; the image what the tree was when the snapshots were
# taken, not what it became while it was read; .snap left out; and every
# snapshot it took unmounted, detached and removed after, after a SIGTERM
# too, and none it did not take ever touched -- one an earlier capture left
# is said and kept.
set -uo pipefail
BIN="${1:?usage: ufs.sh BINARY}"
case "$BIN" in
  /*) ;;
  *) BIN="$PWD/$BIN" ;;
esac
[ -x "$BIN" ] || { echo "ufs.sh: $BIN is not executable" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "ufs.sh: run it as root" >&2; exit 2; }
if [ "$(uname -s)" != FreeBSD ]; then
  echo "ufs.sh: UFS snapshots are FreeBSD's" >&2
  exit 2
fi

WORK="$(mktemp -d /var/tmp/restate-ufs.XXXXXX)" || exit 2
MNT="$WORK/mnt"
MDS=()      # the memory disks this run attached, by unit
MOUNTED=()  # what it mounted, in order

# Unmounts what this run mounted and detaches the disks it attached, by
# their own names, and nothing else.
# shellcheck disable=SC2329  # run by the EXIT trap
finish() {
  local i
  cd / || true
  for ((i = ${#MOUNTED[@]} - 1; i >= 0; i--)); do
    umount -f "${MOUNTED[$i]}" 2> /dev/null || echo "ufs.sh: umount ${MOUNTED[$i]} failed" >&2
  done
  for ((i = ${#MDS[@]} - 1; i >= 0; i--)); do
    mdconfig -d -u "${MDS[$i]}" || echo "ufs.sh: mdconfig -d -u ${MDS[$i]} failed" >&2
  done
  # What a restore put back may have its flags -- schg, a journal's --
  # and a flag keeps rm out.
  chflags -R 0 "$WORK" 2> /dev/null
  rm -rf "$WORK"
}
trap finish EXIT
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
# A UFS filesystem on a memory disk attached to file $1, mounted on $2.
filesystem() {
  local md
  truncate -s 256M "$1" || return 1
  md="$(mdconfig -a -t vnode -f "$1")" || return 1
  MDS+=("${md#md}")
  newfs -U -j "/dev/$md" > /dev/null || return 1
  mkdir -p "$2"
  mount "/dev/$md" "$2" || return 1
  MOUNTED+=("$2")
}
# What restate's capture left of its own: snapshot files by its name in
# either filesystem's .snap, the memory disks they are attached as, and the
# directory it mounts them in.
remains() {
  find "$MNT/.snap" "$MNT/home/.snap" -name 'restate-*' ! -name 'restate-old-*' 2> /dev/null
  mdconfig -l -v | grep -F "$MNT" | grep -F '/.snap/restate-' | grep -v 'restate-old-'
  find /var/run -maxdepth 1 -name 'restate-*' -newer "$WORK/disk1" 2> /dev/null
}
# Whether restate has its snapshots mounted, ready to read: taken whole,
# which mksnap_ffs's file in .snap, there from the start, does not say.
mounted() { mount | grep -qF ' on /var/run/restate-'; }
# That the root restate is to capture is this run's first filesystem, and
# nothing else of the machine's.
guard() {
  local on
  on="$(df -P "$MNT" | awk 'NR == 2 { print $1 }')"
  if [ "$on" != "/dev/md${MDS[0]}" ]; then
    echo "ufs.sh: $MNT is on \"$on\", not /dev/md${MDS[0]}; stopping before restate runs" >&2
    exit 2
  fi
}

printf '\n\033[1mcapture --from-snapshot on UFS\033[0m \033[2m(%s)\033[0m\n\n' "$BIN"

# --- Two filesystems, one under the other, and a tmpfs ---------------------
filesystem "$WORK/disk1" "$MNT" || exit 2
filesystem "$WORK/disk2" "$MNT/home" || exit 2
mkdir -p "$MNT/etc" "$MNT/scratch" "$MNT/zzz" "$MNT/home/pat"
if mount -t tmpfs tmpfs "$MNT/scratch"; then
  MOUNTED+=("$MNT/scratch")
  echo tmpfs > "$MNT/scratch/note"
fi
echo hosts > "$MNT/etc/hosts"
echo mine > "$MNT/home/pat/notes"
echo before > "$MNT/zzz/changes"
echo here > "$MNT/zzz/goes"
mkdir -p "$MNT/aaa"
for d in $(seq 1 30); do
  mkdir "$MNT/aaa/$d"
  dd if=/dev/urandom of="$MNT/aaa/$d/blob" bs=1m count=4 2> /dev/null
done

# --- A capture of it --------------------------------------------------------
guard
expect 0 "capture --from-snapshot" -- \
  "$BIN" capture --from-snapshot -r "$MNT" -o one.tar
contains err.txt "reading from the snapshot restate-" "reads from its snapshots"
contains err.txt "of 2 UFS filesystems" "both filesystems under the root"
if [ "${MOUNTED[-1]}" = "$MNT/scratch" ]; then
  contains err.txt "read as they are, not from a snapshot: $MNT/scratch" \
    "and says what it reads as it is"
fi
check "and leaves nothing of its snapshots behind" test -z "$(remains)"
mkdir back1
expect 0 "restore it" -- "$BIN" restore -q --allow-unverified --root back1 one.tar
check "the root filesystem's file" test "$(cat back1/etc/hosts 2> /dev/null)" = hosts
check "the one under it" test "$(cat back1/home/pat/notes 2> /dev/null)" = mine
if [ "${MOUNTED[-1]}" = "$MNT/scratch" ]; then
  check "and what is not UFS" test "$(cat back1/scratch/note 2> /dev/null)" = tmpfs
fi
check "and no .snap" test ! -e back1/.snap -a ! -e back1/home/.snap
check "the whole tree, as it was" \
  diff -r -x scratch -x .snap -x .sujournal "$MNT" back1

# --- What changes while it is read ------------------------------------------
guard
"$BIN" capture -q --from-snapshot -r "$MNT" -o two.tar 2> two.err &
pid=$!
for _ in $(seq 1 400); do
  mounted && break
  sleep 0.05
done
changed=no
if mounted && kill -0 "$pid" 2> /dev/null; then
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
check "and its snapshots removed" test -z "$(remains)"

# --- Stopped ----------------------------------------------------------------
guard
"$BIN" capture -q --from-snapshot -r "$MNT" -o three.tar 2> three.err &
pid=$!
for _ in $(seq 1 400); do
  mounted && break
  sleep 0.05
done
kill -TERM "$pid" 2> /dev/null
wait "$pid"
status=$?
check "a SIGTERM ends it, by the signal" test "$status" -eq 143
check "and its snapshots are unmounted, detached and removed first" test -z "$(remains)"
check "and it writes no image" test ! -e three.tar

# --- One an earlier capture left ---------------------------------------------
: > "$MNT/home/.snap/restate-old-1"
: > "$MNT/home/.snap/nightly"
guard
expect 0 "capture with one left from before" -- \
  "$BIN" capture --from-snapshot -r "$MNT" -o four.tar
contains err.txt "$MNT/home/.snap/restate-old-1 is a snapshot an earlier capture left behind" \
  "says so"
contains err.txt "rm $MNT/home/.snap/restate-old-1" "and how to remove it"
check "and keeps it" test -e "$MNT/home/.snap/restate-old-1"
check "and one that is not restate's" test -e "$MNT/home/.snap/nightly"
if grep -qF "nightly" err.txt; then
  fail "says nothing of a snapshot that is not restate's"
else
  ok
fi

# --- --one-file-system --------------------------------------------------------
guard
expect 0 "capture --from-snapshot --one-file-system" -- \
  "$BIN" capture --from-snapshot --one-file-system -r "$MNT" -o five.tar
contains err.txt "of 1 UFS filesystem" "the root's own filesystem alone"

printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '  \033[92m✓\033[0m %d UFS checks passed\n\n' "$PASS"
  exit 0
fi
printf '  \033[91m✗\033[0m %d of %d UFS checks failed\n\n' "$FAIL" "$((PASS + FAIL))"
exit 1
