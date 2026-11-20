#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# capture --from-snapshot on real APFS, as root, on macOS:
#
#   sudo tests/cli/apfs.sh ./bin/restate
#
# Run by CI on its macOS runner. On a Mac of your own, know what it does
# first: tmutil snapshots the Data volume -- the whole of it, as Time
# Machine's local snapshots do -- once for each capture, and restate deletes
# each again by its date when the capture ends. What is captured is only a
# directory of its own under /Users/Shared, made and removed here.
#
# What it holds restate to: the directory read from the Data volume's
# snapshot, through the /Users firmlink, at its live path; the image what
# the tree was when the snapshot was taken, not what it became while it was
# read; and the snapshot unmounted and deleted after, after a SIGTERM too.
# Where macOS has not given the process Full Disk Access, restate refuses
# before taking any, and this says so and stops.
set -uo pipefail
BIN="${1:?usage: apfs.sh BINARY}"
case "$BIN" in
  /*) ;;
  *) BIN="$PWD/$BIN" ;;
esac
[ -x "$BIN" ] || { echo "apfs.sh: $BIN is not executable" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "apfs.sh: run it as root" >&2; exit 2; }
if [ "$(uname -s)" != Darwin ]; then
  echo "apfs.sh: APFS snapshots are macOS's" >&2
  exit 2
fi

WORK="$(mktemp -d /Users/Shared/restate-apfs.XXXXXX)" || exit 2
TREE="$WORK/tree"
DATA=/System/Volumes/Data

# The local snapshot dates there were before, so that what is left after is
# told from them.
dates() { tmutil listlocalsnapshotdates "$DATA" 2> /dev/null | grep -E '^[0-9]{4}-' | sort; }
BEFORE="$WORK/before"
dates > "$BEFORE"

# shellcheck disable=SC2329  # run by the EXIT trap
finish() {
  cd / || true
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
# What restate's captures left: its snapshots mounted, and snapshot dates
# that were not there before.
remains() {
  mount | grep -E ' on (/private)?/var/run/restate-'
  dates | comm -13 "$BEFORE" -
}
# Whether restate has its snapshot mounted, ready to read.
mounted() { mount | grep -qE ' on (/private)?/var/run/restate-'; }

printf '\n\033[1mcapture --from-snapshot on APFS\033[0m \033[2m(%s)\033[0m\n\n' "$BIN"

# Whether this Mac takes local snapshots at all, asked of tmutil itself:
# where it cannot -- some virtual machines, a TCC refusal -- there is
# nothing of restate's to test, and what macOS says about it is shown
# instead. The probe's own snapshot is deleted by its date.
if probe="$(tmutil localsnapshot 2>&1)"; then
  made="$(printf '%s\n' "$probe" | sed -n 's/.*date: \([0-9]\{4\}-[0-9-]\{12\}\).*/\1/p' | head -1)"
  if [ -n "$made" ]; then
    tmutil deletelocalsnapshots "$made" > /dev/null 2>&1 ||
      echo "apfs.sh: the probe's snapshot $made was not deleted" >&2
  fi
else
  printf '  skipped: tmutil cannot take a local snapshot on this machine, so restate cannot either:\n'
  printf '%s\n' "$probe" | sed 's/^/        /' | head -6
  printf '      macOS %s; Time Machine destinations:\n' "$(sw_vers -productVersion 2> /dev/null)"
  tmutil destinationinfo 2>&1 | sed 's/^/        /' | head -6
  printf '      what macOS logged:\n'
  log show --last 2m --style compact \
    --predicate 'process == "tmutil" OR subsystem BEGINSWITH "com.apple.TimeMachine" OR process == "backupd"' \
    2> /dev/null | grep -iE 'snapshot|error|fail|denied|tcc' | tail -15 | sed 's/^/        /'
  printf '\n'
  exit 0
fi

mkdir -p "$TREE/etc" "$TREE/zzz" "$TREE/aaa"
echo hosts > "$TREE/etc/hosts"
echo before > "$TREE/zzz/changes"
echo here > "$TREE/zzz/goes"
for d in $(seq 1 30); do
  mkdir "$TREE/aaa/$d"
  dd if=/dev/urandom of="$TREE/aaa/$d/blob" bs=1m count=4 2> /dev/null
done

# --- A capture of it --------------------------------------------------------
"$BIN" capture --from-snapshot -r "$TREE" -o one.tar > out.txt 2> err.txt < /dev/null
status=$?
if [ "$status" -ne 0 ] && grep -qF "Full Disk Access" err.txt; then
  printf '  skipped: macOS has not given this process Full Disk Access, and restate said so:\n'
  sed 's/^/        /' err.txt | head -4
  check "and took no snapshot" test -z "$(remains)"
  exit "$((FAIL > 0))"
fi
check "capture --from-snapshot" test "$status" -eq 0
[ "$status" -eq 0 ] || sed 's/^/        /' err.txt | head -8
contains err.txt "reading from the snapshot restate-" "reads from its snapshot"
contains err.txt "of 1 APFS volume" "the Data volume's"
check "and leaves nothing of it behind" test -z "$(remains)"
mkdir back1
expect 0 "restore it" -- "$BIN" restore -q --allow-unverified --root back1 one.tar
check "the whole tree, as it was" diff -r "$TREE" back1

# --- What changes while it is read ------------------------------------------
"$BIN" capture -q --from-snapshot -r "$TREE" -o two.tar 2> two.err &
pid=$!
for _ in $(seq 1 600); do
  mounted && break
  sleep 0.05
done
changed=no
if mounted && kill -0 "$pid" 2> /dev/null; then
  echo after > "$TREE/zzz/changes"
  rm "$TREE/zzz/goes"
  echo new > "$TREE/zzz/came"
  changed=yes
fi
wait "$pid"
status=$?
check "capture while the tree changes" test "$status" -eq 0
[ "$status" -eq 0 ] || sed 's/^/        /' two.err | head -8
check "changed while its snapshot was mounted" test "$changed" = yes
mkdir back2
expect 0 "restore it" -- "$BIN" restore -q --allow-unverified --root back2 two.tar
check "a file as it was before" test "$(cat back2/zzz/changes 2> /dev/null)" = before
check "one removed since, there" test -f back2/zzz/goes
check "one made since, not" test ! -e back2/zzz/came
check "and its snapshot unmounted and deleted" test -z "$(remains)"

# --- Stopped ----------------------------------------------------------------
"$BIN" capture -q --from-snapshot -r "$TREE" -o three.tar 2> three.err &
pid=$!
for _ in $(seq 1 600); do
  mounted && break
  sleep 0.05
done
kill -TERM "$pid" 2> /dev/null
wait "$pid"
status=$?
check "a SIGTERM ends it, by the signal" test "$status" -eq 143
check "and its snapshot is unmounted and deleted first" test -z "$(remains)"
check "and it writes no image" test ! -e three.tar

printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '  \033[92m✓\033[0m %d APFS checks passed\n\n' "$PASS"
  exit 0
fi
printf '  \033[91m✗\033[0m %d of %d APFS checks failed\n\n' "$FAIL" "$((PASS + FAIL))"
remains | sed 's/^/  left: /'
exit 1
