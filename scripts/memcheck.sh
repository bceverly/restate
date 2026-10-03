#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Memory safety: the same tests again, under instrumentation that notices what
# a passing test cannot.
#
#   make test-memory
#
# Three passes, because they find different things:
#
#   AddressSanitizer   buffer overflows, use-after-free, double free, and
#                      (LeakSanitizer, which it includes) leaks
#   UndefinedBehavior  signed overflow, bad shifts, misaligned loads, and the
#      Sanitizer       integer conversions a parser has chances for
#   valgrind           the same ground as ASan from a different angle, and it
#                      catches uninitialised reads, which ASan does not
#
# A tool that is not installed is reported as skipped rather than failing the
# run, so this is useful before all of them are set up. `make install-dev`
# installs them and CI installs them, so in both of those places nothing skips.
#
# The sanitizers are pointed at a log file rather than stderr: the end-to-end
# tests assert on what the program writes to stderr, and a sanitizer summary
# printed there would fail those tests for the wrong reason.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

CC="${CC:-cc}"
VERSION="$(cat VERSION)"
WORK=".sanitize"
FAILURES=()
SKIPPED=()

section() { printf '\n\033[1;94m▸ %s\033[0m\n' "$*"; }
ok()      { printf '  \033[92m✓\033[0m %s\n' "$*"; }
bad()     { printf '  \033[91m✗\033[0m %s\n' "$*"; FAILURES+=("$1"); }
skip()    { printf '  \033[93m-\033[0m %s\n' "$*"; SKIPPED+=("$1"); }
note()    { printf '    \033[2m%s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# What a failing step says.
#
# Pointing at a log is not reporting a failure, for one reason: the next run
# starts by deleting $WORK, so by the time anybody looks, the evidence is a
# file from a run that passed. That is not a hypothetical -- it is how two
# separate afternoons were spent, once here and once on a macOS runner where
# the log could not be reached at all.
#
# So a failure prints its own evidence, and keeps a copy the next run will not
# touch. The copy is named for the step rather than the time, because a second
# failure of the same step supersedes the first and a directory of timestamped
# logs is its own kind of unreadable.
# ---------------------------------------------------------------------------
show_failure() {
  local log="$1"
  local kept

  [ -f "$log" ] || { note "no log at $log"; return; }
  kept="$WORK.failed/$(basename "$log")"

  # Beside $WORK, not inside it: inside is the one place guaranteed to be
  # deleted by the next run, which is the whole problem being fixed. Not
  # cleared at startup either -- a kept log stops being interesting when the
  # same step fails again and overwrites it, and not a moment earlier.
  mkdir -p "$WORK.failed" 2> /dev/null
  cp "$log" "$kept" 2> /dev/null || kept="$log"
  # The lines that say what went wrong, not the hundreds that say what did not.
  if grep -qE '✗|FAIL|ERROR|runtime error' "$log"; then
    grep -E '✗|FAIL|ERROR|runtime error' "$log" | head -12 | sed 's/^/      /'
  else
    tail -12 "$log" | sed 's/^/      /'
  fi
  note "full output: $kept"
}

printf '\n\033[1mMemory safety\033[0m\n'

# ---------------------------------------------------------------------------
# One run at a time in this working tree.
#
# $WORK is a fixed directory rather than a mktemp one, deliberately: the logs
# and the instrumented binaries are what a failure is diagnosed from, and a
# path that changes every run is a path nobody can find afterwards. The price
# is that two runs in the same checkout share all of it -- one rebuilds
# restate-asan while the other is executing it, and both write the same log.
#
# What that produces is worse than an error. Every check still prints, so the
# run looks normal; the suite just exits non-zero with nothing in the log to
# say why, because the log that survived belongs to whichever run finished
# last -- typically the one that passed. Diagnosed exactly once, the hard way.
#
# mkdir is the primitive rather than flock, which is not on macOS or the BSDs.
# It is atomic everywhere: of two racing processes exactly one creates the
# directory and the other is told no. The lock sits beside $WORK rather than
# inside it, because the first thing below is to delete $WORK.
# ---------------------------------------------------------------------------
LOCK="$WORK.lock"
LOCK_HELD=0

# Released on the way out, but only if it is ours: a lock we failed to take
# belongs to the run that has it, and removing that on our way out would hand
# its directory to the next caller while it is still working.
trap 'if [ "$LOCK_HELD" = "1" ]; then rm -rf "$LOCK"; fi' EXIT

if ! mkdir "$LOCK" 2> /dev/null; then
  holder="$(cat "$LOCK/pid" 2> /dev/null || true)"
  if [ -n "$holder" ] && kill -0 "$holder" 2> /dev/null; then
    bad "another memcheck is already running in this tree (pid $holder)"
    note "Both would share $WORK -- the instrumented binaries and the logs --"
    note "so this one would overwrite what that one is still using. Wait for it"
    note "to finish, or stop it, and run again."
    printf '\n'
    exit 1
  fi
  # Nobody alive is holding it: a previous run was killed before it could clean
  # up. Taking it over is the right answer, and racing to take it over is safe
  # -- the mkdir below is what decides, and the loser is told no.
  note "clearing a stale lock left by pid ${holder:-unknown}"
  rm -rf "$LOCK"
  if ! mkdir "$LOCK" 2> /dev/null; then
    bad "could not take $LOCK"
    printf '\n'
    exit 1
  fi
fi
LOCK_HELD=1
echo "$$" > "$LOCK/pid"

rm -rf "$WORK"
mkdir -p "$WORK"

# Platform feature macros in one place; see scripts/features.sh.
read -r -a RS_FEATURES <<< "$(scripts/features.sh)"
CPPFLAGS_ALL=(-Iinclude -Isrc -Itests "${RS_FEATURES[@]}"
              -DRESTATE_VERSION="\"$VERSION\"")

# ---------------------------------------------------------------------------
# A corpus to point the instrumented binary at: a tree to scan, and hand-made
# malformed indexes, images and rules files, because the parser paths worth
# instrumenting are the ones restate itself never writes.
# ---------------------------------------------------------------------------
build_corpus() {
  local dir="$1"
  local hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  mkdir -p "$dir/tree/etc/deep/er/still" "$dir/tree/usr/bin" "$dir/tree/tmp" \
           "$dir/tree/var/cache"
  echo hello > "$dir/tree/etc/hello.conf"
  printf 'odd\n' > "$dir/tree/etc/tab	and
newline"
  ln -sf hello.conf "$dir/tree/etc/link"
  ln -sf /nonexistent "$dir/tree/etc/dangling"
  mkfifo "$dir/tree/etc/fifo" 2>/dev/null || true
  echo bin > "$dir/tree/usr/bin/tool"
  echo junk > "$dir/tree/tmp/junk"
  echo cache > "$dir/tree/var/cache/c"
  : > "$dir/tree/etc/empty"
  dd if=/dev/zero of="$dir/tree/etc/big.bin" bs=1024 count=300 2>/dev/null

  local head='{"format": "restate-index", "version": 1, "entries": ['
  local entry='"type": "file", "class": "state", "mode": "0644", "uid": 0, "gid": 0, "size": 0, "mtime": "2026-10-03T00:00:00.000000000Z"'
  printf '%s{"path": "/a", %s, "sha256": "%s"}]}' "$head" "$entry" "$hash" > "$dir/good.json"
  printf '%s{"path": "/a\\u00", %s}]}' "$head" "$entry" > "$dir/bad-escape.json"
  printf '%s{"path": "/a", "type": "symlink", "class": "state", "mode": "0777", "uid": 0, "gid": 0, "size": 0, "mtime": "2026-10-03T00:00:00.000000000Z"}]}' "$head" > "$dir/no-target.json"
  printf '%s{"path": "/a/../../b", %s}]}' "$head" "$entry" > "$dir/traversal.json"
  printf '%s{"path": "/a", "uid": 99999999999999999999999, %s}]}' "$head" "$entry" > "$dir/overflow.json"
  printf '%s{"path": "/a", %s}, {"path": "/a", %s}]}' "$head" "$entry" "$entry" > "$dir/duplicate.json"
  printf '%s{"path": "/a", %s, "path": "/b"}]}' "$head" "$entry" > "$dir/duplicate-key.json"
  printf '{"format": "restate-index", "root": 5, "entries": []}' > "$dir/bad-header.json"
  head -c 3000 /dev/zero | tr '\0' '[' > "$dir/deep.json"
  printf '%s' "$head" > "$dir/truncated.json"
  : > "$dir/empty.json"
  head -c 3000 /dev/urandom > "$dir/random.json"
  { printf '%s' "$head"; head -c 3000 /dev/urandom; } > "$dir/random-body.json"
  # Images: one made by hand that is not restate's, one truncated, one that
  # is gzip magic and then nothing.
  mkdir -p "$dir/notimage/x"
  echo x > "$dir/notimage/x/y"
  ( cd "$dir/notimage" && tar -cf - x | gzip -c ) > "$dir/foreign.tgz"
  printf '\037\213garbage' > "$dir/junk.tgz"

  printf 'state /a\nephemeral *.pid\nexpendable /**/cache\n' > "$dir/good.rules"
  printf 'keep /a\n' > "$dir/bad-class.rules"
  printf 'state\n' > "$dir/no-pattern.rules"
  printf 'state /a\0b\n' > "$dir/nul.rules"
  head -c 2000 /dev/urandom > "$dir/random.rules"
}

run_over_corpus() {
  local binary="$1"
  local dir="$2"
  local f

  for f in "$dir"/*.json "$dir"/*.tgz; do
    "$binary" diff "$f" "$dir/good.json" > /dev/null 2>&1
    "$binary" verify "$f" -r "$dir/tree" > /dev/null 2>&1
  done
  for f in "$dir"/*.rules; do
    "$binary" -R "$f" classify /a /a/b.pid /var/cache/x > /dev/null 2>&1
    "$binary" -N -R "$f" rules > /dev/null 2>&1
  done
  for os in linux freebsd openbsd netbsd darwin; do
    "$binary" --os="$os" -r "$dir/tree" scan -a -v > /dev/null 2>&1
  done
  "$binary" -r "$dir/tree" scan -o "$dir/scan.json" > /dev/null 2>&1
  "$binary" -r "$dir/tree" -n -x scan > /dev/null 2>&1
  "$binary" -r "$dir/tree" -a -B capture -o "$dir/image.tgz" > /dev/null 2>&1
  "$binary" diff "$dir/image.tgz" "$dir/scan.json" > /dev/null 2>&1
  head -c 2000 "$dir/image.tgz" > "$dir/truncated.tgz"
  "$binary" diff "$dir/truncated.tgz" "$dir/scan.json" > /dev/null 2>&1
  # shellcheck disable=SC2094  # reading the same file twice is the point
  "$binary" diff - "$dir/scan.json" < "$dir/scan.json" > /dev/null 2>&1
  # The argument-handling paths too. Stdin is /dev/null throughout, so nothing
  # here can wait on an inherited pipe.
  "$binary" > /dev/null 2>&1
  "$binary" --help > /dev/null 2>&1
  "$binary" --version > /dev/null 2>&1
  "$binary" --os=plan9 rules > /dev/null 2>&1
  "$binary" scan --root > /dev/null 2>&1
  "$binary" -q -v scan > /dev/null 2>&1
  "$binary" restore > /dev/null 2>&1
  return 0
}

build_corpus "$WORK/corpus"

# ---------------------------------------------------------------------------
section "AddressSanitizer + UndefinedBehaviorSanitizer"

SAN_FLAGS=(-std=c11 -O1 -g -fno-omit-frame-pointer
           "-fsanitize=address,undefined"
           -fno-sanitize-recover=all
           -Wall -Wextra)

# Everything except main.c, which the unit tests replace with their own.
LIB_SOURCES=()
for source in src/*.c; do
  [ "$source" = "src/main.c" ] || LIB_SOURCES+=("$source")
done

if "$CC" "${CPPFLAGS_ALL[@]}" "${SAN_FLAGS[@]}" -o "$WORK/restate-asan" src/*.c \
     2> "$WORK/build-asan.log"; then
  "$CC" "${CPPFLAGS_ALL[@]}" "${SAN_FLAGS[@]}" -o "$WORK/unittests-asan" \
     "${LIB_SOURCES[@]}" tests/*.c 2>> "$WORK/build-asan.log"

  export ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:detect_invalid_pointer_pairs=2:log_path=$PWD/$WORK/asan"
  export UBSAN_OPTIONS="print_stacktrace=1:log_path=$PWD/$WORK/ubsan"
  export LSAN_OPTIONS="log_path=$PWD/$WORK/lsan"

  if "$WORK/unittests-asan" > "$WORK/unittests-asan.log" 2>&1; then
    ok "unit tests are clean under ASan/UBSan (leak detection on)"
  else
    bad "unit tests failed under the sanitizers"
    show_failure "$WORK/unittests-asan.log"
    note "and $WORK/asan.*"
  fi

  if tests/cli/run.sh "$WORK/restate-asan" > "$WORK/cli-asan.log" 2>&1; then
    ok "end-to-end tests are clean under ASan/UBSan"
  else
    bad "end-to-end tests failed under the sanitizers"
    show_failure "$WORK/cli-asan.log"
  fi

  run_over_corpus "$WORK/restate-asan" "$WORK/corpus" < /dev/null

  # The sanitizers write to <log_path>.<pid>, so any such file at all is a
  # finding — the exit status alone would miss a leak in a run whose exit
  # status the test harness deliberately ignores.
  if compgen -G "$WORK/asan.*" > /dev/null || \
     compgen -G "$WORK/ubsan.*" > /dev/null || \
     compgen -G "$WORK/lsan.*" > /dev/null; then
    bad "the sanitizers reported something"
    for log in "$WORK"/asan.* "$WORK"/ubsan.* "$WORK"/lsan.*; do
      [ -f "$log" ] || continue
      note "$log:"
      head -15 "$log" | sed 's/^/      /'
    done
  else
    ok "malformed indexes, images and rules files are clean under the sanitizers"
  fi
  unset ASAN_OPTIONS UBSAN_OPTIONS LSAN_OPTIONS
else
  skip "this compiler does not support -fsanitize=address,undefined"
  note "see $WORK/build-asan.log"
fi

# ---------------------------------------------------------------------------
section "valgrind — uninitialised reads and leaks"

if command -v valgrind > /dev/null 2>&1; then
  # An uninstrumented build: valgrind and ASan must not be combined, and the
  # optimizer's view is the one a released binary has.
  "$CC" "${CPPFLAGS_ALL[@]}" -std=c11 -O1 -g -Wall -Wextra \
        -o "$WORK/restate-plain" src/*.c 2> "$WORK/build-plain.log"
  "$CC" "${CPPFLAGS_ALL[@]}" -std=c11 -O1 -g -Wall -Wextra \
        -o "$WORK/unittests-plain" "${LIB_SOURCES[@]}" tests/*.c \
        2>> "$WORK/build-plain.log"

  # --error-exitcode=42 is what valgrind returns when IT finds something; a
  # clean run passes the program's own status through. Half the corpus is
  # deliberately broken, and restate correctly exits 2 on it, so the test
  # below is "status == 42", never "status != 0".
  # tests/valgrind.supp names the C library's own allocations, each with why.
  VG=(valgrind --quiet --error-exitcode=42
      --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all
      --suppressions=tests/valgrind.supp
      --track-origins=yes --num-callers=25)
  # Descriptor tracking only for the real binary. The walker opens one
  # descriptor per directory level and a leak there is a real bug; the unit
  # tests deliberately swap stdout and stderr around to capture output, and
  # valgrind reports the restored descriptors as leaks.
  VG_FDS=("${VG[@]}" --track-fds=yes)

  "${VG[@]}" --log-file="$WORK/valgrind-unit.log" \
    "$WORK/unittests-plain" > /dev/null 2>&1
  unit_status=$?
  if [ "$unit_status" -eq 0 ]; then
    ok "unit tests are clean under valgrind"
  elif [ "$unit_status" -eq 42 ]; then
    bad "valgrind found something in the unit tests"
    note "see $WORK/valgrind-unit.log"
    head -25 "$WORK/valgrind-unit.log" | sed 's/^/      /'
  else
    bad "the unit tests themselves failed under valgrind (exit $unit_status)"
  fi

  VG_ERROR_EXIT=42
  vg_failures=0
  index=0
  # One line per run: the arguments, split on purpose.
  while IFS= read -r args; do
    [ -n "$args" ] || continue
    index=$((index + 1))
    # shellcheck disable=SC2086  # the argument string is deliberately split
    "${VG_FDS[@]}" --log-file="$WORK/valgrind-$index.log" \
      "$WORK/restate-plain" $args > /dev/null 2>&1 < /dev/null
    if [ $? -eq "$VG_ERROR_EXIT" ]; then
      vg_failures=$((vg_failures + 1))
      note "restate $args — see $WORK/valgrind-$index.log"
    fi
  done <<RUNS
--os=linux -r $WORK/corpus/tree scan -a
--os=freebsd -r $WORK/corpus/tree -n scan
--os=linux -r $WORK/corpus/tree -o $WORK/corpus/vg.json scan
--os=linux -r $WORK/corpus/tree -B -o $WORK/corpus/vg.tgz capture
diff $WORK/corpus/vg.tgz $WORK/corpus/vg.json
diff $WORK/corpus/good.json $WORK/corpus/random-body.json
diff $WORK/corpus/good.json $WORK/corpus/traversal.json
diff $WORK/corpus/duplicate.json $WORK/corpus/good.json
diff $WORK/corpus/foreign.tgz $WORK/corpus/good.json
verify $WORK/corpus/good.json -r $WORK/corpus/tree
-R $WORK/corpus/good.rules classify /a /var/cache/x /b.pid
-R $WORK/corpus/random.rules classify /a
--os=darwin rules
--help
scan --root
RUNS
  if [ "$vg_failures" -eq 0 ]; then
    ok "every corpus run is clean under valgrind"
  else
    bad "valgrind found something on $vg_failures of the corpus runs"
  fi
else
  skip "valgrind is not installed"
  note "sudo apt install valgrind   (or: make install-dev)"
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ ${#SKIPPED[@]} -gt 0 ]; then
  printf '  \033[93mSkipped:\033[0m %s\n' "${SKIPPED[*]}"
fi
if [ ${#FAILURES[@]} -eq 0 ]; then
  printf '  \033[92m✓ no memory errors, no leaks, no undefined behavior\033[0m\n\n'
  exit 0
fi
printf '  \033[91m✗ %d memory check(s) failed\033[0m\n\n' "${#FAILURES[@]}"
exit 1
