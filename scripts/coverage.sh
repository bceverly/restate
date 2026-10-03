#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Measure line coverage and fail below the gate.
#
#   make coverage                      the default 80% gate
#   COVERAGE_MIN=90 make coverage      a stricter one overall
#   COVERAGE_FILE_MIN=85 make coverage a stricter one per file
#
# Two gates, both 80% by default: the total, and every source file on its own.
# The total alone can hide a file nobody tested behind the files somebody
# tested twice; the per-file gate means there is no such file.
#
# The 80% gate is a floor, not a target, and it can only be raised:
# COVERAGE_MIN below 80 is refused, so a red build cannot be turned green by
# lowering the bar instead of writing the test.
#
# The whole program is rebuilt with gcov instrumentation, then BOTH suites are
# run against it: the unit tests and the end-to-end tests. The unit tests never
# reach main.c, and the end-to-end tests are what cover it, so measuring either
# alone reports a number that is wrong.
#
# The report is computed from gcov's own .gcov output rather than from gcovr,
# so `make coverage` works on a machine with nothing but a compiler installed.
# gcovr, when present, additionally writes the XML that CI uploads.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

COVERAGE_MIN="${COVERAGE_MIN:-80}"
COVERAGE_FILE_MIN="${COVERAGE_FILE_MIN:-80}"
COVERAGE_FLOOR=80
for gate in COVERAGE_MIN COVERAGE_FILE_MIN; do
  if ! [ "${!gate}" -ge "$COVERAGE_FLOOR" ] 2>/dev/null; then
    printf '  \033[91m✗\033[0m %s=%s: the gate cannot go below %d%%\n' \
           "$gate" "${!gate}" "$COVERAGE_FLOOR" >&2
    exit 1
  fi
done
COV_DIR=".coverage"
OBJ_DIR="$COV_DIR/obj"
CC="${CC:-cc}"
VERSION="$(cat VERSION)"

# Platform feature macros in one place; see scripts/features.sh.
read -r -a RS_FEATURES <<< "$(scripts/features.sh)"
CPPFLAGS_ALL=(-Iinclude -Isrc -Itests "${RS_FEATURES[@]}"
              -DRESTATE_VERSION="\"$VERSION\"")
# -O0: an optimized build merges and reorders lines, and the resulting report
# blames coverage on lines that no longer exist as written.
CFLAGS_ALL=(-std=c11 -O0 -g --coverage -fprofile-abs-path -Wall -Wextra)

printf '\n\033[1mCoverage\033[0m \033[2m(gate: %s%% overall, %s%% every file)\033[0m\n' \
       "$COVERAGE_MIN" "$COVERAGE_FILE_MIN"

rm -rf "$COV_DIR"
mkdir -p "$OBJ_DIR"

# ---------------------------------------------------------------------------
# Build instrumented
# ---------------------------------------------------------------------------
objects=()
for source in src/*.c; do
  object="$OBJ_DIR/$(basename "$source" .c).o"
  if ! "$CC" "${CPPFLAGS_ALL[@]}" "${CFLAGS_ALL[@]}" -c "$source" -o "$object"; then
    echo "  build failed: $source" >&2
    exit 1
  fi
  objects+=("$object")
done

test_objects=()
for source in tests/*.c; do
  object="$OBJ_DIR/test_$(basename "$source" .c).o"
  if ! "$CC" "${CPPFLAGS_ALL[@]}" "${CFLAGS_ALL[@]}" -c "$source" -o "$object"; then
    echo "  build failed: $source" >&2
    exit 1
  fi
  test_objects+=("$object")
done

# The program, and the unit tests with everything except main.o.
"$CC" --coverage -o "$COV_DIR/restate" "${objects[@]}" || exit 1
lib_objects=()
for object in "${objects[@]}"; do
  [ "$(basename "$object")" = "main.o" ] || lib_objects+=("$object")
done
"$CC" --coverage -o "$COV_DIR/unittests" "${lib_objects[@]}" "${test_objects[@]}" || exit 1

# ---------------------------------------------------------------------------
# Exercise it
# ---------------------------------------------------------------------------
printf '  \033[96m→\033[0m running the unit tests\n'
if ! "$COV_DIR/unittests" > "$COV_DIR/unittests.log" 2>&1; then
  echo "  unit tests failed — see $COV_DIR/unittests.log" >&2
  tail -20 "$COV_DIR/unittests.log" >&2
  exit 1
fi

printf '  \033[96m→\033[0m running the end-to-end tests\n'
if ! tests/cli/run.sh "$COV_DIR/restate" > "$COV_DIR/cli.log" 2>&1; then
  echo "  end-to-end tests failed — see $COV_DIR/cli.log" >&2
  tail -20 "$COV_DIR/cli.log" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
( cd "$COV_DIR" && gcov -o obj ../src/*.c ) > "$COV_DIR/gcov.log" 2>&1 || true

printf '\n  \033[1m%-16s %8s %8s %7s\033[0m\n' "file" "lines" "covered" "%"

total_lines=0
total_covered=0
worst_file=""
worst_pct=101
below=()

for source in src/*.c; do
  name="$(basename "$source")"
  report="$COV_DIR/$name.gcov"
  [ -f "$report" ] || continue

  # A .gcov line is "<count>:<line>:<source>". "#####" and "=====" mean the
  # line was compiled and never run; "-" means there is no code on it.
  read -r lines covered <<< "$(
    awk -F: '
      {
        count = $1
        gsub(/^[ \t]+|[ \t]+$/, "", count)
        if (count == "-") next
        lines++
        if (count != "#####" && count != "=====") covered++
      }
      END { printf "%d %d\n", lines, covered }
    ' "$report"
  )"

  [ "$lines" -gt 0 ] || continue
  percent=$(( covered * 100 / lines ))
  total_lines=$(( total_lines + lines ))
  total_covered=$(( total_covered + covered ))

  if [ "$percent" -lt 60 ]; then color='\033[91m'
  elif [ "$percent" -lt 80 ]; then color='\033[93m'
  else color='\033[92m'; fi
  printf "  %-16s %8d %8d ${color}%6d%%\033[0m\n" "$name" "$lines" "$covered" "$percent"

  if [ "$percent" -lt "$COVERAGE_FILE_MIN" ]; then
    below+=("$name ($percent%)")
  fi
  if [ "$percent" -lt "$worst_pct" ]; then
    worst_pct=$percent
    worst_file=$name
  fi
done

if [ "$total_lines" -eq 0 ]; then
  echo "  no coverage data was produced — is gcov installed?" >&2
  exit 1
fi

total_percent=$(( total_covered * 100 / total_lines ))
printf '  %-16s %8d %8d %6d%%\n' "----" "$total_lines" "$total_covered" "$total_percent"

# gcovr, when it is installed, writes the machine-readable report CI keeps.
if command -v gcovr > /dev/null 2>&1; then
  gcovr --root . --filter 'src/.*' \
        --xml-pretty --output "$COV_DIR/coverage.xml" \
        --html-details "$COV_DIR/index.html" \
        --gcov-object-directory "$OBJ_DIR" > /dev/null 2>&1 \
    && printf '  \033[2mwrote %s/coverage.xml and %s/index.html\033[0m\n' "$COV_DIR" "$COV_DIR"
fi

# ---------------------------------------------------------------------------
# The README badge
#
# Generated from the number just measured rather than typed into the README by
# hand, because a coverage badge that is edited by a person is a coverage badge
# that is eventually wrong. Committed, so the README renders without a network
# round trip.
#
# Colors: red below either gate, amber for a pass with no headroom, green above.
# ---------------------------------------------------------------------------
BADGE_GOOD="${COVERAGE_GOOD:-85}"
if   [ "$total_percent" -lt "$COVERAGE_MIN" ] || [ ${#below[@]} -gt 0 ]; then badge_color=red
elif [ "$total_percent" -lt "$BADGE_GOOD" ];  then badge_color=amber
else                                               badge_color=green
fi
scripts/badge.sh "coverage" "${total_percent}%" "$badge_color" \
  "docs/badges/coverage.svg"
printf '  \033[2mwrote docs/badges/coverage.svg (%s)\033[0m\n' "$badge_color"

printf '\n'
failed=0
if [ "$total_percent" -lt "$COVERAGE_MIN" ]; then
  printf '  \033[91m✗ %d%% line coverage is below the %d%% gate\033[0m\n' \
         "$total_percent" "$COVERAGE_MIN"
  failed=1
fi
if [ ${#below[@]} -gt 0 ]; then
  printf '  \033[91m✗ %d file(s) below the %d%% per-file gate:\033[0m %s\n' \
         "${#below[@]}" "$COVERAGE_FILE_MIN" "${below[*]}"
  failed=1
fi
if [ "$failed" -eq 1 ]; then
  printf '    Least covered: %s at %d%%\n' "$worst_file" "$worst_pct"
  printf '    The annotated sources are in %s/*.gcov — lines marked ##### never ran.\n\n' \
         "$COV_DIR"
  exit 1
fi
printf '  \033[92m✓ %d%% line coverage, every file at least %d%% (gates: %d%% / %d%%)\033[0m\n\n' \
       "$total_percent" "$worst_pct" "$COVERAGE_MIN" "$COVERAGE_FILE_MIN"
