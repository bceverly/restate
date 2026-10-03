#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Run the same security scanners CI runs, locally.
#
#   make security
#
# The threat model: restate runs as root, reads every file on the machine, and
# walks directories that unprivileged users own and can change mid-scan. It
# also reads manifests and rules files back in, and a manifest may have come
# off a dead machine or a USB stick. So the bugs that matter are memory-safety
# bugs in the parsers, anything a user can do to steer the walk somewhere it
# should not go, and anything that leaks what the walk saw. The checks below
# are ordered by how close they sit to that:
#
#   1. the binary's own hardening      is the shipped executable defended
#   2. gcc -fanalyzer                  leaks, double frees, null derefs
#   3. cppcheck + CERT C rules         the rule-based second opinion
#   4. clang's static analyzer         the third
#   5. flawfinder                      known-dangerous API use
#   6. semgrep                         pattern-based SAST
#   7. the sanitizers                  the real thing, at runtime
#   8. a short fuzz run                the real thing, on inputs nobody wrote
#   9. gitleaks                        committed secrets
#  10. MITRE's "Lucky 13"              the unforgivable classes, one by one
#
# Anything not installed is reported as skipped rather than failing the run.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

CC="${CC:-cc}"
VERSION="$(cat VERSION)"
REPORTS=".security-reports"
FAILURES=()
SKIPPED=()

section() { printf '\n\033[1;94m▸ %s\033[0m\n' "$*"; }
ok()      { printf '  \033[92m✓\033[0m %s\n' "$*"; }
bad()     { printf '  \033[91m✗\033[0m %s\n' "$*"; FAILURES+=("$1"); }
skip()    { printf '  \033[93m-\033[0m %s\n' "$*"; SKIPPED+=("$1"); }
note()    { printf '    \033[2m%s\033[0m\n' "$*"; }

mkdir -p "$REPORTS"
printf '\n\033[1mSecurity scan\033[0m \033[2m(same tools as CI)\033[0m\n'

# Platform feature macros in one place; see scripts/features.sh.
read -r -a RS_FEATURES <<< "$(scripts/features.sh)"
CPPFLAGS_ALL=(-Iinclude -Isrc "${RS_FEATURES[@]}"
              -DRESTATE_VERSION="\"$VERSION\"")

# ---------------------------------------------------------------------------
section "binary hardening"
#
# What is actually in the executable that ships, rather than what the flags in
# the Makefile say. The two come apart more easily than they should: a
# distribution's CFLAGS override, a linker that quietly drops an option, a
# _FORTIFY_SOURCE that did nothing because the build was -O0.
if [ ! -x bin/restate ]; then
  skip "bin/restate is not built — run 'make build' first"
elif command -v hardening-check > /dev/null 2>&1; then
  #
  # The report is read rather than the exit status trusted, because which
  # features hardening-check knows about — and which command-line options it
  # offers to skip them — varies between devscripts releases. Asking it to
  # skip a check it has never heard of is a hard error: passing
  # --nobranchprotection is fine on 26.04 and fails outright on 24.04 with
  # "Unknown option", which is how a scan that was green on a laptop failed on
  # a runner. Parsing the lines works on every version.
  #
  # Branch Protection is deliberately not required. It is an AArch64
  # pointer-authentication feature; on x86 the equivalent is CET, which is
  # checked on its own line and which this build does enable.
  hardening-check bin/restate > "$REPORTS/hardening.txt" 2>&1 || true

  #
  # "unknown" is not "missing", and treating it as such is stricter than the
  # tool itself (which exits 0 on it). It means hardening-check found no
  # evidence either way -- for stack-clash protection that is the normal
  # result on a program whose stack frames are all small, since the compiler
  # only emits a probe where one is actually needed. The flag is passed; there
  # was simply nothing for it to do.
  missing=()
  unknown=()
  present=0
  while IFS= read -r line; do
    feature="${line%%:*}"
    feature="${feature#"${feature%%[![:space:]]*}"}"   # trim leading spaces
    verdict="${line#*: }"
    case "$feature" in
      # AArch64 pointer authentication. On x86 the equivalent is CET, which
      # has a line of its own and which this build enables.
      "Branch Protection") continue ;;
      "") continue ;;
    esac
    case "$verdict" in
      yes*)     present=$((present + 1)) ;;
      unknown*) unknown+=("$feature") ;;
      *)        missing+=("$feature") ;;
    esac
  done < <(grep ':' "$REPORTS/hardening.txt" | grep -v '^[^ ]')

  if [ ${#missing[@]} -eq 0 ] && [ "$present" -gt 0 ]; then
    ok "$present hardening features present (PIE, stack protector, fortify, RELRO, BIND_NOW, CET)"
    if [ ${#unknown[@]} -gt 0 ]; then
      note "not determinable from the binary: ${unknown[*]}"
      note "(enabled at compile time; the compiler emitted no instruction needing it)"
    fi
  elif [ "$present" -eq 0 ]; then
    bad "could not read hardening-check's report"
    sed 's/^/      /' "$REPORTS/hardening.txt"
  else
    bad "the binary is missing: ${missing[*]}"
    sed 's/^/      /' "$REPORTS/hardening.txt"
  fi
elif command -v readelf > /dev/null 2>&1; then
  # The parts that can be seen without devscripts installed.
  missing=()
  readelf -d bin/restate 2>/dev/null | grep -q "BIND_NOW" || missing+=("BIND_NOW")
  readelf -lW bin/restate 2>/dev/null | grep -q "GNU_RELRO" || missing+=("RELRO")
  readelf -sW bin/restate 2>/dev/null | grep -q "__stack_chk_fail" || missing+=("stack protector")
  readelf -sW bin/restate 2>/dev/null | grep -q "_chk@" || missing+=("_FORTIFY_SOURCE")
  if [ ${#missing[@]} -eq 0 ]; then
    ok "RELRO, BIND_NOW, the stack protector and fortified calls are all present"
  else
    bad "the binary is missing: ${missing[*]}"
  fi
else
  skip "neither hardening-check nor readelf is installed"
fi

# ---------------------------------------------------------------------------
section "gcc -fanalyzer — leaks, double frees, null dereferences"
if "$CC" -fanalyzer -fsyntax-only -x c /dev/null > /dev/null 2>&1; then
  if "$CC" -std=c11 -O2 "${CPPFLAGS_ALL[@]}" -fanalyzer \
       -Wanalyzer-too-complex -Wall -Wextra -Werror \
       -fsyntax-only src/*.c 2> "$REPORTS/analyzer.log"; then
    ok "no findings"
  else
    bad "gcc -fanalyzer found something"
    sed 's/^/      /' "$REPORTS/analyzer.log" | head -40
  fi
else
  skip "this compiler has no -fanalyzer"
fi

# ---------------------------------------------------------------------------
section "cppcheck — with the CERT C rules"
if command -v cppcheck > /dev/null 2>&1; then
  ADDONS=()
  # The CERT addon ships with cppcheck but is not enabled by default.
  for candidate in /usr/share/cppcheck/addons/cert.py \
                   /usr/local/share/cppcheck/addons/cert.py; do
    [ -f "$candidate" ] && ADDONS+=("--addon=$candidate") && break
  done
  if cppcheck --quiet --error-exitcode=1 --std=c11 \
       --enable=warning,style,performance,portability \
       "${ADDONS[@]+"${ADDONS[@]}"}" --inline-suppr \
       --suppress=missingIncludeSystem --suppress=unusedFunction \
       --suppress=checkersReport \
       -I include -I src src 2> "$REPORTS/cppcheck.log"; then
    ok "no findings${ADDONS[0]:+ (CERT rules included)}"
  else
    bad "cppcheck found something"
    sed 's/^/      /' "$REPORTS/cppcheck.log" | head -40
  fi
else
  skip "cppcheck is not installed"
  note "sudo apt install cppcheck"
fi

# ---------------------------------------------------------------------------
section "clang static analyzer"
if command -v scan-build > /dev/null 2>&1; then
  if scan-build -o "$REPORTS/scan-build" --status-bugs \
       "$CC" -std=c11 "${CPPFLAGS_ALL[@]}" -fsyntax-only src/*.c \
       > "$REPORTS/scan-build.log" 2>&1; then
    ok "no findings"
  else
    bad "the clang analyzer found something"
    note "the report is under $REPORTS/scan-build/"
    grep -E "warning:" "$REPORTS/scan-build.log" | head -20 | sed 's/^/      /'
  fi
else
  skip "scan-build is not installed"
  note "sudo apt install clang-tools"
fi

# ---------------------------------------------------------------------------
section "flawfinder — known-dangerous API use"
if command -v flawfinder > /dev/null 2>&1; then
  # --error-level=3 is "medium and above". Levels 1 and 2 are almost entirely
  # reports of memcpy and snprintf existing, which is what a parser is made of.
  if flawfinder --quiet --dataonly --error-level=3 --minlevel=3 \
       src include > "$REPORTS/flawfinder.txt" 2>&1; then
    ok "no findings at level 3 or above"
  else
    bad "flawfinder found something"
    sed 's/^/      /' "$REPORTS/flawfinder.txt" | head -30
  fi
else
  skip "flawfinder is not installed"
  note "pipx install flawfinder   (or: sudo apt install flawfinder)"
fi

# ---------------------------------------------------------------------------
section "semgrep — pattern-based static analysis"
if command -v semgrep > /dev/null 2>&1; then
  if semgrep --config=p/c --config=p/secrets --error --quiet --metrics=off \
       --json --output="$REPORTS/semgrep.json" src include tests scripts \
       > /dev/null 2>&1; then
    ok "no findings"
  else
    bad "semgrep found something"
    note "see $REPORTS/semgrep.json"
    if command -v python3 > /dev/null 2>&1; then
      python3 - "$REPORTS/semgrep.json" <<'PYEOF' | head -30
import json, sys
try:
    results = json.load(open(sys.argv[1]))["results"]
except (OSError, ValueError, KeyError):
    print("      (report unreadable)")
    raise SystemExit
for finding in results:
    rule = finding["check_id"].rsplit(".", 1)[-1]
    print(f"      {finding['path']}:{finding['start']['line']}  {rule}")
    print("        " + " ".join(finding["extra"]["message"].split())[:140])
PYEOF
    fi
  fi
else
  skip "semgrep is not installed"
  note "pipx install semgrep"
fi

# ---------------------------------------------------------------------------
section "the sanitizers, at runtime"
# The static tools above reason about the code; this runs it. For a parser
# that is the more convincing of the two, which is why it is part of the
# security scan and not only of `make test`.
if scripts/memcheck.sh > "$REPORTS/memcheck.log" 2>&1; then
  ok "no memory errors, leaks or undefined behavior"
else
  bad "the sanitizers found something"
  note "see $REPORTS/memcheck.log"
  grep -E "✗|ERROR|runtime error" "$REPORTS/memcheck.log" | head -20 | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
section "fuzzing — inputs nobody wrote"
FUZZ_SECONDS="${SECURITY_FUZZ_SECONDS:-60}"
if FUZZ_SECONDS="$FUZZ_SECONDS" scripts/fuzz.sh > "$REPORTS/fuzz.log" 2>&1; then
  # Either engine, whichever ran: the built-in loop counts "N cases", libFuzzer
  # reports "Done N runs". Without both patterns the line came out as
  # "✓  in 120s, no crashes" on a runner where libFuzzer was the one available.
  FUZZ_COUNT="$(grep -oE '[0-9]+ cases' "$REPORTS/fuzz.log" | tail -1)"
  if [ -z "$FUZZ_COUNT" ]; then
    FUZZ_COUNT="$(grep -oE 'Done [0-9]+ runs' "$REPORTS/fuzz.log" | tail -1 \
                  | sed 's/Done //; s/ runs/ cases/')"
  fi
  ok "${FUZZ_COUNT:-the fuzzer ran} in ${FUZZ_SECONDS}s, no crashes"
elif grep -q 'could not build the fuzz target' "$REPORTS/fuzz.log"; then
  # A target that does not compile has found nothing. Reporting it as a crash
  # sends somebody looking for a malformed input that does not exist.
  bad "the fuzz target failed to BUILD — nothing was fuzzed"
  note "tests/fuzz/fuzz_restate.c is compiled by nothing else; 'make lint' checks it"
  # Show the compiler error itself. Echoing fuzz.sh's own failure line back
  # would only repeat that it failed, not say why.
  if [ -s .fuzz/build-builtin.log ]; then
    grep -E 'error:|note:' .fuzz/build-builtin.log | head -6 | sed 's/^/      /'
    note "full output in .fuzz/build-builtin.log"
  else
    note "see $REPORTS/fuzz.log"
  fi
else
  bad "the fuzzer found a crash"
  note "see $REPORTS/fuzz.log, .fuzz/crash.bin and .fuzz/findings/"
  tail -20 "$REPORTS/fuzz.log" | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
section "gitleaks — committed secrets"
if command -v gitleaks > /dev/null 2>&1; then
  if gitleaks detect --no-banner --redact \
       --report-path "$REPORTS/gitleaks.json" > "$REPORTS/gitleaks.log" 2>&1; then
    ok "no secrets in the history"
  else
    bad "gitleaks found something"
    note "see $REPORTS/gitleaks.json — the values are redacted in the report"
    tail -20 "$REPORTS/gitleaks.log" | sed 's/^/      /'
  fi
else
  skip "gitleaks is not installed"
  note "see scripts/install-dev.sh, which installs a pinned release"
fi

# ---------------------------------------------------------------------------
section "MITRE's \"Lucky 13\" — the unforgivable vulnerabilities"
# Christey's thirteen classes from MITRE's "Unforgivable Vulnerabilities"
# (2007), each checked or ruled out with a reason; scripts/lucky13.sh has the
# detail and `make lucky13` runs it alone.
if scripts/lucky13.sh > "$REPORTS/lucky13.log" 2>&1; then
  ok "all 13 accounted for, none found"
  if grep -q 'Skipped' "$REPORTS/lucky13.log"; then
    note "some runtime checks were skipped; see $REPORTS/lucky13.log"
  fi
else
  bad "a Lucky 13 check failed"
  grep -E '✗' "$REPORTS/lucky13.log" | sed 's/^/      /'
  note "see $REPORTS/lucky13.log"
fi

# ---------------------------------------------------------------------------
section "dependencies"
# Said out loud rather than left as an absent section: a CVE in a dependency is
# the most common way a small tool becomes vulnerable, and a recovery tool
# especially must not depend on a library the broken machine may be missing.
# The claim is checked, not asserted: anything linked beyond the C runtime
# fails this.
if command -v ldd > /dev/null 2>&1 && ldd bin/restate > /dev/null 2>&1; then
  NONLIBC="$(ldd bin/restate 2>/dev/null \
             | grep -oE '/[^ ]*lib[a-z0-9_.+-]+\.so[^ ]*' \
             | grep -vE '/(libc|libm|libdl|libpthread|librt|ld-linux[^/]*|ld-musl[^/]*)[.-]' \
             || true)"
  if [ -n "$NONLIBC" ]; then
    bad "the binary links something beyond the C runtime"
    printf '%s\n' "$NONLIBC" | sed 's/^/      /'
  else
    ok "nothing is vendored, and nothing beyond libc is linked"
  fi
elif command -v otool > /dev/null 2>&1; then
  NONLIBC="$(otool -L bin/restate | tail -n +2 | grep -v 'libSystem' || true)"
  if [ -n "$NONLIBC" ]; then
    bad "the binary links something beyond libSystem"
    printf '%s\n' "$NONLIBC" | sed 's/^/      /'
  else
    ok "nothing is vendored, and nothing beyond libSystem is linked"
  fi
else
  skip "neither ldd nor otool is available to list what the binary links"
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ ${#SKIPPED[@]} -gt 0 ]; then
  printf '  \033[93mSkipped:\033[0m %d scanner(s) not installed\n' "${#SKIPPED[@]}"
  note "make install-dev installs every one of them"
fi
if [ ${#FAILURES[@]} -eq 0 ]; then
  printf '  \033[92m✓ security scan clean\033[0m\n\n'
  exit 0
fi
printf '  \033[91m✗ %d security check(s) failed\033[0m\n\n' "${#FAILURES[@]}"
exit 1
