#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Static analysis and the house rules.
#
#   make lint
#
# In order of how likely they are to be the thing that is wrong:
#
#   1. the compiler, with every warning this project is clean under and -Werror
#   2. gcc -fanalyzer, which does path-sensitive analysis and finds leaks and
#      null dereferences the warning flags do not
#   3. cppcheck, a second opinion from a different engine
#   4. clang-tidy, a third
#   5. the house style: tmd's formatting (scripts/style.sh), braces on their
#      own line, American spelling
#   6. the copyright audit -- every source file, the Makefile, the workflows
#      and the repository configuration carry the same notice
#   7. shellcheck on every script and actionlint on every workflow
#   8. the generated files (manpage, README usage) match the binary
#
# A tool that is not installed is reported as skipped rather than failing the
# run. `make install-dev` installs all of them, and CI installs all of them, so
# nothing skips in the place where skipping would matter.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

CC="${CC:-cc}"
VERSION="$(cat VERSION)"
WORK=".lint"
FAILURES=()
SKIPPED=()

section() { printf '\n\033[1;94m▸ %s\033[0m\n' "$*"; }
ok()      { printf '  \033[92m✓\033[0m %s\n' "$*"; }
bad()     { printf '  \033[91m✗\033[0m %s\n' "$*"; FAILURES+=("$1"); }
skip()    { printf '  \033[93m-\033[0m %s\n' "$*"; SKIPPED+=("$1"); }
note()    { printf '    \033[2m%s\033[0m\n' "$*"; }

mkdir -p "$WORK"
printf '\n\033[1mLint\033[0m\n'

WARNINGS=(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
          -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Wformat-nonliteral -Wcast-qual
          -Wwrite-strings -Wpointer-arith -Wundef -Wredundant-decls
          -Wmissing-declarations -Wdouble-promotion
          -Wold-style-definition -Wnested-externs)
# -Wswitch-enum is deliberately NOT in that list. It demands every enumerator
# be named even in a switch that already has a default, which would turn each
# of the "how do I render this kind" switches into a wall of cases that all do
# the same thing — and would then have to be edited in five places to add one
# enumerator. -Wswitch, which -Wall already includes, catches the case that
# actually matters: a switch with no default that forgot a value.
# The feature macros come from scripts/features.sh, not from here: they differ
# per platform and there are seven places that need the same answer.
read -r -a RS_FEATURES <<< "$(scripts/features.sh)"
CPPFLAGS_ALL=(-Iinclude -Isrc -Itests "${RS_FEATURES[@]}"
              -D_FORTIFY_SOURCE=2 -DRESTATE_VERSION="\"$VERSION\"")

# ---------------------------------------------------------------------------
section "the compiler, with -Werror"
if "$CC" -std=c11 -O2 "${CPPFLAGS_ALL[@]}" "${WARNINGS[@]}" -Werror \
     -fsyntax-only src/*.c 2> "$WORK/compiler.log"; then
  ok "no warnings from $("$CC" --version | head -1 | cut -d' ' -f1-3)"
else
  bad "the compiler found something"
  sed 's/^/      /' "$WORK/compiler.log" | head -40
fi

# ---------------------------------------------------------------------------
section "the fuzz target still compiles"
#
# tests/fuzz/fuzz_restate.c is source that NOTHING else in the build touches:
# not `make build`, not the unit tests, not coverage. Only `make fuzz` and
# `make security` compile it, so a rename in the headers would rot it silently
# and the next fuzz run would report a build failure instead of a result.
#
# -fsyntax-only, so this costs a fraction of a second and needs no sanitizer
# runtime installed.
if "$CC" -std=c11 -O2 "${CPPFLAGS_ALL[@]}" "${WARNINGS[@]}" -Werror \
     -fsyntax-only tests/fuzz/fuzz_restate.c 2> "$WORK/fuzz-target.log"; then
  ok "tests/fuzz/fuzz_restate.c compiles against the current headers"
else
  bad "the fuzz target no longer compiles"
  sed 's/^/      /' "$WORK/fuzz-target.log" | head -20
fi

# ---------------------------------------------------------------------------
section "gcc -fanalyzer — path-sensitive analysis"
# Separate from the warning pass because it is slow and because its findings
# are of a different kind: leaks, double frees and null dereferences along a
# specific path, rather than a suspicious line.
# Probed rather than matched on the compiler's name: this machine's `cc` is
# gcc and says "cc (Ubuntu 15.2.0) 15.2.0" when asked, with the word "gcc"
# nowhere in it — so a name match reported "not gcc" about gcc and skipped the
# analyzer silently, which is the one thing this script promises not to do.
if "$CC" -fanalyzer -fsyntax-only -x c /dev/null > /dev/null 2>&1; then
  if "$CC" -std=c11 -O2 "${CPPFLAGS_ALL[@]}" -fanalyzer -Wall \
       -fsyntax-only src/*.c 2> "$WORK/analyzer.log"; then
    ok "no findings"
  else
    bad "gcc -fanalyzer found something"
    sed 's/^/      /' "$WORK/analyzer.log" | head -40
  fi
else
  skip "gcc -fanalyzer needs gcc (this is $("$CC" --version | head -1))"
fi

# ---------------------------------------------------------------------------
section "cppcheck"
if command -v cppcheck > /dev/null 2>&1; then
  # --error-exitcode makes a finding a failure. The suppressions are for checks
  # that do not apply rather than for findings being ignored:
  #   missingIncludeSystem  cppcheck does not have the system headers
  #   unusedFunction        every exported function is used by another unit or
  #                         by the tests, which cppcheck does not analyze here
  #   checkersReport        an informational note, not a finding
  if cppcheck --quiet --error-exitcode=1 --std=c11 --enable=warning,style,performance,portability \
       --inline-suppr \
       --suppress=missingIncludeSystem --suppress=unusedFunction \
       --suppress=checkersReport \
       -I include -I src -I tests \
       src tests 2> "$WORK/cppcheck.log"; then
    ok "no findings"
  else
    bad "cppcheck found something"
    sed 's/^/      /' "$WORK/cppcheck.log" | head -40
  fi
else
  skip "cppcheck is not installed"
  note "sudo apt install cppcheck   (or: make install-dev)"
fi

# ---------------------------------------------------------------------------
section "clang-tidy"
if command -v clang-tidy > /dev/null 2>&1; then
  # bugprone, cert and the clang analyzer. Most of readability-* and the naming
  # checks are deliberately off: they encode a house style that is not this
  # one, and a linter that reports 400 things nobody intends to change is a
  # linter that gets switched off entirely.
  #
  # One readability check is ON, by name, because it IS this house style:
  #
  #   readability-braces-around-statements
  #       Every if/else/for/while body is braced, including a single statement.
  #       Not a matter of taste: an unbraced body is one careless edit away from
  #       a second statement that looks guarded and is not. That is exactly
  #       CVE-2014-1266 -- Apple's "goto fail", a duplicated `goto fail;` under
  #       an unbraced `if` that skipped the rest of a TLS signature check and
  #       shipped. The check is cheap, the fix is mechanical, and the failure it
  #       prevents is invisible in review.
  #
  # Four checks are disabled by name. Each is off because it does not apply to
  # C as written here, not because its findings were inconvenient — everything
  # else these checks reported was fixed rather than silenced:
  #
  #   security.insecureAPI.DeprecatedOrUnsafeBufferHandling
  #       Wants fprintf_s and snprintf_s, the bounds-checked functions of ISO
  #       C11 Annex K. Annex K is OPTIONAL, glibc does not implement any of it,
  #       and no Linux libc does — so there is literally nothing to call. It
  #       reported 160 findings, one per printf in the program.
  #
  #   bugprone-multi-level-implicit-pointer-conversion
  #       Flags `char **p = malloc(...)` and `free(p)`. Conversion to and from
  #       `void *` is defined by C itself (C11 6.3.2.3), and casting the result
  #       of an allocator is a C++ habit that C style guides advise against.
  #       All eight findings were malloc/realloc/free calls.
  #
  #   misc-include-cleaner
  #       Wants every transitively-used declaration included directly, which
  #       means naming <stddef.h> beside every <stdio.h>.
  #
  #   bugprone-easily-swappable-parameters
  #       Flags (const char *a, const char *b) signatures. True of most string
  #       functions ever written.
  #
  #   clang-analyzer-valist.Uninitialized
  #       A false positive in the analyzer shipped with clang 18 (Ubuntu
  #       24.04), which does not model va_copy and reports the vsnprintf in
  #       xvasprintf as taking an uninitialized va_list when it is the freshly
  #       va_copy'd one. Correct C, and a newer clang says nothing. The sibling
  #       checks valist.Unterminated and valist.CopyToSelf stay on.
  if clang-tidy --quiet \
       '-checks=-*,bugprone-*,cert-*,clang-analyzer-*,misc-*,performance-*,readability-braces-around-statements,-misc-include-cleaner,-bugprone-easily-swappable-parameters,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,-bugprone-multi-level-implicit-pointer-conversion,-clang-analyzer-valist.Uninitialized' \
       --warnings-as-errors='*' \
       src/*.c -- -std=c11 "${CPPFLAGS_ALL[@]}" > "$WORK/clang-tidy.log" 2>&1; then
    # Name the version, as the compiler section above does.
    #
    # clang-tidy's checks change between releases: 19 refined
    # bugprone-sizeof-expression and fixed the valist false positive that 18
    # reports. So "clean locally, failed in CI" is usually a version gap, and
    # having both logs state their version turns that from a puzzle into a
    # one-line comparison.
    ok "no findings ($(clang-tidy --version | sed -n 's/.*LLVM version /clang-tidy /p' | head -1))"
  else
    bad "clang-tidy found something"
    grep -E "warning:|error:" "$WORK/clang-tidy.log" | head -30 | sed 's/^/      /'
  fi
else
  skip "clang-tidy is not installed"
  note "sudo apt install clang-tidy   (or: make install-dev)"
fi

# ---------------------------------------------------------------------------
section "brace style"
#
# The opening brace of a control statement goes on its own line.
#
#     if (x)          not     if (x) {
#     {
#
# A house rule, adopted because the maintainer finds the attached form harder
# to read, and enforced here because a style nobody checks is a style that half
# the file follows. It is deliberately narrow: this is about STATEMENTS. A
# struct, union or enum body and an initializer keep their brace where it is,
# because those are declarations of shape rather than blocks of code, and moving
# theirs would make a table of constants twice as tall for no gain.
#
# Written in awk rather than clang-format because clang-format cannot be asked
# for one rule: it reformats everything, and this file is full of alignment and
# comment wrapping that was done by hand and is meant to stay.
BRACE_HITS="$(awk '
  # Track block comments so a brace inside prose is not mistaken for code.
  {
    line = $0
    if (in_comment) {
      if (match(line, /\*\//)) { line = substr(line, RSTART + 2); in_comment = 0 }
      else { next }
    }
    # Drop trailing line comments and any complete block comment.
    gsub(/\/\*[^*]*\*+([^\/*][^*]*\*+)*\//, "", line)
    if (match(line, /\/\*/)) { line = substr(line, 1, RSTART - 1); in_comment = 1 }
    sub(/\/\/.*/, "", line)
    sub(/[ \t]+$/, "", line)

    if (line !~ /\{$/) next
    body = line
    sub(/^[ \t]+/, "", body)
    if (body == "{") next                                  # already alone
    if (body ~ /^(static[ \t]+|const[ \t]+)*(struct|union|enum|typedef)\y/) next
    if (body ~ /=[ \t]*\{$/) next                          # an initializer
    printf "%s:%d: %s\n", FILENAME, FNR, body
  }
' src/*.c src/*.h include/*.h tests/*.c tests/*.h tests/fuzz/*.c || true)"

if [ -z "$BRACE_HITS" ]; then
  ok "every control statement puts its opening brace on its own line"
else
  bad "$(printf '%s\n' "$BRACE_HITS" | wc -l) opening brace(s) share a line with a statement"
  printf '%s\n' "$BRACE_HITS" | head -10 | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
section "house style"
#
# The formatting ../tmd is written in -- indentation, braces, spacing, include
# order, guards, and the hand alignment of declarations and continuation
# lines. scripts/style.sh has the rules and why each is one; `make style`
# runs it alone.
if scripts/style.sh > "$WORK/style.log" 2>&1; then
  ok "every C file is in the house style"
else
  bad "$(wc -l < "$WORK/style.log" | tr -d ' ') house-style finding(s)"
  head -20 "$WORK/style.log" | sed 's/^/      /'
fi

# And the checker still checks. A sample with one violation of every rule,
# written fresh each time: a style check that has quietly stopped matching
# reports "clean" forever, and nothing else would notice.
STYLE_SAMPLE="$WORK/style-sample"
rm -rf "$STYLE_SAMPLE"
mkdir -p "$STYLE_SAMPLE"
printf '#ifndef WRONG_GUARD\n#define WRONG_GUARD\n#endif\n' > "$STYLE_SAMPLE/sample.h"
{
  printf '/* sample */\n'
  printf '#include <stdio.h>\n'
  printf '#include "sample.h"\n'
  printf '#include <string.h>\n'
  printf '#include <stdlib.h>\n'
  printf '\n'
  printf 'int f(int x);\n'
  printf '\n'
  printf 'int f(int x)\n'
  printf '{\n'
  printf '    char* p = NULL;\n'
  printf '    int a;\n'
  printf '    long b;\n'
  printf '\t(void)p;\n'
  printf '    a = 1;   \n'
  printf '\n'
  printf '\n'
  printf '    b = 2; // done\n'
  printf '    if(x)\n'
  printf '    {\n'
  printf '      a++;\n'
  printf '    }\n'
  printf '    else\n'
  printf '    {\n'
  printf '        b++;\n'
  printf '    }\n'
  printf '    switch (x)\n'
  printf '    {\n'
  printf '        case 1:\n'
  printf '        a = 2;\n'
  printf '        break;\n'
  printf '    }\n'
  printf '    return printf("%%d %%ld",\n'
  printf '        a, b);\n'
  printf '}\n'
  printf 'int g(void);\n'
  printf '\n'
} > "$STYLE_SAMPLE/sample.c"
scripts/style.sh "$STYLE_SAMPLE/sample.c" "$STYLE_SAMPLE/sample.h" > "$WORK/style-sample.log" 2>&1
missed=()
for rule in "own header" "includes out of order" "system and project headers" \
            "binds to the name" "do not line up" "a tab" "trailing whitespace" \
            "two blank lines" "// comment" "a space goes between" \
            "a block is indented" "else on a line of its own" \
            "column of their switch" "continuation line misaligned" \
            "no blank line after the function" "blank line at the end" \
            "include guard should be"; do
  grep -qF "$rule" "$WORK/style-sample.log" || missed+=("$rule")
done
if [ ${#missed[@]} -eq 0 ]; then
  ok "the style checker still catches every rule it claims to"
else
  bad "the style checker no longer catches: ${missed[*]}"
fi

# ---------------------------------------------------------------------------
section "American spelling"
#
# The house style is American English, in prose, comments, messages and the
# manpage alike. The list is of words this project is likely to use; it is
# matched as whole words, case-insensitively, so "licence" is caught and
# "license" is not. Two things are exempt: a proper noun keeps its own spelling,
# and quoted material keeps the spelling it was written in. Add an exemption
# for either by putting "spelling: ok" on the same line.
BRITISH='colours?|coloured|behaviours?|favourites?|honours?|labours?|neighbours?|licences?|initialis(e|ed|es|ing|ation)|organis(e|ed|es|ing|ation|ations)|recognis(e|ed|es|ing)|analys(e|ed|es|ing)|serialis(e|ed|es|ing|ation)|normalis(e|ed|es|ing|ation)|optimis(e|ed|es|ing|ation)|summaris(e|ed|es|ing)|prioritis(e|ed|es|ing)|customis(e|ed|es|ing|ation)|centre[sd]?|fibre|metres?|catalogue[sd]?|dialogue|judgement|travell(ed|ing|er|ers)|modell(ed|ing)|labell(ed|ing)|cancell(ed|ing)|defence|greys?|programme[sd]?|enquir(y|ies)|aluminium|artefacts?|whilst|amongst|cheque'
SPELL_FILES="$(find src include tests scripts .githooks .github man docs \
                    -type f \( -name '*.c' -o -name '*.h' -o -name '*.def' -o -name '*.sh' \
                    -o -name '*.yml' -o -name '*.8' -o -name '*.md' -o -path '.githooks/*' \) \
                    2>/dev/null; ls ./*.md Makefile .gitignore 2>/dev/null)"
# shellcheck disable=SC2086  # the file list is deliberately split
SPELL_HITS="$(grep -nEiw "$BRITISH" $SPELL_FILES 2>/dev/null | grep -v 'spelling: ok' \
              | grep -v "^scripts/lint.sh:" || true)"
if [ -z "$SPELL_HITS" ]; then
  ok "no British spellings"
else
  bad "$(printf '%s\n' "$SPELL_HITS" | wc -l | tr -d ' ') British spelling(s)"
  printf '%s\n' "$SPELL_HITS" | head -10 | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
section "copyright audit"
#
# Every source file carries the same notice, and this is what keeps that true.
# It is not bureaucracy: the license grant on a BSD-2 project is the file
# header, and a file that reaches somebody without one has no license at all.
# The owner and the SPDX identifier are matched exactly; the year is allowed to
# be a single year or a range, so bumping it does not mean touching every file.
EXPECTED_OWNER="Bryan C. Everly"
EXPECTED_SPDX="SPDX-License-Identifier: BSD-2-Clause"
COPYRIGHT_RE="Copyright \(c\) 20[0-9][0-9](-20[0-9][0-9])? $EXPECTED_OWNER"

missing=0
checked=0
while IFS= read -r file; do
  checked=$((checked + 1))
  head_text="$(head -12 "$file")"
  problem=""
  # Here-strings, not `printf | grep -q`: under pipefail that pipeline fails
  # whenever grep finds its match and exits before printf has finished writing,
  # and the audit then blamed a file that was perfectly fine -- at random.
  if ! grep -Eq "$COPYRIGHT_RE" <<< "$head_text"; then
    problem="no \"Copyright (c) <year> $EXPECTED_OWNER\" in the first 12 lines"
  elif ! grep -qF "$EXPECTED_SPDX" <<< "$head_text"; then
    problem="no \"$EXPECTED_SPDX\" in the first 12 lines"
  fi
  if [ -n "$problem" ]; then
    if [ "$missing" -eq 0 ]; then
      bad "files without the project copyright header"
    fi
    missing=$((missing + 1))
    note "$file: $problem"
  fi
done < <(
  {
    # Every file in the source directories, whatever its extension: a new
    # kind of file (a suppressions list, an awk program, a hook with no
    # extension at all) is source the moment it is added, and an extension
    # list would let it in without a header.
    find src include tests scripts .githooks -type f 2>/dev/null
    # And the code outside them: the build, the CI and the repository's own
    # configuration. Prose (the Markdown) and data (VERSION, the generated
    # badge) are not code and carry no header.
    find .github -type f \( -name '*.yml' -o -name '*.yaml' -o -name CODEOWNERS \)
    printf '%s\n' Makefile .editorconfig .gitignore
  } | sort
)

if [ "$missing" -eq 0 ]; then
  ok "$checked source files carry the copyright and SPDX header"
fi

# The notice in the code, the one the program prints, and the one in the
# packaging have to name the same person and the same license.
for file in LICENSE man/restate.8 include/restate.h; do
  [ -f "$file" ] || continue
  if ! grep -qF "$EXPECTED_OWNER" "$file"; then
    bad "$file does not name $EXPECTED_OWNER"
  fi
done

# The address a vulnerability report goes to has to be one, stated once.
if [ -f SECURITY.md ] && ! grep -qE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]+' SECURITY.md; then
  bad "SECURITY.md gives no address for reporting a vulnerability"
fi
if ! ./bin/restate --version 2>/dev/null | grep -qF "$EXPECTED_OWNER"; then
  if [ -x ./bin/restate ]; then
    bad "the binary's --version output does not carry the copyright"
  else
    note "./bin/restate is not built, so its --version was not checked"
  fi
else
  ok "LICENSE, the manpage, the header and --version all agree"
fi

# ---------------------------------------------------------------------------
section "shellcheck"
if command -v shellcheck > /dev/null 2>&1; then
  if shellcheck --severity=style scripts/*.sh tests/cli/*.sh .githooks/* \
       > "$WORK/shellcheck.log" 2>&1; then
    ok "every script is clean"
  else
    bad "shellcheck found something"
    head -40 "$WORK/shellcheck.log" | sed 's/^/      /'
  fi
else
  skip "shellcheck is not installed"
  note "sudo apt install shellcheck   (or: make install-dev)"
fi

# ---------------------------------------------------------------------------
section "actionlint"
# The workflows are code too, and a typo in one is found by GitHub only after
# the push -- or, for the release workflow, after the tag. actionlint also
# checks every run block with ShellCheck when it is installed.
if command -v actionlint > /dev/null 2>&1; then
  if actionlint > "$WORK/actionlint.log" 2>&1; then
    ok "every workflow is clean"
  else
    bad "actionlint found something"
    head -30 "$WORK/actionlint.log" | sed 's/^/      /'
  fi
else
  skip "actionlint is not installed"
  note "see scripts/install-dev.sh, which installs a pinned release"
fi

# ---------------------------------------------------------------------------
section "generated files are current"
if [ -x ./bin/restate ]; then
  if scripts/gen-man.sh --check ./bin/restate man/restate.8 > "$WORK/man.log" 2>&1; then
    ok "man/restate.8 matches the program's --help"
  else
    bad "man/restate.8 is out of date — run 'make man' and commit it"
    head -20 "$WORK/man.log" | sed 's/^/      /'
  fi

  # The README states the same option list a third time. Three copies of one
  # list is fine as long as two of them are generated and checked.
  if scripts/gen-readme-usage.sh --check ./bin/restate README.md \
       > "$WORK/readme.log" 2>&1; then
    ok "the README's Usage block matches the program's --help"
  else
    bad "the README's Usage block is out of date"
    sed 's/^/      /' "$WORK/readme.log"
  fi
else
  skip "./bin/restate is not built — run 'make build' before 'make lint'"
fi

# The version the binary reports has to be the one this tree should produce, or
# a release tag will name something that is not what was built. Compared against
# scripts/version.sh rather than against the VERSION file, because a working
# tree correctly reports "0.1.0.0-dev" and a released one reports "0.1.0.0".
if [ -x ./bin/restate ]; then
  expected="$(scripts/version.sh)"
  built="$(./bin/restate --version | head -1 | awk '{print $2}')"
  if [ "$built" = "$expected" ]; then
    case "$built" in
      *-dev) ok "the built binary reports $built (this tree is not the release)" ;;
      *)     ok "the built binary reports version $built" ;;
    esac
  else
    bad "./bin/restate reports $built but this tree should build $expected — run 'make build'"
  fi
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ ${#SKIPPED[@]} -gt 0 ]; then
  printf '  \033[93mSkipped:\033[0m %d tool(s) not installed\n' "${#SKIPPED[@]}"
fi
if [ ${#FAILURES[@]} -eq 0 ]; then
  printf '  \033[92m✓ lint is clean\033[0m\n\n'
  exit 0
fi
printf '  \033[91m✗ %d lint check(s) failed\033[0m\n\n' "${#FAILURES[@]}"
exit 1
