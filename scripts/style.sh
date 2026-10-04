#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# The house style for C, checked.
#
#   scripts/style.sh                  every C file in the project
#   scripts/style.sh FILE...          just these
#
# The style is the one ../tmd is written in, and these rules were taken from
# that code by measuring it -- each is one tmd keeps in practically every
# instance, not a preference written down first and imposed after:
#
#   braces       a control statement's opening brace on its own line; else
#                joined to the closing brace before it ("} else", "} else if")
#   indentation  four spaces a level, never a tab; case and default at the
#                column of their switch
#   spacing      if/for/while/switch followed by a space; no trailing spaces;
#                no two blank lines in a row; one newline at the end; a blank
#                line after every function
#   pointers     the '*' binds to the name: "char *p", never "char* p"
#   comments     C comments only, never "//"
#   includes     a file's own header first; then the system headers, then the
#                project's, each group sorted
#   guards       a header's include guard is RESTATE_<NAME>_H
#   alignment    the names in a run of local declarations line up, a pointer's
#                '*' hanging to their left (a static table is exempt, and a
#                blank line or comment starts a new run); a continuation line
#                lines up after
#                its open parenthesis, under the string it continues, or -- for
#                a wrapped ternary -- its ':' under the '?'
#
# What is deliberately NOT a rule, because tmd does not keep it either: a line
# length limit. Help text and diagnostics run long, and splitting a message
# mid-sentence to satisfy a counter makes it harder to find with grep.
#
# Not clang-format, for the reason tmd gives: clang-format cannot be asked for
# these rules alone. It reformats everything, and the code here is full of
# alignment and comment wrapping done by hand that is meant to stay. This
# checks; it never rewrites.
#
# Plain POSIX awk, so it runs everywhere the build does.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

GUARD_PREFIX="${STYLE_GUARD_PREFIX:-RESTATE}"

if [ $# -gt 0 ]; then
  FILES=("$@")
else
  FILES=()
  while IFS= read -r f; do
    FILES+=("$f")
  done < <(find src include tests -type f \( -name '*.c' -o -name '*.h' \) | sort)
fi

status=0
for f in "${FILES[@]}"; do
  # awk cannot see whether the last line ended in a newline.
  if [ -s "$f" ] && [ "$(tail -c 1 "$f" | od -An -c | tr -d ' ')" != '\n' ]; then
    printf '%s: no newline at the end of the file\n' "$f"
    status=1
  fi
done

awk -v guard_prefix="$GUARD_PREFIX" '
# Every finding is "file:line: what is wrong". The file and line are kept in
# variables rather than read from FILENAME and FNR, because some findings are
# only known later -- a misaligned declaration when its run ends, an include
# out of order when the last include has been seen.
function report_at(line, msg) {
  printf "%s:%d: %s\n", fname, line, msg
  bad = 1
}

function report(msg) {
  report_at(FNR, msg)
}

function indent_of(s) {
  match(s, /^ */)
  return RLENGTH
}

# The line with string and character literals blanked to the same length --
# so columns still line up -- and comments removed. strstart[] records the
# 0-based column of each string literal that begins on the line.
function code_of(s,    out, i, n, ch, nxt, q) {
  out = ""
  nstr = 0
  n = length(s)
  i = 1
  while (i <= n) {
    ch = substr(s, i, 1)
    nxt = substr(s, i + 1, 1)
    if (in_comment) {
      if (ch == "*" && nxt == "/") {
        in_comment = 0
        out = out "  "
        i += 2
      } else {
        out = out " "
        i++
      }
      continue
    }
    if (ch == "/" && nxt == "*") {
      in_comment = 1
      out = out "  "
      i += 2
      continue
    }
    if (ch == "\"" || ch == "\047") {
      q = ch
      if (ch == "\"") {
        strstart[++nstr] = i - 1
      }
      out = out q
      i++
      while (i <= n) {
        ch = substr(s, i, 1)
        if (ch == "\\") {
          out = out "xx"
          i += 2
          continue
        }
        if (ch == q) {
          break
        }
        out = out "x"
        i++
      }
      if (i <= n) {
        out = out q
        i++
      }
      continue
    }
    out = out ch
    i++
  }
  return out
}

function check_includes(    k, g, kind, first_kind, prev, own, sys_seen, base) {
  if (ninc == 0) {
    return
  }
  base = fname
  sub(/.*\//, "", base)
  own = base
  sub(/\.c$/, ".h", own)
  if (base ~ /\.c$/ && own_exists) {
    if (inc[1] != "\"" own "\"") {
      report_at(incline[1], "the file'\''s own header, \"" own "\", has to be included first")
    }
  }
  sys_seen = 0
  for (k = 1; k <= ninc; k++) {
    kind = (substr(inc[k], 1, 1) == "<") ? "sys" : "loc"
    if (k > 1 && incgroup[k] == incgroup[k - 1]) {
      if (kind != prevkind) {
        report_at(incline[k], "system and project headers in one group; separate them with a blank line")
      } else if (inc[k] < inc[k - 1]) {
        report_at(incline[k], "includes out of order: " inc[k] " belongs before " inc[k - 1])
      }
    } else if (k > 2 && kind == "sys" && prevkind == "loc") {
      # A new group of system headers straight after project headers. The
      # one header a file leads with -- its own, or the one it is about --
      # comes before them; and a second group of system headers, under an
      # #if, after the first is in order.
      report_at(incline[k], "system headers go before the project'\''s own")
    }
    prevkind = kind
  }
}

function end_of_file() {
  flush_decls()
  if (prev_raw == "" && nlines > 0) {
    report_at(nlines, "blank line at the end of the file")
  }
  if (is_header && !saw_guard) {
    report_at(1, "no include guard (#ifndef " want_guard ")")
  }
  check_includes()
}

function start_file(    base, h) {
  fname = FILENAME
  in_comment = 0
  prev_raw = "x"
  prev_code = ""
  prev_sig = ""
  prev_sig_indent = -1
  prev_case_indent = -1
  depth = 0
  nsw = 0
  ninc = 0
  group = 1
  saw_guard = 0
  decl_n = 0
  pending_cont = 0
  nlines = 0
  base = fname
  sub(/.*\//, "", base)
  is_header = (base ~ /\.h$/)
  if (base == "restate.h") {
    want_guard = guard_prefix "_H"
  } else {
    h = base
    sub(/\.h$/, "", h)
    want_guard = guard_prefix "_" toupper(h) "_H"
  }
  # Whether this .c file has a header of its own, beside it.
  own_exists = 0
  if (fname ~ /\.c$/) {
    h = fname
    sub(/\.c$/, ".h", h)
    own_exists = ((getline junk < h) >= 0)
    close(h)
  }
}

# The alignment of a run of local declarations, checked when the run ends.
function flush_decls(    k, col) {
  if (decl_n >= 2) {
    col = decl_col[1]
    for (k = 2; k <= decl_n; k++) {
      if (decl_col[k] != col) {
        report_at(decl_line[k], "declaration names do not line up with the line above (\"*\" hangs left of the name)")
        break
      }
    }
  }
  decl_n = 0
}

FNR == 1 {
  if (fname != "") {
    end_of_file()
  }
  start_file()
}

{
  raw = $0
  nlines = FNR
  was_comment = in_comment
  code = code_of(raw)
  stripped = code
  sub(/^ +/, "", stripped)
  sub(/ +$/, "", stripped)
  ind = indent_of(raw)

  # --- whitespace -----------------------------------------------------------
  if (index(raw, "\t")) {
    report("a tab; indent with spaces")
  }
  if (raw ~ /[ \t]+$/) {
    report("trailing whitespace")
  }
  if (raw == "" && prev_raw == "") {
    report("two blank lines in a row")
  }

  # --- comments, guards, includes -------------------------------------------
  if (code ~ /\/\//) {
    report("a // comment; use /* */")
  }
  if (is_header && !saw_guard && raw ~ /^#ifndef /) {
    saw_guard = 1
    if (raw != "#ifndef " want_guard) {
      report("the include guard should be " want_guard)
    }
  }
  if (raw ~ /^#include /) {
    ninc++
    inc[ninc] = raw
    sub(/^#include +/, "", inc[ninc])
    sub(/ .*/, "", inc[ninc])
    incline[ninc] = FNR
    incgroup[ninc] = group
  } else if (ninc > 0 && raw !~ /^#include/) {
    group++
  }

  # --- a blank line after every function ------------------------------------
  if (prev_raw == "}" && raw != "" && raw !~ /^#/) {
    report("no blank line after the function above")
  }

  if (stripped == "" || raw ~ /^ *#/) {
    # A blank line, a comment or a directive ends a run of declarations: the
    # groups on either side of one are aligned separately.
    flush_decls()
    if (raw == "" || raw ~ /^ *#/) {
      pending_cont = 0
    }
    prev_raw = raw
    next
  }

  # --- keywords and pointers -------------------------------------------------
  if (code ~ /(^|[^A-Za-z0-9_])(if|for|while|switch)\(/) {
    report("a space goes between the keyword and its parenthesis")
  }
  if (code ~ /^ *else([^A-Za-z0-9_]|$)/) {
    report("else on a line of its own; join it to the closing brace: \"} else\"")
  }
  if (code ~ /[A-Za-z0-9_]\* +[A-Za-z_(]/) {
    report("the \"*\" binds to the name: \"type *name\", not \"type* name\"")
  }

  # --- continuation lines ------------------------------------------------------
  if (pending_cont && !was_comment) {
    ok = 0
    for (k in allowed) {
      if (ind == allowed[k] + 0) {
        ok = 1
      }
    }
    if (!ok && substr(stripped, 1, 1) != "{") {
      report("continuation line misaligned: start it at column " (want_paren + 1) " (after the open parenthesis)" )
    }
  }
  pending_cont = 0
  split("", allowed)
  if (raw !~ /\\$/) {
    nopen = 0
    for (k = 1; k <= length(code); k++) {
      ch = substr(code, k, 1)
      if (ch == "(") {
        open_at[++nopen] = k
      } else if (ch == ")" && nopen > 0) {
        nopen--
      }
    }
    if (nopen > 0 && stripped !~ /[{(]$/) {
      pending_cont = 1
      want_paren = open_at[nopen]
      allowed[1] = want_paren
      for (k = 1; k <= nstr; k++) {
        allowed[k + 1] = strstart[k]
      }
      q = 0
      for (k = 1; k <= length(code); k++) {
        if (substr(code, k, 1) == "?") {
          q = k - 1
        }
      }
      if (q > 0) {
        allowed[nstr + 2] = q
      }
    }
  }

  # --- block indentation ---------------------------------------------------------
  if (prev_sig == "{" && !was_comment) {
    if (stripped == "}") {
      if (ind != prev_sig_indent) {
        report("closing brace not at the column of its opening brace")
      }
    } else if (ind != prev_sig_indent + 4 &&
               !(ind == prev_sig_indent && stripped ~ /^(case |default)/)) {
      # A switch body is the exception: its cases sit at the column of the brace.
      report("a block is indented four spaces from its brace")
    }
  }
  if (prev_case_indent >= 0 && !was_comment) {
    if (!(ind == prev_case_indent + 4 || (ind == prev_case_indent && stripped ~ /^(case |default|\{)/))) {
      report("a case body is indented four spaces from its case")
    }
  }

  # --- switch and case -----------------------------------------------------------
  if (code ~ /^ *switch \(/) {
    sw_indent[++nsw] = ind
    sw_depth[nsw] = depth
  }
  if (code ~ /^ *(case [^:]*|default *):/ && nsw > 0) {
    if (ind != sw_indent[nsw]) {
      report("case and default go at the column of their switch")
    }
  }
  prev_case_indent = (code ~ /^ *(case [^:]*|default *): *$/) ? ind : -1

  # --- local declarations ----------------------------------------------------------
  decl = stripped
  if (ind > 0 && decl ~ /^((const|unsigned|signed|volatile|long|short) )*((struct|enum|union) )?[A-Za-z_][A-Za-z0-9_]*( (const|long|int|char))* +\**[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])*( = .*)?;$/ \
      && decl !~ /^(return|goto|case|else|break|continue|do|sizeof|typedef|static) /) {
    head = code
    sub(/ +$/, "", head)
    sub(/ = .*/, "", head)
    sub(/;$/, "", head)
    sub(/\[.*$/, "", head)
    match(head, /[A-Za-z_][A-Za-z0-9_]*$/)
    col = RSTART
    if (decl_n > 0 && ind != decl_ind) {
      flush_decls()
    }
    decl_ind = ind
    decl_n++
    decl_col[decl_n] = col
    decl_line[decl_n] = FNR
  } else {
    flush_decls()
  }

  # --- brace depth, for closing a switch -------------------------------------------
  for (k = 1; k <= length(code); k++) {
    ch = substr(code, k, 1)
    if (ch == "{") {
      depth++
    } else if (ch == "}") {
      depth--
      while (nsw > 0 && depth <= sw_depth[nsw]) {
        nsw--
      }
    }
  }

  prev_sig = stripped
  prev_sig_indent = ind
  prev_raw = raw
}

END {
  if (fname != "") {
    end_of_file()
  }
  exit bad
}
' "${FILES[@]}" || status=1

exit "$status"
