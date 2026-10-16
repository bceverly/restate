<!--
Copyright (c) 2026 Bryan C. Everly
SPDX-License-Identifier: BSD-2-Clause
-->

# Contributing

Thank you. A few things make a change easy to take.

## Set up once

```bash
make install-dev    # compilers, analyzers, valgrind, fuzzing tools, git hooks
```

The pre-commit hook runs `make lint` and refuses a commit if anything fails
*or is skipped* — a scanner that is not installed passes by doing nothing,
which proves nothing.

`make test`, `make lint` and `make security` each record, in `.passed/`, the
content they passed on — only when they pass with nothing skipped, and the
record is deleted when a run starts, so a failed run leaves none. Content, not
timestamps: touching a file changes nothing, editing one does. A check run by
hand therefore counts, and nothing that has passed on exactly these files is
run on them again:

- the pre-commit hook skips lint that has passed on them;
- `make check` runs whichever of test, lint and security has not;
- the pre-push hook runs nothing — GitHub drops a push whose hook runs for
  minutes — but refuses a commit whose files all three have not passed on.
  A commit made with the pre-commit hook bypassed, or a file edited after the
  checks, is caught before it leaves the machine.

The tests' record ignores the prose (`*.md`, `docs/`), which no test reads;
lint's and the security scan's cover everything. None of them counts the
version number, in `VERSION` and the manpage's `.TH` line, while the two
agree: `make release` writes the next one before it runs `make check`, so the
checks already passed on what is being released are not run again.

The hooks are copies in `.git/hooks/`, so a change to `.githooks/` does nothing
until `make install-hooks` runs again. `make check`, and so `make release`,
installs them first whenever they differ.

`RESTATE_SKIP_HOOK=1` bypasses either hook, for the rare honest reason.

## The bar

- `make lint` is clean: `-Werror` under every warning in the Makefile,
  `gcc -fanalyzer`, cppcheck, clang-tidy, shellcheck, actionlint, the brace
  style, American spelling, and the copyright header on every source file.
- `make test` passes: unit tests, end-to-end tests, the sanitizers, valgrind,
  and **at least 80% line coverage — overall and in every source file**. The
  gates can be raised, never lowered.
- `make security` is clean: the static analyzers, flawfinder, semgrep, a fuzz
  run, gitleaks and the Lucky 13. `make check` runs all three.
- New behavior comes with tests that exercise it, and a fixed bug with a test
  that fails without the fix: unit tests in `tests/test_*.c`, end-to-end
  checks of the command line in `tests/cli/run.sh`. Coverage that only rises
  because other code was deleted does not count.
- `make security` is clean.
- A new command or option is added to `src/commands.def` or `src/options.def`,
  and `make man` regenerates the manpage and the README's Usage block from it.
  Commit both.
- Anything that parses input is reachable from `tests/fuzz/fuzz_restate.c`.

## House style

The C is written in the style of [tmd](https://github.com/bceverly/tmd), and
`make style` (part of `make lint`, so the pre-commit hook runs it) checks it:

- Four spaces a level, never a tab. `case` and `default` sit at the column of
  their `switch`.
- The opening brace of a control statement goes on its own line, and every body
  is braced, even one line. `else` joins the brace before it: `} else`.
- `if (`, `for (`, `while (`, `switch (` — a space before the parenthesis.
- The `*` binds to the name: `char *p`.
- Local declarations line up by name, the `*` hanging to its left:

  ```c
  size_t        len;
  struct rs_buf b;
  char         *p;
  ```

- A wrapped line continues after its open parenthesis, under the string it
  continues, or with a ternary's `:` under its `?`:

  ```c
  (void)fprintf(out, "first part of a long message, "
                     "second part\n",
                count);
  ```

- Includes: the file's own header first, then system headers, then the
  project's, each group sorted.
- C comments only, never `//`. Comments say *why*; the code says what.
- No trailing spaces, no two blank lines in a row, a blank line after every
  function, one newline at the end of the file.
- No line-length limit: a long message is easier to find whole.
- American spelling.
- C11, POSIX.1-2008, and libc. No new dependencies.
- Every source file begins with:

  ```c
  /*
   * Copyright (c) 2026 Bryan C. Everly
   * SPDX-License-Identifier: BSD-2-Clause
   */
  ```

  and every script, Makefile, workflow and configuration file with the same
  two lines as `#` comments, in its first 12 lines. `make lint` checks every
  file under `src/`, `include/`, `tests/`, `scripts/` and `.githooks/`,
  whatever its extension, plus the Makefile, the `.github` YAML, `CODEOWNERS`,
  `.editorconfig` and `.gitignore`. Prose (the Markdown) and data (`VERSION`,
  the generated badge) carry no header.

By contributing you agree your contribution is licensed under the
[BSD 2-Clause License](LICENSE).
