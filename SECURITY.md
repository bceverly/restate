<!--
Copyright (c) 2026 Bryan C. Everly
SPDX-License-Identifier: BSD-2-Clause
-->

# Security Policy

## The threat model

`restate` is a system administration tool: a capture worth having reads every
file on the machine, so it runs as root. That shapes what matters.

- **It walks directories other people control.** Every user owns something
  under `/home`, and can change it while a scan is running. A scan must not be
  steerable — by swapping a directory for a symlink mid-walk, by nesting
  directories a million deep, by naming a file with quotes, tabs and newlines —
  into reading somewhere else, crashing, or writing a misleading index.
- **Its output is a map of the whole machine.** An image holds the machine's
  configuration and data and records who owns what. It must not be readable
  by anyone else, and must never be left half-written where a good one was.
- **Its input may come from anywhere.** An image or index read back by `diff`
  or `verify` may have come off a dead machine or a USB stick. Every byte of
  it is untrusted: the JSON parser, the tar reader, the timestamp and base64
  decoders are all memory-safety-critical, and none of them may accept a path
  that points outside the tree it describes.

## What is done about it

| | |
|---|---|
| The walk cannot be redirected | every directory and file is opened relative to its parent's descriptor with `O_NOFOLLOW`, and checked against what was stat'ed a moment earlier; a symlink is recorded, never followed |
| Recursion is bounded | a tree deeper than 1000 levels is reported as incomplete, not walked until the stack runs out |
| Output is private and atomic | images and indexes are created `0600` beside their destination and renamed into place only when complete; a symlink planted at the output path is replaced, not written through |
| Input is distrusted | the JSON parser rejects duplicate keys, fractions, unpaired surrogates and NUL, and limits nesting; the tar reader checks every header checksum and bounds every size before allocating; every path must be clean and absolute — no `..`, no `.`, no empty component |
| Integers never wrap | every number is parsed with an overflow check, and every count-times-size allocation goes through a checked helper |
| No shell, no `PATH` | restate runs three programs — `gzip`, `curl` and `gpgv` — all from one file (`src/run.c`), each from a fixed absolute path (`/usr/bin`, then `/usr/local/bin` for curl and gpgv, then `/bin`), with `posix_spawn` and an environment of `PATH`, `LC_ALL` and the proxy variables only — a `PATH` reaching a user-writable directory would otherwise hand that user root |
| Downloads are verified, not trusted | restate opens no connection itself. `restate installer fetch` has curl download over HTTPS only (redirects included, `~/.curlrc` ignored); the vendor's `SHA256SUMS` must carry a signature that gpgv attributes to the vendor key built into restate and pinned by fingerprint, and the image must match it before it is moved into place |
| SHA-256, not MD5 | an MD5 collision can be manufactured, so a planted file could compare equal to the original |
| It links nothing but libc | there is no dependency to have a CVE; gzip, curl and gpgv run as separate processes, outside restate's address space |
| The binary is hardened | PIE, stack protector, `_FORTIFY_SOURCE=3`, stack-clash protection, CET, full RELRO, BIND_NOW, zero-initialized automatic variables — and `make security` checks the *binary*, not the flags |
| Every push runs the sanitizers | AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer and valgrind (with descriptor tracking), over both test suites and a corpus of malformed images, indexes and rules files |
| Every push runs a fuzzer | libFuzzer over the JSON, tar, rules, pattern, timestamp and base64 parsers, with round-trip invariants; fifteen minutes on the weekly schedule |
| Every push runs the static analyzers | `gcc -fanalyzer`, cppcheck with the CERT C rules, clang-tidy, the clang static analyzer, flawfinder, semgrep, CodeQL `security-extended`, and gitleaks over the history |
| MITRE's "Lucky 13" | each of the thirteen unforgivable vulnerability classes is tested or ruled out with a reason, by `make lucky13` |

`make security` runs all of that locally except CodeQL and the Scorecard. A
clean local run and a clean CI run mean the same thing, on purpose.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private reporting — **Security → Report a vulnerability** on
https://github.com/bceverly/restate — or email **bryan@theeverlys.com**.

Helpful, in rough order of how much it helps:

1. The input that triggers it: the image, index or rules file, or the shape of
   the directory tree. A fuzzer's raw input — `.fuzz/crash.bin` or a file
   under `.fuzz/findings/` — is exactly what is wanted, however malformed.
2. The command line and the `restate --version` output.
3. What you saw — a sanitizer report, a core dump, a hang, a file read or
   written that should not have been.

An index or image describes the machine it came from. If yours cannot be
shared, a description of the tree that reproduces the problem is enough.

### What to expect

- An acknowledgement within a few days.
- An assessment of whether it is exploitable and how, shared with you.
- A fix and a released version, with credit in the release notes unless you
  would rather not have it.

This is a small tool maintained by one person; there is no bounty and no formal
SLA. What there is, is a reply.

## Supported versions

The most recent release. A fix means a new version rather than a backport.

## Scope

In scope: anything that makes restate crash, hang, allocate without bound,
read or write outside its allocations, follow a link it should not, read or
write outside the tree it was given, leave an image readable by others, or
record something as fact that the filesystem does not say.

Out of scope: the *contents* of the files restate keeps. It records and stores
what is on the machine; deciding whether that content is trustworthy is the
administrator's business.
