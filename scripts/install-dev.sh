#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Install everything `make test`, `make lint` and `make security` want, so that
# none of them has to skip a check.
#
#   make install-dev
#
# Every script in this project skips a tool it cannot find rather than failing,
# which is what makes them usable on a fresh checkout — and also what makes it
# possible to have a green local run that CI then fails, because CI has all of
# them. This closes that gap.
#
# Nothing here is required to *build* restate. A C compiler and GNU make are
# enough for that, deliberately: the list below is for developing it.
#
# apt is the full set, because Ubuntu is where CI runs every check. On the
# BSDs and macOS this installs what is needed to build and run the tests; the
# rest of the analyzers are best run on Linux, as CI does.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

# Pinned, because an unpinned scanner is a build that starts failing on a day
# nobody changed anything. CI installs the same version.
GITLEAKS_VERSION="8.21.2"
ACTIONLINT_VERSION="1.7.7"

bold()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
info()  { printf '  \033[96m→\033[0m %s\n' "$*"; }
ok()    { printf '  \033[92m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[93m!\033[0m %s\n' "$*"; }
die()   { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

bold "restate — development environment"

# ---------------------------------------------------------------------------
# The BSDs and macOS: the build and the tests
# ---------------------------------------------------------------------------
case "$(uname -s)" in
FreeBSD)
  bold "FreeBSD"
  sudo pkg install -y gmake bash shellcheck cppcheck || die "pkg install failed"
  ok "installed; build with: gmake build && gmake test-unit test-cli"
  exit 0
  ;;
OpenBSD)
  bold "OpenBSD"
  doas pkg_add -I gmake bash shellcheck cppcheck || die "pkg_add failed"
  ok "installed; build with: gmake build && gmake test-unit test-cli"
  exit 0
  ;;
NetBSD)
  bold "NetBSD"
  sudo pkgin -y install gmake bash shellcheck cppcheck || die "pkgin failed"
  ok "installed; build with: gmake build && gmake test-unit test-cli"
  exit 0
  ;;
Darwin)
  bold "macOS"
  command -v brew > /dev/null 2>&1 || die "Homebrew is needed: https://brew.sh"
  brew install make bash shellcheck cppcheck llvm actionlint gitleaks \
    || die "brew install failed"
  ok "installed; the Xcode command line tools provide the compiler"
  exit 0
  ;;
esac

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
if ! command -v apt-get > /dev/null 2>&1; then
  warn "This script installs with apt. On another Linux, the equivalents are:"
  printf '\n'
  printf '    build       gcc make\n'
  printf '    tests       valgrind\n'
  printf '    coverage    gcov (ships with gcc), gcovr for the XML report\n'
  printf '    lint        cppcheck clang-tidy shellcheck actionlint\n'
  printf '    security    clang-tools (scan-build) flawfinder semgrep gitleaks\n'
  printf '                hardening-check (devscripts)\n'
  printf '    fuzzing     clang compiler-rt llvm (llvm-symbolizer)\n\n'
  exit 0
fi

PACKAGES=(
  # --- build ---------------------------------------------------------------
  build-essential          # gcc, make, libc headers
  # --- tests ---------------------------------------------------------------
  valgrind                 # the uninitialized-read pass in make test-memory
  # --- coverage ------------------------------------------------------------
  gcovr                    # the XML and HTML reports CI keeps
  # --- the installer fetch tests -------------------------------------------
  # They sign a local mirror with a key of their own and fetch from it; without
  # these they are skipped, which is the right thing on a machine without them
  # and the wrong thing on a developer's.
  gnupg                    # gpg, to make the test key and sign the mirror
  gpgv
  # --- lint ----------------------------------------------------------------
  cppcheck
  clang-tidy
  clang-tools              # scan-build, for the clang static analyzer
  shellcheck
  # --- security ------------------------------------------------------------
  flawfinder
  devscripts               # hardening-check, which reads the built binary
  # --- the fuzzer's better engine ------------------------------------------
  clang                    # libFuzzer; the built-in mutator works without it
  # clang alone is not enough: -fsanitize=fuzzer links against compiler-rt,
  # and without this the build fails with "cannot find libclang_rt.fuzzer.a"
  # and scripts/fuzz.sh quietly falls back to the weaker built-in mutator.
  # Quietly is the problem -- it looks like a passing fuzz run either way.
  libclang-rt-dev
  # Without this a sanitizer crash reports hex offsets instead of a file and a
  # line, and every report has to be run back through addr2line by hand. It is
  # a separate package from clang, and easy not to notice is missing until the
  # first crash.
  llvm                     # llvm-symbolizer
  # --- what this script itself needs ---------------------------------------
  curl                     # fetching the pinned gitleaks and actionlint releases
  pipx                     # semgrep is Python, and apt has no current package
)

bold "System packages"
MISSING=()
for package in "${PACKAGES[@]}"; do
  if dpkg -s "$package" > /dev/null 2>&1; then
    continue
  fi
  MISSING+=("$package")
done

if [ ${#MISSING[@]} -eq 0 ]; then
  ok "every system package is already installed"
else
  info "installing: ${MISSING[*]}"
  sudo apt-get update -qq || die "apt-get update failed"
  sudo apt-get install -y -qq --no-install-recommends "${MISSING[@]}" \
    || die "apt-get install failed"
  ok "installed ${#MISSING[@]} package(s)"
fi

# ---------------------------------------------------------------------------
# gitleaks — a release binary, because the apt package lags well behind
# ---------------------------------------------------------------------------
bold "gitleaks"
if command -v gitleaks > /dev/null 2>&1; then
  ok "already installed ($(gitleaks version 2>/dev/null || echo 'version unknown'))"
else
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64)  GL_ARCH=x64 ;;
    aarch64) GL_ARCH=arm64 ;;
    *)       GL_ARCH="" ;;
  esac
  if [ -z "$GL_ARCH" ]; then
    warn "no gitleaks release for $ARCH — the secret scan will skip"
  else
    URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz"
    info "downloading gitleaks $GITLEAKS_VERSION"
    TMP_GL="$(mktemp -d)"
    if curl -sSfL "$URL" -o "$TMP_GL/gl.tar.gz" \
       && tar -xzf "$TMP_GL/gl.tar.gz" -C "$TMP_GL" gitleaks \
       && sudo install -m 0755 "$TMP_GL/gitleaks" /usr/local/bin/gitleaks; then
      ok "installed gitleaks $GITLEAKS_VERSION"
    else
      warn "could not install gitleaks — the secret scan will skip"
    fi
    rm -rf "$TMP_GL"
  fi
fi

# ---------------------------------------------------------------------------
# actionlint — the workflows are code too
# ---------------------------------------------------------------------------
bold "actionlint"
if command -v actionlint > /dev/null 2>&1; then
  ok "already installed ($(actionlint -version 2>/dev/null | head -1))"
else
  case "$(uname -m)" in
    x86_64)  AL_ARCH=amd64 ;;
    aarch64) AL_ARCH=arm64 ;;
    *)       AL_ARCH="" ;;
  esac
  if [ -z "$AL_ARCH" ]; then
    warn "no actionlint release for $(uname -m) — the workflow lint will skip"
  else
    URL="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_${AL_ARCH}.tar.gz"
    TMP_AL="$(mktemp -d)"
    info "downloading actionlint $ACTIONLINT_VERSION"
    if curl -sSfL "$URL" -o "$TMP_AL/al.tar.gz" \
       && tar -xzf "$TMP_AL/al.tar.gz" -C "$TMP_AL" actionlint \
       && sudo install -m 0755 "$TMP_AL/actionlint" /usr/local/bin/actionlint; then
      ok "installed actionlint $ACTIONLINT_VERSION"
    else
      warn "could not install actionlint — the workflow lint will skip"
    fi
    rm -rf "$TMP_AL"
  fi
fi

# ---------------------------------------------------------------------------
# semgrep — Python, so pipx rather than apt
# ---------------------------------------------------------------------------
bold "semgrep"
if command -v semgrep > /dev/null 2>&1; then
  ok "already installed"
elif command -v pipx > /dev/null 2>&1; then
  if pipx install semgrep > /dev/null 2>&1; then
    ok "installed with pipx"
  else
    warn "pipx install semgrep failed — that scan will skip"
  fi
else
  warn "pipx is not installed, so semgrep was not installed"
  info "sudo apt install pipx && pipx install semgrep"
fi

# ---------------------------------------------------------------------------
# The hooks
# ---------------------------------------------------------------------------
bold "Git hooks"
scripts/install-hooks.sh

# ---------------------------------------------------------------------------
bold "Ready"
printf '  \033[2mmake build     compile into ./bin\033[0m\n'
printf '  \033[2mmake test      unit + end-to-end tests, sanitizers, valgrind, 80%% coverage gate\033[0m\n'
printf '  \033[2mmake lint      the compiler, the analyzers and the house rules\033[0m\n'
printf '  \033[2mmake security  the security scanners, the sanitizers and a fuzz run\033[0m\n'
printf '  \033[2mmake install   install into /usr/local\033[0m\n\n'

