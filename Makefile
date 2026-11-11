# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# =============================================================================
# restate — back up what a fresh OS install would not put back, to rebuild the machine
#
# Run `make` with no arguments for the list of targets.
#
# This is GNU make. On the BSDs it is `gmake`, installed from packages; the
# README's "Building" section has the one-line install for each system.
# =============================================================================

# /bin/sh and POSIX flags, not bash: OpenBSD keeps bash in /usr/local/bin and
# its sh has no pipefail. The scripts carry their own `#!/usr/bin/env bash`.
SHELL       := /bin/sh
.SHELLFLAGS := -eu -c

# BASE_VERSION is the VERSION file: what the manpage and the release tag use.
# VERSION is what is compiled into the binary, and gains "-dev" whenever this
# tree is not exactly the tagged release -- see scripts/version.sh. A bug
# report saying "0.1.0.0" names a build somebody else can download; one saying
# "0.1.0.0-dev" names a build only its author has.
BASE_VERSION := $(shell cat VERSION)
VERSION     := $(shell scripts/version.sh)
PROG        := restate

BIN_DIR     := bin
OBJ_DIR     := obj
COV_DIR     := .coverage
MAN_PAGE    := man/$(PROG).8

SRC         := $(wildcard src/*.c)
TEST_SRC    := $(wildcard tests/*.c)
# Everything except main.c: the unit tests link the program's own objects and
# bring their own entry point.
LIB_SRC     := $(filter-out src/main.c,$(SRC))

# restate-proxy: restate's library code and proxy/, linked with a TLS library.
# restate itself never is -- it links the C library and nothing else, which
# `make security` checks -- so nothing below is part of `make build`, and a
# machine without OpenSSL's headers builds and tests restate as before.
PROXY          := restate-proxy
PROXY_SRC      := $(wildcard proxy/*.c)
PROXY_LIB_SRC  := $(filter-out proxy/main.c,$(PROXY_SRC))
PROXY_TEST_SRC := $(wildcard tests/proxy/*.c)

# Asked of scripts/tls.sh only by a target that uses them, and once: each
# replaces itself with its answer the first time it is expanded.
TLS_CFLAGS   = $(eval TLS_CFLAGS := $$(shell scripts/tls.sh --cflags))$(TLS_CFLAGS)
TLS_LIBS     = $(eval TLS_LIBS := $$(shell scripts/tls.sh --libs))$(TLS_LIBS)
TLS_NAME     = $(eval TLS_NAME := $$(shell scripts/tls.sh --name))$(TLS_NAME)
PROXY_OK     = $(eval PROXY_OK := $$(shell scripts/tls.sh --check && echo yes))$(PROXY_OK)

# Where the TLS library is missing, the proxy is passed over and said to be
# -- unless RS_REQUIRE_PROXY is set, as CI sets it, where that is a failure:
# CI installs the headers, so a skip there is a broken install.
PROXY_MISSING = $(if $(RS_REQUIRE_PROXY),{ echo "restate-proxy: $(TLS_NAME) is not installed; RS_REQUIRE_PROXY is set" >&2; exit 1; },printf '  \033[93m-\033[0m restate-proxy passed over: %s is not installed (make install-dev)\n' '$(TLS_NAME)')

# -----------------------------------------------------------------------------
# Flags
#
# CC, CFLAGS, CPPFLAGS and LDFLAGS are left to the caller, because a
# distribution build passes its own and a package that ignores them ships
# without the hardening the distribution promises. Everything this project
# insists on goes in RS_* and is appended, so both survive.
# -----------------------------------------------------------------------------
CC          ?= cc
CFLAGS      ?= -O2 -g

RS_STD      := -std=c11

# Feature-test macros differ per platform; scripts/features.sh is the one
# answer every build in this project (lint, coverage, memcheck, fuzz) shares.
RS_FEATURES := $(shell scripts/features.sh)

RS_CPPFLAGS := -Iinclude -Isrc $(RS_FEATURES) \
               -DRESTATE_VERSION='"$(VERSION)"'

# The warnings the code is clean under, on in every build rather than in a
# "strict" mode nobody runs.
RS_WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion \
               -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Wformat-nonliteral \
               -Wcast-qual -Wwrite-strings -Wpointer-arith -Wundef -Wvla

# The tests build structures by hand from string literals, which is exactly what
# -Wwrite-strings and -Wcast-qual exist to stop in real code.
TEST_WARNINGS := $(filter-out -Wcast-qual -Wwrite-strings -Wconversion -Wsign-conversion,$(RS_WARNINGS))

# -Werror is NOT on by default: a newer compiler inventing a new warning must
# not stop somebody building from source. `make lint` and CI turn it on, which
# is where a new warning should fail.
WERROR      ?=

# Hardening, each optional flag probed rather than assumed. The probe compiles
# a real translation unit with -Werror: clang accepts some flags it cannot honor
# on a target (-fstack-clash-protection on arm64 macOS) and only says so in a
# warning, and rejects others (-fcf-protection there) only at code generation.
cc_supports = $(shell printf 'int main(void){return 0;}' \
                | $(CC) $(1) -Werror -x c - -c -o /dev/null > /dev/null 2>&1 && echo yes)

RS_HARDEN   := -fstack-protector-strong -fno-common -fPIE
RS_HARDEN   += $(if $(call cc_supports,-fstack-clash-protection),-fstack-clash-protection)
RS_HARDEN   += $(if $(call cc_supports,-fcf-protection=full),-fcf-protection=full)
RS_HARDEN   += $(if $(call cc_supports,-ftrivial-auto-var-init=zero),-ftrivial-auto-var-init=zero)

# _FORTIFY_SOURCE: 3 where the toolchain supports it, 2 where it does not.
# Probed by compiling something that includes a header, because glibc's
# complaint about an unsupported level comes from features.h.
FORTIFY_LEVEL := $(if $(shell printf '\043include <string.h>\nint main(void){return 0;}\n' \
                        | $(CC) -O2 -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
                                -x c - -o /dev/null > /dev/null 2>&1 && echo yes),3,2)

# _FORTIFY_SOURCE needs optimization to do anything at all.
ifeq (,$(findstring -O0,$(CFLAGS)))
RS_HARDEN   += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$(FORTIFY_LEVEL)
endif

# The linker half. -z relro/now/noexecstack are ELF concepts, and Apple's linker
# rejects -z outright, so one probe decides the group.
ELF_LDHARDEN := $(shell printf 'int main(void){return 0;}' \
                  | $(CC) -Wl,-z,relro -x c - -o /dev/null > /dev/null 2>&1 \
                  && echo yes)
ifeq ($(ELF_LDHARDEN),yes)
RS_LDHARDEN := -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
else
# macOS builds PIE by default and has no equivalent knobs; `make security`
# reads the binary rather than trusting the flags either way.
RS_LDHARDEN :=
endif

ALL_CFLAGS    = $(RS_STD) $(RS_WARNINGS) $(WERROR) $(RS_HARDEN) $(CFLAGS)
ALL_TESTFLAGS = $(RS_STD) $(TEST_WARNINGS) $(WERROR) $(RS_HARDEN) $(CFLAGS)
ALL_CPPFLAGS  = $(RS_CPPFLAGS) $(CPPFLAGS) -Itests
ALL_LDFLAGS   = $(RS_LDHARDEN) $(LDFLAGS)

# Installation paths, overridable the way every package build expects.
#
# /usr/local, not /usr: /usr belongs to the distribution's package manager, and
# a file written there by hand is one the eventual package would fight with.
#
# sbin and section 8, because restate is a system administration tool: a scan
# worth having reads every file on the machine, which means running as root.
prefix      ?= /usr/local
exec_prefix ?= $(prefix)
sbindir     ?= $(exec_prefix)/sbin
datarootdir ?= $(prefix)/share
mandir      ?= $(datarootdir)/man
sysconfdir  ?= /etc
DESTDIR     ?=
INSTALL     ?= install

export prefix exec_prefix sbindir mandir DESTDIR PROG MAN_PAGE

.DEFAULT_GOAL := help

# -----------------------------------------------------------------------------
# Help -- `make` with no target prints this. Targets document themselves with a
# `## description` comment and group under `##@ Section` headers, so the list
# cannot drift from the targets that exist.
# -----------------------------------------------------------------------------
.PHONY: help
help:
	@printf '\n  \033[1;97mrestate\033[0m \033[2m%s\033[0m — back up what a fresh OS install would not put back, to rebuild the machine\n' '$(VERSION)'
	@printf '  \033[2mUsage: make <target>\033[0m\n'
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n  \033[1;94m%s\033[0m\n", substr($$0, 5); next } \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "    \033[96m%-16s\033[0m %s\n", $$1, $$2 } \
	' $(MAKEFILE_LIST)
	@printf '\n  \033[2mFirst time? Run: make install-dev && make build && make test\033[0m\n\n'

##@ Build

.PHONY: build
build: $(BIN_DIR)/$(PROG) $(MAN_PAGE) ## Compile the program into ./bin, regenerating the manpage

$(BIN_DIR)/$(PROG): $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRC)) | $(BIN_DIR)
	@$(CC) $(ALL_CFLAGS) -o $@ $^ $(ALL_LDFLAGS)
	@printf '  \033[92m✓\033[0m %s (%s)\n' "$@" "$(VERSION)"

# A stamp that changes only when the version string does, so a binary built
# with a different -DRESTATE_VERSION is rebuilt. FORCE makes the recipe run
# every time; it rewrites the file only when the content differs, so the mtime
# moves exactly when a rebuild is needed.
.PHONY: FORCE
FORCE:

$(OBJ_DIR)/version.stamp: FORCE | $(OBJ_DIR)
	@printf '%s' '$(VERSION)' | cmp -s - $@ 2>/dev/null \
	  || printf '%s' '$(VERSION)' > $@

$(OBJ_DIR)/%.o: src/%.c $(OBJ_DIR)/version.stamp | $(OBJ_DIR)
	@$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -MMD -MP -c $< -o $@

$(BIN_DIR) $(OBJ_DIR) $(OBJ_DIR)/proxy $(COV_DIR):
	@mkdir -p $@

.PHONY: proxy
proxy: $(BIN_DIR)/$(PROXY) ## Compile restate-proxy into ./bin (needs OpenSSL 3, or libtls on OpenBSD)

$(BIN_DIR)/$(PROXY): $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(LIB_SRC)) \
                     $(patsubst proxy/%.c,$(OBJ_DIR)/proxy/%.o,$(PROXY_SRC)) | $(BIN_DIR)
	@$(CC) $(ALL_CFLAGS) -o $@ $^ $(ALL_LDFLAGS) $(TLS_LIBS)
	@printf '  \033[92m✓\033[0m %s (%s, %s)\n' "$@" "$(VERSION)" "$(TLS_NAME)"

# tls-check first, so that a missing library is said to be missing once, in
# words, and not as a compiler's "No such file" for every object.
$(OBJ_DIR)/proxy/%.o: proxy/%.c $(OBJ_DIR)/version.stamp | $(OBJ_DIR)/proxy tls-check
	@$(CC) $(ALL_CPPFLAGS) -Iproxy $(TLS_CFLAGS) $(ALL_CFLAGS) -MMD -MP -c $< -o $@

.PHONY: tls-check
tls-check:
	@$(if $(PROXY_OK),:,{ echo "restate-proxy needs $(TLS_NAME)'s headers and library: make install-dev" >&2; exit 1; })

# The manpage is generated from the program's own --help, so it depends on the
# binary that prints it and the tables that binary was built from.
$(MAN_PAGE): $(BIN_DIR)/$(PROG) src/options.def src/commands.def scripts/gen-man.sh VERSION
	@scripts/gen-man.sh $(BIN_DIR)/$(PROG) $@

-include $(wildcard $(OBJ_DIR)/*.d $(OBJ_DIR)/proxy/*.d)

.PHONY: debug
debug: ## Rebuild unoptimized with symbols, for a debugger
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory build CFLAGS="-O0 -g3 -fno-omit-frame-pointer"

.PHONY: run
run: build ## Build, then scan this source tree and classify a few paths
	@./$(BIN_DIR)/$(PROG) scan --root=. --no-default-rules
	@./$(BIN_DIR)/$(PROG) classify /etc/passwd /var/cache/apt /usr/bin/ls /usr/local/bin /tmp

##@ Test

# Through scripts/passed.sh, as lint and security are: it records that they
# passed, on what, so the git hooks and `make check` need not run them again.
.PHONY: test
test: ## Unit + CLI tests, sanitizers, valgrind, and the 80% coverage gate
	@scripts/passed.sh test $(MAKE) --no-print-directory test-unit test-cli test-memory coverage

.PHONY: test-unit
test-unit: $(BIN_DIR)/unittests ## Run the C unit tests (restate-proxy's too, where it can be built)
	@./$(BIN_DIR)/unittests

# The stamp is a real prerequisite, so a version change rebuilds the tests
# too, but it must not reach the linker as an input file. proxy/ and
# tests/proxy/ are compiled in only where the TLS library is there.
$(BIN_DIR)/unittests: $(LIB_SRC) $(TEST_SRC) $(PROXY_LIB_SRC) $(PROXY_TEST_SRC) \
                      $(wildcard src/*.h tests/*.h proxy/*.h) $(OBJ_DIR)/version.stamp | $(BIN_DIR)
	@$(if $(PROXY_OK),:,$(PROXY_MISSING))
	@$(CC) $(ALL_CPPFLAGS) $(ALL_TESTFLAGS) \
	       $(if $(PROXY_OK),-DRS_WITH_PROXY -Iproxy $(TLS_CFLAGS)) -o $@ \
	       $(LIB_SRC) $(TEST_SRC) $(if $(PROXY_OK),$(PROXY_LIB_SRC) $(PROXY_TEST_SRC)) \
	       $(ALL_LDFLAGS) $(if $(PROXY_OK),$(TLS_LIBS))

.PHONY: test-cli
test-cli: build ## Run the end-to-end tests against the built binaries
	@tests/cli/run.sh ./$(BIN_DIR)/$(PROG)
	@$(if $(PROXY_OK),$(MAKE) --no-print-directory proxy && tests/cli/proxy.sh ./$(BIN_DIR)/$(PROXY),$(PROXY_MISSING))

# The repository on other storage: a share, a USB disk, anything mounted.
.PHONY: test-share
test-share: build ## Use a repository on SHARE=DIR (exFAT, SMB, NFS...) and read it back bit for bit
	@test -n "$(SHARE)" || { echo "make test-share SHARE=DIR" >&2; exit 2; }
	@tests/cli/share.sh ./$(BIN_DIR)/$(PROG) "$(SHARE)"

.PHONY: test-memory
test-memory: ## Run everything again under ASan, UBSan, LSan and valgrind
	@scripts/memcheck.sh

.PHONY: coverage
coverage: ## Measure line coverage, refresh the badge, fail below 80% overall or in any file
	@scripts/coverage.sh

.PHONY: check
check: ## Lint, test and security, each unless it has passed on this content; what a push needs
	@scripts/check.sh

.PHONY: fuzz
fuzz: ## Fuzz the manifest, rules and pattern parsers (FUZZ_SECONDS=30 by default)
	@scripts/fuzz.sh

##@ Quality

.PHONY: lint
lint: build ## Compiler, analyzers, house style, copyright audit, generated-file checks
	@$(if $(PROXY_OK),$(MAKE) --no-print-directory proxy,$(PROXY_MISSING))
	@scripts/passed.sh lint scripts/lint.sh

.PHONY: style
style: ## Check the C files against the house style (part of make lint)
	@scripts/style.sh

.PHONY: security
security: build ## Run the same security scanners CI runs, locally
	@scripts/passed.sh security scripts/security.sh

.PHONY: lucky13
lucky13: build ## Check MITRE's "Lucky 13" unforgivable vulnerabilities, one by one
	@scripts/lucky13.sh

.PHONY: man
man: docs ## Force the manpage to be regenerated from --help

.PHONY: docs
docs: $(BIN_DIR)/$(PROG) ## Regenerate the manpage and the README's Usage block
	@scripts/gen-man.sh ./$(BIN_DIR)/$(PROG) $(MAN_PAGE)
	@scripts/gen-readme-usage.sh ./$(BIN_DIR)/$(PROG) README.md
	@printf '  \033[92m✓\033[0m %s and the README Usage block are current\n' "$(MAN_PAGE)"

# Shows the page from the tree -- regenerated first if the program changed --
# without installing anything. mandoc where there is one (the BSDs, macOS);
# otherwise man(1), which every system here reads a page from when it is given
# a path with a slash in it rather than a name.
.PHONY: show-man
show-man: $(MAN_PAGE) ## Display the manpage from the tree, without installing it
	@if command -v mandoc > /dev/null 2>&1; then \
	    mandoc -a $(MAN_PAGE); \
	else \
	    man ./$(MAN_PAGE); \
	fi

.PHONY: man-check
man-check: build ## Fail if the committed manpage or README Usage block is out of date
	@scripts/gen-man.sh --check ./$(BIN_DIR)/$(PROG) $(MAN_PAGE)
	@scripts/gen-readme-usage.sh --check ./$(BIN_DIR)/$(PROG) README.md

.PHONY: install-hooks
install-hooks: ## Install the git pre-push hook (make check passed on what is pushed)
	@scripts/install-hooks.sh

##@ Installing

.PHONY: install
install: build ## Install into $(prefix) (default /usr/local), asking for sudo/doas if needed
	@scripts/install.sh

.PHONY: uninstall
uninstall: ## Remove what `make install` installed
	@scripts/install.sh --uninstall

.PHONY: install-proxy
install-proxy: proxy ## Install restate-proxy into $(prefix), and make /etc/restate/proxy.d
	@scripts/install-proxy.sh

.PHONY: uninstall-proxy
uninstall-proxy: ## Remove what `make install-proxy` installed (the grants stay)
	@scripts/install-proxy.sh --uninstall

##@ Packaging

.PHONY: deb
deb: build ## Build the binary .deb into the parent directory
	@scripts/build-deb.sh

.PHONY: deb-source
deb-source: build ## Build the signed source package for a Launchpad upload
	@scripts/build-deb.sh --source

.PHONY: deb-sbuild
deb-sbuild: build ## Build in a clean chroot with no network, as a Launchpad builder does
	@scripts/build-deb.sh --sbuild

# The staged install debian/rules runs.
#
# Not `make install`, which puts files on a live system: under /usr/local so as
# not to collide with what dpkg owns, asking for privileges if it has to, and
# refreshing the man database. This assembles a directory that is about to be
# a package -- wherever DESTDIR says, with the prefix debian/rules gives,
# never asking for privileges, and leaving the man database alone, which
# indexing a staging tree would point at a filesystem that does not exist.
# The hooks go where the program looks for them: libexec/restate/hooks beside
# the sbin it is in.
.PHONY: install-tree
install-tree: build ## Install into DESTDIR, for the package build
	@$(INSTALL) -d $(DESTDIR)$(sbindir) $(DESTDIR)$(mandir)/man8 \
	              $(DESTDIR)$(exec_prefix)/libexec/$(PROG)/hooks
	@$(INSTALL) -d -m 0755 $(DESTDIR)$(sysconfdir)/$(PROG)/jobs.d
	@$(INSTALL) -m 0755 $(BIN_DIR)/$(PROG) $(DESTDIR)$(sbindir)/$(PROG)
	@$(INSTALL) -m 0644 $(MAN_PAGE) $(DESTDIR)$(mandir)/man8/$(PROG).8
	@$(INSTALL) -m 0755 hooks/* $(DESTDIR)$(exec_prefix)/libexec/$(PROG)/hooks/
	@printf '  \033[92m✓\033[0m installed into %s\n' "$(DESTDIR)$(prefix)"

# restate-proxy's staged install, as install-tree is restate's, for the
# packages: the program, its manual and the directory of its grants. Each
# package adds its own service for its init system, and its user.
.PHONY: install-proxy-tree
install-proxy-tree: proxy ## Install restate-proxy into DESTDIR, for the package build
	@$(INSTALL) -d $(DESTDIR)$(sbindir) $(DESTDIR)$(mandir)/man8
	@$(INSTALL) -d -m 0755 $(DESTDIR)$(sysconfdir)/$(PROG)/proxy.d
	@$(INSTALL) -m 0755 $(BIN_DIR)/$(PROXY) $(DESTDIR)$(sbindir)/$(PROXY)
	@$(INSTALL) -m 0644 man/$(PROXY).8 $(DESTDIR)$(mandir)/man8/$(PROXY).8
	@printf '  \033[92m✓\033[0m installed %s into %s\n' "$(PROXY)" "$(DESTDIR)$(prefix)"

# A BSD's binary package, built with that system's own tool from a staged
# install (scripts/build-bsd-pkg.sh). OpenBSD's and NetBSD's packages put the
# manual under $(prefix)/man, as their ports and pkgsrc do.
BSD_STAGE := pkg-stage
BSD_MANDIR = $(if $(filter OpenBSD NetBSD,$(shell uname -s)),$(prefix)/man,$(mandir))

# Then restate-proxy's, the same way, where its TLS library is here (the
# base system's on each BSD).
.PHONY: bsd-pkg
bsd-pkg: build ## Build this BSD's binary packages (restate, restate-proxy) into dist/
	@rm -rf $(BSD_STAGE)
	@$(MAKE) --no-print-directory install-tree DESTDIR=$(CURDIR)/$(BSD_STAGE) \
	         mandir=$(BSD_MANDIR) > /dev/null
	@scripts/build-bsd-pkg.sh $(BSD_STAGE) dist
	@rm -rf $(BSD_STAGE)
	@$(if $(PROXY_OK),$(MAKE) --no-print-directory install-proxy-tree \
	         DESTDIR=$(CURDIR)/$(BSD_STAGE) mandir=$(BSD_MANDIR) > /dev/null \
	   && scripts/build-bsd-pkg.sh --proxy $(BSD_STAGE) dist,$(PROXY_MISSING))
	@rm -rf $(BSD_STAGE)

# An RPM for the Fedora, EL or openSUSE this runs on, and an Alpine package
# for the Alpine release it runs on, each from a tarball of this tree
# (scripts/build-rpm.sh, scripts/build-apk.sh), into dist/.
.PHONY: rpm
rpm: ## Build this distribution's RPM into dist/ (Fedora, RHEL and its rebuilds, openSUSE)
	@scripts/build-rpm.sh

.PHONY: apk
apk: ## Build this Alpine release's package into dist/ (as root, in a throwaway container)
	@scripts/build-apk.sh

.PHONY: deb-clean
deb-clean: ## Remove what the package builds left behind
	@rm -rf debian/$(PROG) debian/$(PROXY) debian/.debhelper debian/files debian/changelog
	@rm -f debian/*.substvars debian/*.debhelper debian/*.debhelper.log
	@rm -f debian/debhelper-build-stamp
	@rm -f debian/restate.restate-job@.service debian/restate.restate-job@.timer
	@rm -f debian/restate-proxy.service
	@rm -f ../$(PROXY)_*.deb ../$(PROXY)-dbgsym_*.ddeb 2>/dev/null || true
	@rm -f ../$(PROG)_*.deb ../$(PROG)-dbgsym_*.ddeb ../$(PROG)_*.changes \
	       ../$(PROG)_*.buildinfo ../$(PROG)_*.build ../$(PROG)_*.dsc \
	       ../$(PROG)_*.tar.* ../$(PROG)_*.upload 2>/dev/null || true

##@ Release

.PHONY: release
release: ## Bump the version, tag it and push (make release VERSION=1.2.3.4)
	@scripts/release.sh

# make release without make check, and past the pre-push hook; the Release
# workflow still waits for CI to pass on the commit before it publishes.
.PHONY: force-release
force-release: ## make release, testing nothing here first (make force-release VERSION=1.2.3.4)
	@RESTATE_FORCE_RELEASE=1 scripts/release.sh

##@ Setup

.PHONY: install-dev
install-dev: ## Install the compilers, analyzers and tools development needs
	@scripts/install-dev.sh

##@ Housekeeping

# Everything here is regenerated by some target, so removing it leaves the tree
# as a fresh checkout. The generated manpage and the coverage badge are kept:
# both are committed.
CLEAN_DIRS := $(OBJ_DIR) $(BIN_DIR) $(COV_DIR) .lint .sanitize .sanitize.lock .fuzz .security-reports \
              dist pkg-stage

.PHONY: clean
clean: ## Remove every intermediate file: objects, binaries, coverage, logs
	@rm -rf $(CLEAN_DIRS)
	@find . -path ./.git -prune -o \
	        \( -name '*.o' -o -name '*.d' -o -name '*.gcda' -o -name '*.gcno' \
	           -o -name '*.gcov' -o -name '*.core' -o -name 'core.[0-9]*' \
	           -o -name 'vgcore.*' \) -type f -print0 2>/dev/null \
	  | xargs -0 rm -f 2> /dev/null || true
	@echo "Cleaned. (The generated manpage and coverage badge are kept; both are committed.)"

.PHONY: distclean
distclean: clean ## clean, plus test-memory's kept failure logs and the records of what passed
	@rm -rf .sanitize.failed .passed
	@echo "Distribution clean."
