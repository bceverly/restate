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

$(BIN_DIR) $(OBJ_DIR) $(COV_DIR):
	@mkdir -p $@

# The manpage is generated from the program's own --help, so it depends on the
# binary that prints it and the tables that binary was built from.
$(MAN_PAGE): $(BIN_DIR)/$(PROG) src/options.def src/commands.def scripts/gen-man.sh VERSION
	@scripts/gen-man.sh $(BIN_DIR)/$(PROG) $@

-include $(wildcard $(OBJ_DIR)/*.d)

.PHONY: debug
debug: ## Rebuild unoptimized with symbols, for a debugger
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory build CFLAGS="-O0 -g3 -fno-omit-frame-pointer"

.PHONY: run
run: build ## Build, then scan this source tree and classify a few paths
	@./$(BIN_DIR)/$(PROG) scan --root=. --no-default-rules
	@./$(BIN_DIR)/$(PROG) classify /etc/passwd /var/cache/apt /usr/bin/ls /usr/local/bin /tmp

##@ Test

.PHONY: test
test: test-unit test-cli test-memory coverage ## Unit + CLI tests, sanitizers, valgrind, and the 80% coverage gate

.PHONY: test-unit
test-unit: $(BIN_DIR)/unittests ## Run the C unit tests
	@./$(BIN_DIR)/unittests

# $(filter %.c,$^): the stamp is a real prerequisite, so a version change
# rebuilds the tests too, but it must not reach the linker as an input file.
$(BIN_DIR)/unittests: $(LIB_SRC) $(TEST_SRC) $(wildcard src/*.h tests/*.h) $(OBJ_DIR)/version.stamp | $(BIN_DIR)
	@$(CC) $(ALL_CPPFLAGS) $(ALL_TESTFLAGS) -o $@ $(filter %.c,$^) $(ALL_LDFLAGS)

.PHONY: test-cli
test-cli: build ## Run the end-to-end tests against the built binary
	@tests/cli/run.sh ./$(BIN_DIR)/$(PROG)

.PHONY: test-memory
test-memory: ## Run everything again under ASan, UBSan, LSan and valgrind
	@scripts/memcheck.sh

.PHONY: coverage
coverage: ## Measure line coverage, refresh the badge, fail below 80% overall or in any file
	@scripts/coverage.sh

.PHONY: fuzz
fuzz: ## Fuzz the manifest, rules and pattern parsers (FUZZ_SECONDS=30 by default)
	@scripts/fuzz.sh

##@ Quality

.PHONY: lint
lint: build ## Compiler, analyzers, house style, copyright audit, generated-file checks
	@scripts/lint.sh

.PHONY: style
style: ## Check the C files against the house style (part of make lint)
	@scripts/style.sh

.PHONY: security
security: build ## Run the same security scanners CI runs, locally
	@scripts/security.sh

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
install-hooks: ## Install the git pre-commit (lint) and pre-push (test) hooks
	@scripts/install-hooks.sh

##@ Installing

.PHONY: install
install: build ## Install into $(prefix) (default /usr/local), asking for sudo/doas if needed
	@scripts/install.sh

.PHONY: uninstall
uninstall: ## Remove what `make install` installed
	@scripts/install.sh --uninstall

##@ Release

.PHONY: release
release: ## Bump the version, tag it and push (make release VERSION=1.2.3.4)
	@scripts/release.sh

##@ Setup

.PHONY: install-dev
install-dev: ## Install the compilers, analyzers and tools development needs
	@scripts/install-dev.sh

##@ Housekeeping

# Everything here is regenerated by some target, so removing it leaves the tree
# as a fresh checkout. The generated manpage and the coverage badge are kept:
# both are committed.
CLEAN_DIRS := $(OBJ_DIR) $(BIN_DIR) $(COV_DIR) .lint .sanitize .sanitize.lock .fuzz .security-reports

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
distclean: clean ## clean, plus the kept failure logs from test-memory
	@rm -rf .sanitize.failed
	@echo "Distribution clean."
