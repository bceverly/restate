#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Install the git hooks.
#
#   make install-hooks
#
# Copies .githooks/* into .git/hooks/. A plain file copy rather than
# `git config core.hooksPath`, so that no git command is needed to install or
# uninstall them and so that removing one is just deleting a file.
#
# A hook that is already there and is not ours is left alone: someone else's
# pre-push is theirs, and silently replacing it is not this script's business.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SOURCE_DIR=".githooks"
TARGET_DIR=".git/hooks"
# Written into each installed hook so a later run can tell ours from a
# hand-written or third-party one.
MARKER="# restate — installed by scripts/install-hooks.sh"

ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[93m!\033[0m %s\n' "$*"; }
info() { printf '  \033[96m→\033[0m %s\n' "$*"; }

if [ ! -d .git ]; then
  warn "Not a git repository — nothing to install."
  exit 0
fi
if [ ! -d "$SOURCE_DIR" ]; then
  warn "$SOURCE_DIR is missing — nothing to install."
  exit 0
fi

mkdir -p "$TARGET_DIR"

installed=0
for source in "$SOURCE_DIR"/*; do
  [ -f "$source" ] || continue
  name="$(basename "$source")"
  target="$TARGET_DIR/$name"

  if [ -f "$target" ] && ! grep -qF "$MARKER" "$target" 2>/dev/null; then
    backup="$target.local-backup"
    cp "$target" "$backup"
    warn "$name already existed and is not ours — kept a copy at $backup"
  fi

  cp "$source" "$target"
  chmod +x "$target"
  installed=$((installed + 1))
  ok "$name"
done

if [ "$installed" -eq 0 ]; then
  warn "No hooks found in $SOURCE_DIR."
else
  info "$installed hook(s) installed. Set RESTATE_SKIP_HOOK=1 to bypass one."
fi
