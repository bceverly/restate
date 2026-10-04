#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Cut a release version.
#
#   make release                      bump the last digit of the highest tag
#   make release VERSION=1.2.3.4      set an explicit version
#   make release VERSION=v1.2.3.4     the same thing; the "v" is optional
#
# Versions are four-part and tags carry a lowercase "v", e.g. v1.2.3.4. With no
# version tags in the repository at all, the first release is whatever VERSION
# already says (0.1.0.0 to begin with) rather than a bump of nothing.
#
# What it does, in order, after a single confirmation:
#   1. Brings VERSION up to the newest release tag if it has fallen behind,
#      works out the next version, refuses an existing tag, a version older
#      than the newest release, or uncommitted changes (other than VERSION),
#      and asks you to confirm it.
#   2. Writes it into VERSION, rebuilds, regenerates the manpage and the
#      README's Usage block, and checks the manpage names the new version.
#   3. Commits and pushes that change.
#   4. Creates an annotated tag and pushes the tag.
#
# Pushing the tag is what triggers the release build, so the confirmation in
# step 1 is the point of no return — answer "n" and nothing is released (VERSION
# keeps its catch-up, if it needed one).
#
# Commit and tag signing follow your git config (commit.gpgsign / tag.gpgsign);
# this script does not override them.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

#: Used when the repository has no version tags yet: the number already in the
#: VERSION file, so the first release is the one the tree has been calling
#: itself all along.
FIRST_VERSION="$(cat VERSION 2>/dev/null || echo 0.1.0.0)"
VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'

GREEN=$'\033[1;92m'
RESET=$'\033[0m'

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  \033[96m→\033[0m %s\n' "$*"; }
ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[93m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

command -v git > /dev/null 2>&1 || die "git is not installed."
[ -d .git ] || die "Not a git repository."

# ---------------------------------------------------------------------------
# Work out the version
# ---------------------------------------------------------------------------
bold "Release"

# `sort -V` orders version strings numerically, so v1.10.0.0 correctly sorts
# above v1.9.0.0 — a plain lexical sort gets that backwards.
LATEST="$(git tag -l 'v*' 2>/dev/null \
          | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
          | sed 's/^v//' \
          | sort -V \
          | tail -1)"

# VERSION catches up with the newest release before anything else. It can fall
# behind -- a release cut from another clone, or a release commit that never
# reached this branch -- and then everything built here calls itself an older
# version than one already published. The newest tag is the authority on what
# has been released, so VERSION is brought up to it here, where git is already
# being run, rather than by hand. This stays done even if the release is
# declined below, and the release commit carries it either way.
CURRENT="$(cat VERSION 2>/dev/null || echo)"
if [ -n "$LATEST" ] && { [ -z "$CURRENT" ] || \
   [ "$(printf '%s\n%s\n' "$CURRENT" "$LATEST" | sort -V | tail -1)" != "$CURRENT" ]; }; then
  echo "$LATEST" > VERSION || die "Could not write VERSION."
  warn "VERSION said ${CURRENT:-nothing}, but v$LATEST is released: VERSION -> $LATEST"
fi

# `make release VERSION=1.2.3.4` hands this script the number two ways at once:
# as an environment variable — which is how it is read, just below — and as a
# make *override*, which make propagates to every sub-make and every child
# process through MAKEFLAGS.
#
# That second path was a trap. The Makefile has its own
# `VERSION := $(shell scripts/version.sh)`, the string compiled into the binary,
# and an override replaces it. So the rebuild further down stamped a bare
# "1.2.3.4" instead of the "1.2.3.4-dev" this tree actually builds (the bump is
# not committed and the tag does not exist yet), and then the pre-commit hook's
# `make lint` — which derives the version for itself and so was never fooled —
# refused to commit the release it had just prepared. A plain `make release`
# never hit it, because there was no override to propagate.
#
# The argument has been read by the time the next line runs, so the make
# plumbing is dropped here, once, rather than at each place downstream that
# shells out.
VERSION_ARG="${VERSION:-}"
unset VERSION MAKEFLAGS MAKEOVERRIDES

EXPLICIT="$VERSION_ARG"

if [ -n "$EXPLICIT" ]; then
  # Both "1.2.3.4" and "v1.2.3.4" are accepted; the tag always gets the "v".
  EXPLICIT="${EXPLICIT#v}"
  echo "$EXPLICIT" | grep -qE "$VERSION_PATTERN" \
    || die "VERSION must look like 1.2.3.4 or v1.2.3.4 (four numbers), got '${VERSION_ARG}'."
  NEXT="$EXPLICIT"
  if [ -n "$LATEST" ]; then
    info "Current version:  v$LATEST"
  else
    info "Current version:  (no tags yet)"
  fi
  info "Setting version:  v$NEXT  (explicit)"
elif [ -z "$LATEST" ]; then
  NEXT="$FIRST_VERSION"
  info "No version tags found in this repository."
  info "First release:    v$NEXT"
else
  # Bump the last of the four components.
  IFS='.' read -r MAJOR MINOR PATCH BUILD <<< "$LATEST"
  NEXT="${MAJOR}.${MINOR}.${PATCH}.$((BUILD + 1))"
  info "Current version:  v$LATEST"
  info "Next version:     v$NEXT"
fi

TAG="v$NEXT"

# Everything below is checked BEFORE anything changes, because each of these
# used to be found halfway through: after the version commit had already been
# pushed, with only the tag left to fail.

# A tag that exists names a release that may already have been built and
# published. Moving it is a decision, not something to do by accident.
if git rev-parse -q --verify "refs/tags/$TAG" > /dev/null 2>&1; then
  die "Tag $TAG already exists. Release a newer version, or, if $TAG was never
       published and you mean to move it, delete it first:
           git push --delete origin $TAG && git tag -d $TAG"
fi

# A version has to move forward: one at or below the newest tag would sort
# before releases that already exist.
if [ -n "$LATEST" ] && [ "$NEXT" != "$LATEST" ] \
   && [ "$(printf '%s\n%s\n' "$LATEST" "$NEXT" | sort -V | tail -1)" != "$NEXT" ]; then
  die "v$NEXT is older than the newest release, v$LATEST."
fi

# A release built from a dirty tree is a release nobody can reproduce -- and it
# is not even the tree that is being looked at: uncommitted changes would be
# left out of it. Commit them, or stash them, first.
# VERSION is left out: the catch-up above may just have changed it, and the
# release writes and commits it regardless.
if [ -n "$(git status --porcelain --untracked-files=no -- . ':!VERSION' 2>/dev/null)" ]; then
  git status --short --untracked-files=no -- . ':!VERSION' | sed 's/^/      /'
  die "The working tree has uncommitted changes (above). Commit them first:
       a release has to be exactly what is committed."
fi

# ---------------------------------------------------------------------------
# Confirm
# ---------------------------------------------------------------------------
printf '\n'
printf '  Release as \033[1;96m%s\033[0m? [y/N] ' "$TAG"
read -r REPLY
case "$REPLY" in
  y | Y | yes | YES | Yes) ;;
  *)
    printf '\n'
    if [ "$(cat VERSION)" != "$CURRENT" ]; then
      info "Stopped. Only VERSION changed, to match v$LATEST; nothing was released."
    else
      info "Stopped. Nothing was changed."
    fi
    exit 0
    ;;
esac

# ---------------------------------------------------------------------------
# Write the version into the project
# ---------------------------------------------------------------------------
bold "Updating the version"

# One file. The Makefile reads it, compiles it into the binary with
# -DRESTATE_VERSION, and the manpage's footer is generated from it -- so there
# is exactly one place a version can be wrong.
CURRENT="$(cat VERSION 2>/dev/null || echo)"
if [ "$CURRENT" = "$NEXT" ]; then
  info "VERSION already says $NEXT"
else
  echo "$NEXT" > VERSION || die "Could not write VERSION."
  ok "VERSION -> $NEXT"
fi

# Rebuild so the manpage's version line and the binary's --version agree with
# the tag. `make lint` checks exactly this, and finding out at that point that
# the release is wrong is finding out too late.
info "Rebuilding so the binary and the manpage carry $NEXT…"
make --no-print-directory build > /dev/null || die "The build failed; nothing was committed."
BUILT="$(./bin/restate --version | head -1 | awk '{print $2}')"

# The manpage and the README's Usage block, regenerated outright rather than
# left to the build's timestamps. The manpage's footer names the version, and
# a release once went out with the previous one in it because the build
# decided, from the files' dates, that the page did not need rewriting.
scripts/gen-man.sh ./bin/restate man/restate.8 \
  || die "Could not regenerate the manpage; nothing was committed."
scripts/gen-readme-usage.sh ./bin/restate README.md \
  || die "Could not regenerate the README's Usage block; nothing was committed."
grep -q "^\.TH RESTATE 8 \"[^\"]*\" \"restate $NEXT\"" man/restate.8 \
  || die "man/restate.8 does not name version $NEXT after regenerating it."
ok "man/restate.8 names $NEXT"
# The "-dev" suffix is expected here and is not a problem: at this point the
# version bump is not committed and the tag does not exist, so scripts/version.sh
# is correctly saying this tree is not the release. What matters is the number
# in front of it. Once the commit and the tag below land, a rebuild drops the
# suffix on its own.
[ "${BUILT%-dev}" = "$NEXT" ] \
  || die "The rebuilt binary reports $BUILT, not $NEXT."

# And check what `make lint` is about to check, with the same comparison, so the
# two can never disagree. Catching a mismatch here names it plainly; catching it
# in the pre-commit hook aborts a release that is already half prepared.
EXPECTED="$(scripts/version.sh)"
[ "$BUILT" = "$EXPECTED" ] || die "The rebuilt binary reports $BUILT, but this
       tree builds $EXPECTED — 'make lint' would reject the commit. Nothing was
       committed."
ok "./bin/restate reports $BUILT"

# ---------------------------------------------------------------------------
# Commit, push, tag, push the tag
# ---------------------------------------------------------------------------
bold "Publishing"

BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
if [ -z "$BRANCH" ] || [ "$BRANCH" = "HEAD" ]; then
  die "Not on a branch (detached HEAD?); cannot push."
fi

git remote get-url origin > /dev/null 2>&1 \
  || die "No 'origin' remote configured; nothing to push to."

git add VERSION man/restate.8 README.md || die "Could not stage the version files."

# An empty diff means the files already carried this version, which is fine on
# a re-run; skip the commit rather than failing on "nothing to commit".
if git diff --cached --quiet; then
  warn "VERSION and the manpage already say $NEXT — nothing to commit."
else
  git commit -m "Release $TAG" || die "Commit failed."
  ok "Committed the version bump."
fi

info "Pushing $BRANCH to origin…"
git push origin "$BRANCH" || die "Push failed; the tag was not created."
ok "Pushed $BRANCH."

info "Tagging $TAG…"
git tag -a "$TAG" -m "Release $TAG" || die "Could not create tag $TAG."
ok "Created tag $TAG."

# RESTATE_SKIP_HOOK=1, and this is the one place it is honest.
#
# A release does two pushes -- the branch, then the tag -- and git runs the
# pre-push hook on each. That hook runs the whole test suite: both suites, the
# sanitizers, valgrind and the coverage gate, which re-runs both suites again.
# The branch push above just did all of it. The tag points at the commit that
# push published, nothing has been touched since, and the hook tests the working
# tree rather than the ref being pushed -- so the second run reads the same
# bytes and can only reach the same answer, several minutes later.
#
# Skipping it is not skipping the check; the check ran, on this tree, moments
# ago. If the branch push had failed its hook, the die above means execution
# never got here.
info "Pushing tag $TAG…"
if ! RESTATE_SKIP_HOOK=1 git push origin "$TAG"; then
  # Leave the local tag in place so it can be retried or inspected.
  die "Could not push the tag. The local tag $TAG still exists; delete it with
       'git tag -d $TAG' if you want to start over."
fi
ok "Pushed tag $TAG."

cat <<NEXT_STEPS

  ────────────────────────────────────────────────────────────────
   ${GREEN}Released ${TAG}${RESET}

   Pushing the tag triggers the Release workflow, which waits for CI and
   the security scan to pass on this commit, builds the source tarball and
   its checksums, attaches a signed build-provenance attestation, and
   publishes a GitHub release. Watch it with:

       gh run watch

   To undo, before anything consumes the tag:

       git push --delete origin ${TAG}
       git tag -d ${TAG}
  ────────────────────────────────────────────────────────────────

NEXT_STEPS
