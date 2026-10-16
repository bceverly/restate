#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Build the restate Debian package.
#
#   scripts/build-deb.sh              the binary .deb for this machine
#   scripts/build-deb.sh --source     a signed source package, for Launchpad
#   scripts/build-deb.sh --sbuild     build in a clean chroot, as Launchpad does
#
# debian/changelog is generated from the VERSION file rather than maintained by
# hand. The version already lives in VERSION and is compiled into the binary; a
# third copy would be a third thing to forget during a release, and a package
# whose version does not match its tag cannot be fixed once it is uploaded.
#
# SERIES selects the Ubuntu release the package is built for. It defaults to
# this machine's, which is right for a local build; a Launchpad upload wants
# one source package per series it targets, which is what the release workflow
# does by setting SERIES for each.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE=binary
case "${1:-}" in
  --source) MODE=source ;;
  --sbuild) MODE=sbuild ;;
  "")       ;;
  *)        echo "Unknown option: $1" >&2; exit 2 ;;
esac

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  \033[96m→\033[0m %s\n' "$*"; }
ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[93m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[91m✗\033[0m %s\n' "$*" >&2; exit 1; }

VERSION="$(cat VERSION)"
[ -n "$VERSION" ] || die "VERSION is empty"

# shellcheck disable=SC1091  # /etc/os-release is not a file in this repository
SERIES="${SERIES:-$(. /etc/os-release && echo "${VERSION_CODENAME:-}")}"
[ -n "$SERIES" ] || die "Could not determine the Ubuntu series; set SERIES=<codename>"

bold "restate — Debian package"
info "Version: $VERSION"
info "Series:  $SERIES"
info "Mode:    $MODE"

command -v dpkg-buildpackage > /dev/null 2>&1 \
  || die "dpkg-buildpackage is not installed. Run: make install-dev"

# ---------------------------------------------------------------------------
# debian/changelog, generated
# ---------------------------------------------------------------------------
#
# The identity that goes into debian/changelog.
#
# Taken from the Maintainer in debian/control and NOT from DEBFULLNAME/DEBEMAIL
# in the environment, even when those are set.
#
# A developer who maintains more than one Debian package has these exported
# in their profile for whichever project they set up first, and a build that
# deferred to them would say that project's maintainer changed this one.
# Which person a package is changed by is a property of the package, not of
# the shell that happened to build it.
#
# RESTATE_DEBFULLNAME / RESTATE_DEBEMAIL override deliberately, and are named
# so that no other project's setup can set them by accident.
MAINTAINER_LINE="$(sed -n 's/^Maintainer: //p' debian/control | head -1)"
CONTROL_NAME="${MAINTAINER_LINE%% <*}"
CONTROL_EMAIL="$(printf '%s' "$MAINTAINER_LINE" | sed -n 's/.*<\(.*\)>.*/\1/p')"

if [ -z "$CONTROL_NAME" ] || [ -z "$CONTROL_EMAIL" ]; then
  die "Could not read the Maintainer line from debian/control."
fi

# Say so when the environment disagrees, rather than silently winning: somebody
# who exported DEBEMAIL on purpose should find out that it was not used here.
if [ -n "${DEBFULLNAME:-}" ] && [ "$DEBFULLNAME" != "$CONTROL_NAME" ]; then
  warn "ignoring DEBFULLNAME=\"$DEBFULLNAME\" from the environment"
fi
if [ -n "${DEBEMAIL:-}" ] && [ "$DEBEMAIL" != "$CONTROL_EMAIL" ]; then
  warn "ignoring DEBEMAIL=\"$DEBEMAIL\" from the environment"
fi

DEBFULLNAME="${RESTATE_DEBFULLNAME:-$CONTROL_NAME}"
DEBEMAIL="${RESTATE_DEBEMAIL:-$CONTROL_EMAIL}"
export DEBFULLNAME DEBEMAIL
info "Maintainer: $DEBFULLNAME <$DEBEMAIL>"

# "~" sorts before everything else, so the same version rebuilt for a newer
# series always upgrades cleanly over the one built for an older one.
DEB_VERSION="${VERSION}~${SERIES}1"

cat > debian/changelog <<CHANGELOG
restate ($DEB_VERSION) $SERIES; urgency=medium

  * Release $VERSION.

 -- $DEBFULLNAME <$DEBEMAIL>  $(date -R)
CHANGELOG
ok "debian/changelog -> $DEB_VERSION"

# ---------------------------------------------------------------------------
# Signing
#
# The key is pinned in debian/signing-fingerprint for the same reason the maintainer is
# pinned in debian/control: DEBSIGN_KEYID is a global shell variable, and on a
# machine that maintains several packages it names whichever project came
# first. It is deliberately NOT consulted here.
#
# Only the SOURCE package is signed. That signature is what Launchpad
# authenticates the upload with. A binary .deb built locally is a test artifact
# that nothing verifies, so signing it only slows the build down and prompts
# for a passphrase nobody needed to type.
# ---------------------------------------------------------------------------
SIGNING_KEY="${RESTATE_SIGNING_KEY:-}"
if [ -z "$SIGNING_KEY" ] && [ -f debian/signing-fingerprint ]; then
  SIGNING_KEY="$(grep -vE '^\s*(#|$)' debian/signing-fingerprint | head -1 | tr -d '[:space:]')"
fi

if [ -n "${DEBSIGN_KEYID:-}" ] && [ "$DEBSIGN_KEYID" != "$SIGNING_KEY" ]; then
  warn "ignoring DEBSIGN_KEYID=$DEBSIGN_KEYID from the environment"
  warn "this project signs with the key in debian/signing-fingerprint"
fi

SIGN=()
if [ "$MODE" = source ]; then
  if [ -z "$SIGNING_KEY" ]; then
    warn "No signing key: debian/signing-fingerprint is missing or empty, and"
    warn "RESTATE_SIGNING_KEY is not set. Building UNSIGNED -- Launchpad will"
    warn "reject this. Fine for a local check, not for an upload."
    SIGN=("--no-sign")
  elif ! gpg --list-secret-keys "$SIGNING_KEY" > /dev/null 2>&1; then
    die "debian/signing-fingerprint names $SIGNING_KEY, which is not in this keyring.
       Import it, or set RESTATE_SIGNING_KEY to one that is."
  else
    # Explicit -k rather than letting debsign match on DEBEMAIL: several keys
    # here carry the same address, and debsign picks among them silently.
    SIGN=("-k${SIGNING_KEY}")
    info "Signing with ${SIGNING_KEY}"
  fi
else
  # --no-sign, not "-us -uc": those two cover the source and the .changes, and
  # dpkg still tries to sign the .buildinfo, failing with "Inappropriate ioctl
  # for device" wherever there is no interactive gpg agent.
  SIGN=("--no-sign")
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
case "$MODE" in
  binary)
    bold "dpkg-buildpackage -b"
    dpkg-buildpackage -b "${SIGN[@]}"
    ;;
  source)
    bold "dpkg-buildpackage -S"
    # -sa forces the full source into the upload, which Launchpad needs for the
    # first upload of any version.
    dpkg-buildpackage -S -sa "${SIGN[@]}"
    ;;
  sbuild)
    bold "sbuild — clean chroot, no network"
    command -v sbuild > /dev/null || die "sbuild is not installed"
    # The unshare backend: no root, no group membership that only takes effect
    # after a re-login, no /etc/schroot entry. It is sbuild's modern default
    # and the least machinery for the same answer.
    IMAGE="$HOME/.cache/sbuild/${SERIES}-amd64.tar.zst"
    if [ ! -f "$IMAGE" ]; then
      warn "No unshare image at $IMAGE"
      printf '\n  Create it once with:\n\n'
      printf '    sudo apt install mmdebstrap uidmap sbuild\n'
      printf '    mkdir -p ~/.cache/sbuild\n'
      printf '    mmdebstrap --variant=buildd --arch=amd64 \\\n'
      printf '      --components=main,universe %s \\\n' "$SERIES"
      printf '      %s \\\n' "$IMAGE"
      printf '      http://archive.ubuntu.com/ubuntu\n\n'
      die "sbuild image missing"
    fi
    # This is the real test of the packaging: sbuild installs only the
    # Build-Depends into a clean chroot and builds with no network, which is
    # exactly what a Launchpad builder does.
    sbuild --chroot-mode=unshare --dist="$SERIES" --arch=amd64 \
           --no-run-lintian --build-dir=.. .
    ;;
esac

# ---------------------------------------------------------------------------
# Check what came out
# ---------------------------------------------------------------------------
if [ "$MODE" != source ]; then
  # shellcheck disable=SC2012  # sorting by mtime is the point, and these are
  # our own filenames: dpkg-buildpackage names them, not a user.
  DEB="$(ls -t ../restate_*.deb 2>/dev/null | head -1 || true)"
  if [ -n "$DEB" ]; then
    bold "Result"
    ok "$DEB ($(du -h "$DEB" | cut -f1))"
    if command -v lintian > /dev/null 2>&1; then
      # Informational: lintian's opinion is worth reading and a tag is not a
      # reason to fail a local build. CI runs it with --fail-on error.
      info "lintian:"
      lintian --tag-display-limit 0 "$DEB" 2>&1 | sed 's/^/    /' || true
    fi
    printf '\n  Install it with:\n    sudo dpkg -i %s\n\n' "$DEB"
  fi
else
  # shellcheck disable=SC2012  # as above: sorted by mtime, dpkg's own names
  CHANGES="$(ls -t ../restate_*_source.changes 2>/dev/null | head -1 || true)"
  if [ -n "$CHANGES" ]; then
    bold "Result"
    ok "$CHANGES"
    printf '\n  Upload it with:\n    dput ppa:bceverly/restate %s\n\n' "$CHANGES"
  fi
fi
