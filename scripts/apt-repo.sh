#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Builds the signed apt repository for Debian that the release workflow
# publishes on GitHub Pages, from the release's Debian packages and the ones
# the repository held already.
#
#   scripts/apt-repo.sh SITE NEW KEEP
#
#   SITE  the site as it is published: SITE/debian is the repository, and is
#         added to and rewritten here; anything else in SITE is left alone
#   NEW   a directory of the release's packages, named as the release names
#         them: restate-VERSION-debian12-amd64.deb, restate-proxy-...
#   KEEP  how many versions each Debian release keeps, the newest: older ones
#         are removed, so the site stays well inside what Pages will serve
#
# RESTATE_SIGNING_KEY is the fingerprint of the key that signs it, in gpg's
# keyring and unlocked already (gpg is run with --batch). Its public half is
# written beside the repository, as restate-archive-keyring.asc.
#
# The layout is Debian's own, one suite for each release, by codename:
#
#   debian/dists/bookworm/{InRelease,Release,Release.gpg}
#   debian/dists/bookworm/main/binary-{amd64,arm64}/Packages{,.gz}
#   debian/pool/bookworm/restate_3.2.1.9~bookworm1_amd64.deb
#
# so a machine names its own release, and gets the packages built and tested
# on it, never another's: restate links against each release's own OpenSSL.
#
# The pool's files have Debian's own names, from each package's control
# fields, as apt-ftparchive finds a pool's packages for each architecture by
# their names.
#
# Needs apt-ftparchive (apt-utils), dpkg-deb, gpg and gzip.
set -eu

SITE="${1:?usage: apt-repo.sh SITE NEW KEEP}"
NEW="${2:?usage: apt-repo.sh SITE NEW KEEP}"
KEEP="${3:?usage: apt-repo.sh SITE NEW KEEP}"
KEY="${RESTATE_SIGNING_KEY:?RESTATE_SIGNING_KEY is not set: the fingerprint of the signing key}"
ARCHES="amd64 arm64"

case "$KEEP" in
  '' | *[!0-9]* | 0) echo "apt-repo.sh: KEEP is a number of versions, 1 or more" >&2; exit 2 ;;
esac

# Debian's release numbers, as the packages are named, and their codenames,
# as apt names them. A release not here is refused, not guessed at: add it.
codename()
{
  case "$1" in
    12) echo bookworm ;;
    13) echo trixie ;;
    14) echo forky ;;
    *) return 1 ;;
  esac
}

# The release a pool's package is of: restate-proxy_3.2.1.9~bookworm1_amd64.deb
# is 3.2.1.9.
version_of()
{
  basename "$1" | sed -n 's/^restate\(-proxy\)\{0,1\}_\([0-9][0-9.]*\)~[a-z]*1_[a-z0-9]*\.deb$/\2/p'
}

mkdir -p "$SITE/debian/pool"
# Absolute, as the indexes are written from inside the repository, below.
SITE="$(cd "$SITE" && pwd)"
NEW="$(cd "$NEW" && pwd)"
REPO="$SITE/debian"

# The release's packages, into their release's pool.
found=0
for deb in "$NEW"/*.deb; do
  [ -e "$deb" ] || continue
  name="$(basename "$deb")"
  num="$(printf '%s\n' "$name" |
         sed -n 's/^restate\(-proxy\)\{0,1\}-[0-9][0-9.]*-debian\([0-9][0-9]*\)-[a-z0-9]*\.deb$/\2/p')"
  if [ -z "$num" ]; then
    echo "apt-repo.sh: $name is not named restate[-proxy]-VERSION-debianNN-ARCH.deb" >&2
    exit 1
  fi
  if ! suite="$(codename "$num")"; then
    echo "apt-repo.sh: Debian $num has no codename here: add it to codename()" >&2
    exit 1
  fi
  pkg="$(dpkg-deb -f "$deb" Package)"
  ver="$(dpkg-deb -f "$deb" Version)"
  arch="$(dpkg-deb -f "$deb" Architecture)"
  # The package says which release it was built for, as its version
  # (scripts/build-deb.sh): one in the wrong suite would install on a system
  # it was never built or tested on.
  case "$ver" in
    *~"$suite"1) ;;
    *)
      echo "apt-repo.sh: $name is version $ver, not one built for $suite" >&2
      exit 1
      ;;
  esac
  mkdir -p "$REPO/pool/$suite"
  cp "$deb" "$REPO/pool/$suite/${pkg}_${ver}_${arch}.deb"
  found=$((found + 1))
done
if [ "$found" -eq 0 ]; then
  echo "apt-repo.sh: no packages in $NEW" >&2
  exit 1
fi

# Each release's newest KEEP versions, the rest removed: one to go back to
# if a release goes wrong, without the site growing with every release.
for pool in "$REPO"/pool/*/; do
  [ -d "$pool" ] || continue
  for deb in "$pool"*.deb; do
    [ -e "$deb" ] && version_of "$deb"
  done | sort -u -V -r | tail -n +"$((KEEP + 1))" | while read -r old; do
    echo "removing $old from $(basename "$pool")"
    rm -f "$pool"restate_"$old"~*.deb "$pool"restate-proxy_"$old"~*.deb
  done
done

# The indexes, written afresh from what the pools hold. Paths are from the
# repository's top, as apt asks for them.
rm -rf "$REPO/dists"
cd "$REPO"
for pool in pool/*/; do
  suite="$(basename "$pool")"
  [ -n "$(find "$pool" -name '*.deb' -print -quit)" ] || { rm -rf "$pool"; continue; }
  for arch in $ARCHES; do
    dir="dists/$suite/main/binary-$arch"
    mkdir -p "$dir"
    apt-ftparchive --arch "$arch" packages "$pool" > "$dir/Packages"
    gzip -9nc "$dir/Packages" > "$dir/Packages.gz"
  done
  # Written beside, then moved in: apt-ftparchive lists the directory it is
  # writing into.
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=restate \
    -o APT::FTPArchive::Release::Label=restate \
    -o APT::FTPArchive::Release::Suite="$suite" \
    -o APT::FTPArchive::Release::Codename="$suite" \
    -o APT::FTPArchive::Release::Architectures="$ARCHES" \
    -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Description="restate for Debian $suite" \
    release "dists/$suite" > Release.tmp
  mv Release.tmp "dists/$suite/Release"
  gpg --batch --yes --local-user "$KEY" --clearsign \
    --output "dists/$suite/InRelease" "dists/$suite/Release"
  gpg --batch --yes --local-user "$KEY" --armor --detach-sign \
    --output "dists/$suite/Release.gpg" "dists/$suite/Release"
  echo "$suite: $(grep -c '^Package:' dists/"$suite"/main/binary-*/Packages | tr '\n' ' ')"
done

# The public half, the one key: what a machine is told to trust for this
# repository, and nothing else.
gpg --batch --armor --export "$KEY" > restate-archive-keyring.asc.tmp
if [ "$(gpg --batch --with-colons --show-keys restate-archive-keyring.asc.tmp |
        grep -c '^pub:')" -ne 1 ]; then
  echo "apt-repo.sh: $KEY did not export as exactly one key" >&2
  rm -f restate-archive-keyring.asc.tmp
  exit 1
fi
mv restate-archive-keyring.asc.tmp restate-archive-keyring.asc

# Served as they are: Pages runs a site through Jekyll unless told not to.
touch "$SITE/.nojekyll"
