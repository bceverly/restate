#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Installs restate and restate-proxy from the apt repository in DIR on a
# clean Debian, as a machine following the README would, and checks they are
# VERSION.
#
#   scripts/verify-apt-repo.sh DIR VERSION
#
# DIR is the repository scripts/apt-repo.sh made (SITE/debian), read here as
# a file: URI in place of the published https one, before it is published --
# the signature, the indexes and the packages they point to are all checked
# by apt itself, as they will be there. Meant for a throwaway container:
#
#   docker run --rm -v "$PWD/site/debian:/repo:ro" -v "$PWD/scripts:/s:ro" \
#     debian:13 sh /s/verify-apt-repo.sh /repo 3.2.1.9
set -eux

DIR="${1:?usage: verify-apt-repo.sh DIR VERSION}"
# WANT, not VERSION: /etc/os-release, read below, sets VERSION.
WANT="${2:?usage: verify-apt-repo.sh DIR VERSION}"
export DEBIAN_FRONTEND=noninteractive

# shellcheck disable=SC1091  # /etc/os-release is not a file in this repository
. /etc/os-release
cp "$DIR/restate-archive-keyring.asc" /usr/share/keyrings/restate-archive-keyring.asc
cat > /etc/apt/sources.list.d/restate.sources <<EOF
Types: deb
URIs: file:$DIR
Suites: $VERSION_CODENAME
Components: main
Signed-By: /usr/share/keyrings/restate-archive-keyring.asc
EOF

# A repository whose signature does not check is only a warning to apt-get
# update, which then goes on without it; Error-Mode=any makes it a failure.
apt-get -o APT::Update::Error-Mode=any update
apt-get install -y -qq restate restate-proxy

# The package's version is the release's for this codename, as
# scripts/build-deb.sh writes it: 3.2.1.9~trixie1.
test "$(dpkg-query -W -f='${Version}' restate)" = "$WANT~${VERSION_CODENAME}1"
test "$(dpkg-query -W -f='${Version}' restate-proxy)" = "$WANT~${VERSION_CODENAME}1"
apt-cache policy restate | grep -F "file:$DIR"
restate --version | grep -F "$WANT"

apt-get purge -y -qq restate restate-proxy
if dpkg-query -W -f='${Status}\n' restate 2> /dev/null | grep -q 'ok installed'; then
  echo "restate is still installed after the purge" >&2
  exit 1
fi
echo "VERIFIED: restate $WANT from the apt repository on Debian $VERSION_ID ($VERSION_CODENAME)"
