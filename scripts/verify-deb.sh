#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Installs the restate .deb in DIR on a clean Ubuntu, as root, and uses it.
#
#   scripts/verify-deb.sh DIR
#
# Meant for a throwaway container -- it installs, captures this system and
# removes the package again -- and run there by the release workflow before
# anything is uploaded to the PPA, since an upload cannot be taken back:
#
#   docker run --rm -v "$PWD/artifacts:/packages:ro" -v "$PWD/scripts:/s:ro" \
#     ubuntu:26.04 sh /s/verify-deb.sh /packages
#
# What it proves is the package, not the program -- the tests do that: that
# apt installs it with what it depends on, puts the program, the manpage and
# the hooks where the program looks for them, and removes it cleanly.
set -eux

DIR="${1:?usage: verify-deb.sh DIR}"
export DEBIAN_FRONTEND=noninteractive

# The official images keep dpkg from unpacking manpages and docs, to stay
# small, while still recording them: the package's manpage would be listed and
# missing. This checks the package, not the image's space-saving.
rm -f /etc/dpkg/dpkg.cfg.d/excludes
apt-get update -qq
# man-db, so the manpage can be looked up as a user would. Nothing restate
# itself needs: the install below has to bring that.
apt-get install -y -qq --no-install-recommends man-db

# apt, not dpkg -i: dpkg does not resolve dependencies, and apt is what
# installing from the PPA does.
apt-get install -y -qq "$DIR"/restate_*.deb
dpkg-query -W -f='${Status}\n' restate | grep -qx 'install ok installed'
# What it put on disk, printed whatever happens, so a failure below can be
# read from this log alone.
dpkg -L restate

test -x /usr/sbin/restate
command -v gpgv
test -n "$(find /usr/share/man/man8 -name 'restate.8*' -print -quit)"
man -w restate
# Where the program looks for its hooks: libexec/restate/hooks beside the
# sbin it runs from.
for hook in postgresql mysql mongodb redis libvirt lxd docker; do
  test -x "/usr/libexec/restate/hooks/$hook"
done
test -f /usr/share/doc/restate/copyright
test -n "$(find /usr/share/doc/restate -name 'changelog*' -print -quit)"

# It runs, says what it is, and does its work.
restate --version
restate --help > /dev/null
mkdir -p /tmp/tree/etc /tmp/tree/home/pat
echo 'hello' > /tmp/tree/etc/motd
echo 'notes' > /tmp/tree/home/pat/notes.txt
restate capture --root /tmp/tree -o /tmp/tree.tar
restate verify --root /tmp/tree /tmp/tree.tar
mkdir -p /tmp/back
restate restore --allow-unverified --root /tmp/back /tmp/tree.tar
cmp /tmp/tree/home/pat/notes.txt /tmp/back/home/pat/notes.txt
restate packages > /dev/null

# And it goes away cleanly.
apt-get remove -y -qq restate
test ! -e /usr/sbin/restate
test ! -e /usr/libexec/restate/hooks/postgresql
echo VERIFIED
