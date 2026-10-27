#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Installs the restate RPM in DIR on a clean Fedora, EL or openSUSE, as root,
# uses it and removes it again:
#
#   scripts/verify-rpm.sh DIR
#
# Meant for a throwaway container of the distribution the package was built
# on, as the release workflow runs it before anything reaches COPR or the
# openSUSE Build Service:
#
#   docker run --rm -v "$PWD/dist:/packages:ro" -v "$PWD/scripts:/s:ro" \
#     fedora:latest sh /s/verify-rpm.sh /packages
#
# What it proves is the package, not the program -- the tests do that: that
# dnf or zypper installs it with what it depends on, that it puts the
# program, the manual and the hooks where the program looks for them, and
# that it removes cleanly. As verify-deb.sh does for the .deb.
set -eux

DIR="${1:?usage: verify-rpm.sh DIR}"
# By glob: a bare image has no find until the tools below are installed.
RPM=""
for f in "$DIR"/restate-*.rpm; do
  case "$f" in
    *.src.rpm) ;;
    *) RPM="$f" && break ;;
  esac
done
test -f "$RPM"

# The package manager, as installing from COPR or OBS would use it: it
# resolves what the package depends on. The package itself is not signed --
# the release's checksums and attestation vouch for it -- and COPR and OBS
# sign their own builds.
if command -v dnf > /dev/null 2>&1; then
  # The images keep no documentation, to stay small; the manual is checked.
  sed -i '/^tsflags=nodocs/d' /etc/dnf/dnf.conf 2> /dev/null || true
  # man-db to look the manual up as a user would; find and cmp for the
  # checks below. Nothing restate itself needs: the install has to bring that.
  dnf install -y -q man-db findutils diffutils
  dnf install -y -q "$RPM"
  remove() { dnf remove -y -q restate; }
elif command -v zypper > /dev/null 2>&1; then
  # Leap says so in zypp.conf; Tumbleweed in a drop-in under /usr/etc, which
  # one of the same name under /etc replaces.
  sed -i 's/^rpm.install.excludedocs.*/rpm.install.excludedocs = no/' /etc/zypp/zypp.conf || true
  if [ -f /usr/etc/zypp/zypp.conf.d/excludedocs.conf ]; then
    mkdir -p /etc/zypp/zypp.conf.d
    printf '[main]\nrpm.install.excludedocs = no\n' > /etc/zypp/zypp.conf.d/excludedocs.conf
  fi
  zypper --non-interactive install -y man findutils diffutils
  zypper --non-interactive install -y --allow-unsigned-rpm "$RPM"
  remove() { zypper --non-interactive remove -y restate; }
else
  echo "neither dnf nor zypper" >&2
  exit 1
fi
rpm -q restate
rpm -ql restate

test -x /usr/sbin/restate
command -v gpgv
test -n "$(find /usr/share/man/man8 -name 'restate.8*' -print -quit)"
man -w restate
for hook in postgresql mysql mongodb redis libvirt lxd docker; do
  test -x "/usr/libexec/restate/hooks/$hook"
done
# restate runs only hooks root owns and no one else may write.
test -z "$(find /usr/sbin/restate /usr/libexec/restate \( ! -user 0 -o -perm -020 -o -perm -002 \) -print)"
test -d /etc/restate/jobs.d
test -f /usr/lib/systemd/system/restate-job@.service
# /usr/bin on Fedora 42 and later, where sbin is bin; /usr/sbin elsewhere.
grep -Eq '^ExecStart=/usr/s?bin/restate ' /usr/lib/systemd/system/restate-job@.service

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

remove
test ! -e /usr/sbin/restate
test ! -e /usr/libexec/restate/hooks/postgresql
echo VERIFIED
