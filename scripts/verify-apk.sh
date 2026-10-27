#!/bin/sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Installs the restate Alpine package in DIR on a clean Alpine, as root, uses
# it and removes it again:
#
#   scripts/verify-apk.sh DIR
#
# Meant for a throwaway container of the Alpine release the package was built
# on, as the release workflow runs it before a release:
#
#   docker run --rm -v "$PWD/dist:/packages:ro" -v "$PWD/scripts:/s:ro" \
#     alpine:3.24 sh /s/verify-apk.sh /packages
#
# What it proves is the package, not the program -- the tests do that: that
# apk installs it with what it depends on, that it puts the program, the
# manual and the hooks where the program looks for them, and that it removes
# cleanly. As verify-deb.sh and verify-rpm.sh do for theirs.
set -eux

DIR="${1:?usage: verify-apk.sh DIR}"
APK="$(find "$DIR" -name 'restate-[0-9]*.apk' | head -1)"
DOC="$(find "$DIR" -name 'restate-doc-*.apk' | head -1)"
test -f "$APK" && test -f "$DOC"

# mandoc to look the manual up as a user would. Not signed by Alpine's means:
# the release's checksums and attestation vouch for it.
apk add -q mandoc
apk add -q --allow-untrusted "$APK" "$DOC"
apk info -e restate
apk info -L restate

test -x /usr/sbin/restate
test -x /usr/bin/gpgv
man -w restate
for hook in postgresql mysql mongodb redis libvirt lxd docker; do
  test -x "/usr/libexec/restate/hooks/$hook"
done
# restate runs only hooks root owns and no one else may write.
test -z "$(find /usr/sbin/restate /usr/libexec/restate \( ! -user 0 -o -perm -020 -o -perm -002 \) -print)"
test -d /etc/restate/jobs.d

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

apk del -q restate restate-doc
test ! -e /usr/sbin/restate
test ! -e /usr/libexec/restate/hooks/postgresql
echo VERIFIED
