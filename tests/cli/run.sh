#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# End-to-end tests: the built binary, run the way a person or a script runs it.
#
#   tests/cli/run.sh ./bin/restate
#
# The unit tests check the parts; these check the promises the manpage makes
# about the whole -- the exit statuses, what goes to stdout and what to stderr,
# the mode an image is created with, that it is a real tarball whose first
# member is the index, that the walk does not follow a symlink.
#
# Written for every system restate builds on: no GNU-only flags, and the one
# thing that differs everywhere (reading a file's mode) goes through file_mode.
set -uo pipefail

BIN="${1:?usage: run.sh BINARY}"
case "$BIN" in
  /*) ;;
  *) BIN="$PWD/$BIN" ;;
esac
[ -x "$BIN" ] || { echo "run.sh: $BIN is not executable" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/restate-cli.XXXXXX")" || exit 2
trap 'chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
cd "$WORK" || exit 2

# A fixed creation time, so the indexes are comparable run to run.
export SOURCE_DATE_EPOCH=1700000000

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); printf '  \033[91mFAIL\033[0m %s\n' "$*"; }

# expect STATUS DESCRIPTION -- COMMAND...
# Runs the command with stdout and stderr captured in $OUT and $ERR.
expect() {
  local want="$1" what="$2"
  shift 3
  "$@" > out.txt 2> err.txt < /dev/null
  local got=$?
  OUT="$(cat out.txt)"
  ERR="$(cat err.txt)"
  if [ "$got" -eq "$want" ]; then
    ok
  else
    fail "$what: exit $got, wanted $want"
    sed 's/^/        /' err.txt | head -5
  fi
}

contains() {
  local haystack="$1" needle="$2" what="$3"
  case "$haystack" in
    *"$needle"*) ok ;;
    *) fail "$what: no \"$needle\" in output"; printf '%s\n' "$haystack" | head -5 | sed 's/^/        /' ;;
  esac
}

lacks() {
  local haystack="$1" needle="$2" what="$3"
  case "$haystack" in
    *"$needle"*) fail "$what: unexpected \"$needle\" in output" ;;
    *) ok ;;
  esac
}

# check DESCRIPTION COMMAND... -- passes when the command succeeds.
check() {
  local what="$1"
  shift
  if "$@"; then
    ok
  else
    fail "$what"
  fi
}

# part IMAGE NAME -- one part of an image, on standard output. Not tar -O,
# which OpenBSD's tar does not have: the outer archive is plain tar, so the
# part is unpacked into a directory of its own and read from there.
part() {
  local d
  d="$(mktemp -d "$WORK/part.XXXXXX")" || return 1
  ( cd "$d" && tar -xf "$WORK/$1" "restate/$2" ) && cat "$d/restate/$2"
  local status=$?
  rm -rf "$d"
  return "$status"
}

# refute DESCRIPTION COMMAND... -- passes when the command fails.
refute() {
  local what="$1"
  shift
  if "$@"; then
    fail "$what"
  else
    ok
  fi
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

# A file's inode number: GNU stat, or the BSDs'.
inode() {
  stat -c '%i' "$1" 2>/dev/null || stat -f '%i' "$1"
}

build_tree() {
  rm -rf tree
  mkdir -p tree/etc/ssh tree/usr/bin tree/tmp tree/var/cache/apt tree/var/lib/app tree/home/u/.cache
  printf 'Port 22\n' > tree/etc/ssh/sshd_config
  printf 'web01\n' > tree/etc/hostname
  printf '#!/bin/sh\n' > tree/usr/bin/tool
  chmod 755 tree/usr/bin/tool
  printf 'scratch\n' > tree/tmp/scratch
  printf 'pkg\n' > tree/var/cache/apt/pkg.deb
  printf 'data\n' > tree/var/lib/app/db
  printf '4242\n' > tree/var/lib/app/app.pid
  printf 'thumb\n' > tree/home/u/.cache/thumb
  printf 'notes\n' > "tree/home/u/with space"
  printf 'odd\n' > "tree/home/u/tab	name"
  ln -s ../etc/hostname tree/home/u/link
  # A symlink to a directory outside the tree: the walk must record it and
  # must not go through it.
  mkdir -p outside
  printf 'secret\n' > outside/secret
  ln -s "$WORK/outside" tree/home/u/escape
  mkfifo tree/home/u/fifo
}

printf '\n\033[1mEnd-to-end tests\033[0m \033[2m(%s)\033[0m\n' "$BIN"

# ---------------------------------------------------------------------------
# The basics
# ---------------------------------------------------------------------------
expect 0 "--version" -- "$BIN" --version
contains "$OUT" "restate " "--version names the program"
contains "$OUT" "Copyright (c)" "--version carries the copyright"
expect 0 "--help" -- "$BIN" --help
contains "$OUT" "Usage: restate" "--help"
contains "$OUT" "Exit status:" "--help documents the exit statuses"
expect 0 "-h" -- "$BIN" -h
expect 2 "no command" -- "$BIN"
contains "$ERR" "no command given" "no command"
contains "$ERR" "Try 'restate --help'" "the usage hint"
check "a usage error wrote nothing to stdout" test -z "$OUT"
expect 2 "an unknown command" -- "$BIN" frobnicate
contains "$ERR" 'unknown command "frobnicate"' "unknown command"
expect 2 "an unknown option" -- "$BIN" --frobnicate scan
expect 2 "a missing option argument" -- "$BIN" scan --root
contains "$ERR" "--root needs an argument" "missing argument names the long option"
expect 2 "a wrong argument count" -- "$BIN" diff only-one
expect 2 "--os with an unknown system" -- "$BIN" --os=plan9 rules

# ---------------------------------------------------------------------------
# scan: the index alone
# ---------------------------------------------------------------------------
build_tree
expect 0 "scan to stdout" -- "$BIN" scan --root=tree --os=linux
contains "$OUT" '"format": "restate-index"' "scan writes an index"
contains "$OUT" '"content": "none"' "an index alone holds no content"
contains "$OUT" '"path": "/etc/ssh/sshd_config", "name": "sshd_config", "type": "file", "class": "state"' \
  "state is recorded, with its name and class"
contains "$OUT" '"path": "/usr/bin", "name": "bin", "type": "directory", "class": "baseline"' \
  "baseline is recorded, classified"
contains "$OUT" '"sha256": "' "files carry a digest"
contains "$OUT" '"atime": "' "access times are recorded"
contains "$OUT" '"btime": ' "birth times are recorded, or null"
contains "$OUT" '"user": "' "owner names are recorded"
contains "$OUT" '"inode": ' "inodes are recorded"
contains "$OUT" '/home/u/with space' "a name with a space"
contains "$OUT" '/home/u/tab\tname' "a tab in a name is a JSON escape"
contains "$OUT" '"target": "../etc/hostname"' "a symlink's target"
contains "$OUT" "\"target\": \"$WORK/outside\"" "a symlink out of the tree is recorded"
lacks "$OUT" "secret" "the walk does not follow a symlink"
contains "$OUT" '"type": "fifo"' "a FIFO is recorded"
lacks "$OUT" "/tmp/scratch" "ephemeral paths are skipped"
lacks "$OUT" "/var/cache" "expendable paths are skipped"
lacks "$OUT" ".cache/thumb" "per-user caches are skipped"
lacks "$OUT" "app.pid" "PID files are skipped"
contains "$ERR" "recorded" "the summary goes to stderr"
lacks "$OUT" "recorded" "the summary does not go to stdout"
if command -v python3 > /dev/null 2>&1; then
  check "the index is valid JSON to another parser" \
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["count"] == len(d["entries"])' \
    < out.txt
fi

lacks "$OUT" '"machine"' "a tree that is not the live root gets no machine description"

# ---------------------------------------------------------------------------
# machine
# ---------------------------------------------------------------------------
expect 0 "machine" -- "$BIN" machine
contains "$OUT" '"system": {' "machine describes the system"
contains "$OUT" '"hardware": {' "machine describes the hardware"
contains "$OUT" '"kernel_name": "' "machine names the kernel"
if command -v python3 > /dev/null 2>&1; then
  check "the machine description is valid JSON" \
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert "system" in d' < out.txt
fi
expect 0 "machine -o" -- "$BIN" machine -o machine.json
check "machine -o writes the file" test -s machine.json
check "and it is private" test "$(file_mode machine.json)" = "600"

# ---------------------------------------------------------------------------
# packages
# ---------------------------------------------------------------------------
mkdir -p pkgtree/var/lib/dpkg pkgtree/etc/apt pkgtree/var/lib/apt/lists
cat > pkgtree/var/lib/dpkg/status <<'DPKG'
Package: hello
Status: install ok installed
Architecture: amd64
Version: 2.10-3

Package: by-hand
Status: install ok installed
Architecture: amd64
Version: 1.0
DPKG
echo 'deb [signed-by=/etc/apt/k.gpg] http://deb.example.com/debian stable main' \
  > pkgtree/etc/apt/sources.list
printf 'key' > pkgtree/etc/apt/k.gpg
printf 'Package: hello\nArchitecture: amd64\nVersion: 2.10-3\n' \
  > pkgtree/var/lib/apt/lists/deb.example.com_debian_dists_stable_main_binary-amd64_Packages
expect 0 "packages" -- "$BIN" packages --root pkgtree
contains "$OUT" '"name": "hello"' "packages lists what dpkg installed"
contains "$OUT" '"http://deb.example.com/debian stable/main"' "and where it came from"
contains "$OUT" '"unavailable": "local"' "and what no repository has"
contains "$OUT" '"path": "/etc/apt/k.gpg"' "and the key the repository is signed with"
if command -v gpgv > /dev/null 2>&1; then
  contains "$OUT" '"problem": "http://deb.example.com/debian stable: apt has no index of it' \
    "and that apt cannot use it"
fi
if command -v python3 > /dev/null 2>&1; then
  check "the inventory is valid JSON" \
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["apt"]["count"] == 2' < out.txt
fi
expect 0 "packages -o" -- "$BIN" packages --root pkgtree -o packages.json
check "packages -o writes the file" test -s packages.json
expect 0 "scan records the inventory" -- "$BIN" scan --root pkgtree -o pkgindex.json
expect 0 "packages IMAGE" -- "$BIN" packages pkgindex.json
contains "$OUT" '"name": "by-hand"' "packages reads the inventory back from an index"
mkdir -p pkgtree/var/cache/apt/archives
printf 'deb' > pkgtree/var/cache/apt/archives/by-hand_1.0_amd64.deb
cat >> pkgtree/var/lib/dpkg/status <<'DPKG'

Package: vanished
Status: install ok installed
Architecture: amd64
Version: 2.0
DPKG
expect 0 "capture --keep-local-packages" -- \
  "$BIN" capture --root pkgtree --keep-local-packages -o kept.tar
contains "$ERR" "vanished 2.0 is not in /var/cache/apt/archives" "a package not in apt's cache is warned of"
contains "$ERR" "dpkg-repack vanished" "with how to rebuild it"
# Its one source has no index apt fetched, and a key that is not one: apt
# cannot use it, which capture says -- or says it could not check, where
# gpgv is not installed.
case "$ERR" in
  *"gpgv is not installed: apt's sources were not checked"*) ok ;;
  *) contains "$ERR" "apt cannot use a source in /etc/apt/sources.list -- http://deb.example.com/debian stable: apt has no index of it" \
       "a source apt cannot use is warned of" ;;
esac
check "the kept .deb is in the image, though /var/cache is left out" \
  eval 'part kept.tar files.tar.gz | gzip -dc | tar -tf - | grep -qx "restate/files/var/cache/apt/archives/by-hand_1.0_amd64.deb"'
check "and nothing else of /var/cache" \
  eval '! part kept.tar files.tar.gz | gzip -dc | tar -tf - | grep -v by-hand_1.0_amd64.deb | grep -q "var/cache/apt/archives/"'
check "the kit holds it, and /etc/apt" \
  eval 'part kept.tar kit.tar.gz | gzip -dc | tar -tf - | tr "\n" " " | grep -q "restate/files/etc/apt/sources.list .*restate/files/var/cache/apt/archives/by-hand_1.0_amd64.deb"'
check "and nothing else" \
  eval '! part kept.tar kit.tar.gz | gzip -dc | tar -tf - | grep -v -e etc/apt -e by-hand | grep -q .'
expect 0 "verify the image with kept packages" -- "$BIN" verify --root pkgtree kept.tar
lacks "$OUT" "by-hand_1.0_amd64.deb" "verify walks what the image kept, and finds it unchanged"
expect 0 "packages of the image" -- "$BIN" packages kept.tar
contains "$OUT" '"kept": "/var/cache/apt/archives/by-hand_1.0_amd64.deb"' "the inventory says what it kept"
expect 2 "autoinstall --image-at a relative path" -- "$BIN" autoinstall --image-at x.tar
contains "$ERR" "not an absolute path" "--image-at has to be absolute"
printf '{"format": "restate-index", "version": 1, "entries": []}' > old-index.json
expect 2 "packages of an old index" -- "$BIN" packages old-index.json
contains "$ERR" "has no package inventory" "an index from before the inventory says so"
expect 2 "packages of a missing file" -- "$BIN" packages no-such-index.json

# Files checked against the packages that installed them: dpkg's digests.
mkdir -p debtree/var/lib/dpkg/info debtree/usr/bin debtree/etc
printf 'Package: hello\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n' \
  > debtree/var/lib/dpkg/status
printf 'Conffiles:\n /etc/hello.conf f968f33f844c98de1d3b4fe70f2e1a0f\n' >> debtree/var/lib/dpkg/status
printf 'a723176f804503c15766073170b99298  usr/bin/hello\n' > debtree/var/lib/dpkg/info/hello.md5sums
printf '/usr/bin/hello\n/etc/hello.conf\n' > debtree/var/lib/dpkg/info/hello.list
printf 'hello-binary' > debtree/usr/bin/hello
printf 'x=2\n' > debtree/etc/hello.conf
printf 'mine' > debtree/usr/bin/by-hand
expect 0 "scan a Debian tree" -- "$BIN" scan --root debtree --os=linux -o deb.json
contains "$ERR" "1 files as their packages installed them; 1 changed since, and 1 where only packages put files that no package did, kept" \
  "each file is checked against its package"
contains "$(grep '"/usr/bin/hello"' deb.json)" '"class": "baseline"' "an unchanged one is its package's"
contains "$(grep '"/etc/hello.conf"' deb.json)" '"modified": true' "an edited conffile is marked"
contains "$(grep '"/usr/bin/by-hand"' deb.json)" '"class": "state"' "a file no package installed is state"
expect 0 "scan --rules-only" -- "$BIN" scan --root debtree --os=linux --rules-only -o deb2.json
lacks "$ERR" "as their packages installed them" "--rules-only checks nothing against the packages"
contains "$(grep '"/usr/bin/by-hand"' deb2.json)" '"class": "baseline"' "and classifies by the rules alone"

# ---------------------------------------------------------------------------
# installer
# ---------------------------------------------------------------------------
cat > ubuntu.json <<'JSON'
{"system": {"id": "ubuntu", "version_id": "26.04", "version": "26.04.1 LTS (Resolute Raccoon)",
            "pretty_name": "Ubuntu 26.04.1 LTS", "hostname": "builder",
            "architecture": "aarch64", "type": "server", "type_evidence": "no desktop is installed"}}
JSON
expect 0 "installer for a described machine" -- "$BIN" installer ubuntu.json
contains "$OUT" "installer   Ubuntu 26.04 Server for arm64" "installer names the image"
contains "$OUT" "for         builder (Ubuntu 26.04.1 LTS)" "installer names the machine"
contains "$OUT" "because     this is a server: no desktop is installed" "installer says why"
contains "$OUT" "https://cdimage.ubuntu.com/releases/26.04/release/" "arm64 comes from cdimage"
contains "$OUT" "ubuntu-26.04[.N]-live-server-arm64.iso -- 26.04.1" "installer names the file"
contains "$OUT" "8439 38DF 228D 22F7 B374  2BC0 D94A A3F0 EFE2 1092" "installer shows the pinned key"
contains "$OUT" "restate installer fetch ubuntu.json" "installer says how to fetch it"
printf '{"system": {"id": "openbsd", "version_id": "7.8"}}\n' > openbsd.json
expect 2 "installer for an unsupported system" -- "$BIN" installer openbsd.json
contains "$ERR" "installers for openbsd are not supported yet" "installer says what is unsupported"
expect 2 "installer for a missing description" -- "$BIN" installer no-such.json
expect 2 "installer with two descriptions" -- "$BIN" installer ubuntu.json ubuntu.json
# A fetch needs curl and gpgv; without them it fails differently.
have() { [ -x "/usr/bin/$1" ] || [ -x "/usr/local/bin/$1" ] || [ -x "/bin/$1" ]; }
if have curl && have gpgv; then
  expect 2 "installer fetch from a mirror that is not there" -- \
    "$BIN" installer fetch ubuntu.json --mirror=file:///nonexistent/mirror --cache=cache -q
  contains "$ERR" "could not download" "a failed fetch says why"
  refute "a failed fetch leaves no image" ls cache/ubuntu/26.04/*.iso > /dev/null 2>&1
fi
expect 2 "installer --mirror must be https or file" -- \
  "$BIN" installer fetch ubuntu.json --mirror=http://mirror.example.invalid/

# ---------------------------------------------------------------------------
# buildsheet and autoinstall
# ---------------------------------------------------------------------------
cat > layout.json <<'JSON'
{"system": {"id": "ubuntu", "version_id": "26.04", "version": "26.04.1 LTS", "hostname": "db01",
            "architecture": "x86_64", "type": "server", "locale": "en_US.UTF-8"},
 "hardware": {"cpus": 2, "memory": 4294967296},
 "firmware": {"mode": "uefi"},
 "disks": [{"name": "sda", "size": 21474836480, "logical_block_size": 512,
            "table": {"type": "gpt", "uuid": "t-uuid"},
            "partitions": [
              {"name": "sda1", "number": 1, "start": 1048576, "size": 536870912,
               "type": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
               "content": {"type": "vfat", "usage": "filesystem", "uuid": "AAAA-BBBB"}},
              {"name": "sda2", "number": 2, "start": 537919488, "size": 20000000000,
               "type": "0fc63daf-8483-4772-8e79-3d69d8477de4",
               "content": {"type": "ext4", "usage": "filesystem", "uuid": "root-uuid"}}]}],
 "mounts": [{"mountpoint": "/", "source": "/dev/sda2", "size": 19000000000, "used": 3000000000}],
 "fstab": [{"spec": "UUID=root-uuid", "file": "/", "type": "ext4", "options": "errors=remount-ro"},
           {"spec": "UUID=AAAA-BBBB", "file": "/boot/efi", "type": "vfat", "options": "umask=0077"}]}
JSON
expect 0 "buildsheet for a described machine" -- "$BIN" buildsheet layout.json
contains "$OUT" "restate build sheet: db01" "buildsheet names the machine"
contains "$OUT" "sda2 : start=1050624, size=39062500" "buildsheet keeps the exact sectors"
contains "$OUT" "mkfs.ext4 -F -U root-uuid" "buildsheet keeps the filesystem UUID"
contains "$OUT" "Custom storage layout" "buildsheet says how to drive the installer"
contains "$OUT" "tar -xOf layout.json restate/files.tar.gz" "buildsheet says how to restore"
expect 0 "buildsheet --target=vm" -- "$BIN" buildsheet --target=vm layout.json -o sheet.txt
check "buildsheet -o writes the file" test -s sheet.txt
contains "$(cat sheet.txt)" "virt-install --name db01" "a VM build sheet defines the VM"
contains "$(cat sheet.txt)" "--disk size=7," "the VM disk is sized to what is used"
# Sized from what an index records, not from how full the old disk was: 4 GiB
# of files on / (the /srv one belongs to its own mount) makes a 7 GiB volume,
# where the old disk's 90 GB of use would have made a 115 GiB one.
cat > captured.json <<'JSON'
{"format": "restate-index", "version": 1, "root": "/", "hashed": false, "content": "none",
 "machine": {"system": {"id": "ubuntu", "version_id": "26.04", "kernel_name": "Linux"},
   "firmware": {"mode": "uefi"},
   "disks": [{"name": "sda", "size": 107374182400, "table": {"type": "gpt"},
     "partitions": [{"name": "sda1", "number": 1, "start": 1048576, "size": 100000000000,
       "type": "0fc63daf-8483-4772-8e79-3d69d8477de4",
       "content": {"type": "ext4", "usage": "filesystem", "uuid": "r"}}]}],
   "mounts": [{"mountpoint": "/", "source": "/dev/sda1", "size": 99000000000, "used": 90000000000},
              {"mountpoint": "/srv", "source": "/dev/sdz9", "size": 1, "used": 1}]},
 "entries": [
{"path": "/", "name": "/", "type": "directory", "class": "state", "mode": "0755", "uid": 0, "gid": 0, "size": 0, "mtime": "2026-10-05T00:00:00.000000000Z"},
{"path": "/etc", "name": "etc", "type": "directory", "class": "state", "mode": "0755", "uid": 0, "gid": 0, "size": 0, "mtime": "2026-10-05T00:00:00.000000000Z"},
{"path": "/etc/big", "name": "big", "type": "file", "class": "state", "mode": "0644", "uid": 0, "gid": 0, "size": 4294967296, "mtime": "2026-10-05T00:00:00.000000000Z"},
{"path": "/srv", "name": "srv", "type": "directory", "class": "state", "mode": "0755", "uid": 0, "gid": 0, "size": 0, "mtime": "2026-10-05T00:00:00.000000000Z"},
{"path": "/srv/x", "name": "x", "type": "file", "class": "state", "mode": "0644", "uid": 0, "gid": 0, "size": 1073741824, "mtime": "2026-10-05T00:00:00.000000000Z"}
]}
JSON
expect 0 "buildsheet --target=vm from an index" -- "$BIN" buildsheet --target=vm captured.json
contains "$OUT" "vda1 : size=7168MiB" "a VM volume is sized from what the index records"
contains "$OUT" "--disk size=8," "and so is the VM's disk"

expect 2 "--target must be vm or metal" -- "$BIN" buildsheet --target=cloud layout.json
contains "$ERR" "--target: \"cloud\" is not vm or metal" "--target says what it takes"
expect 2 "buildsheet without disks" -- "$BIN" buildsheet ubuntu.json
contains "$ERR" "no disks to rebuild" "buildsheet says why it cannot"
expect 2 "buildsheet of a missing description" -- "$BIN" buildsheet no-such.json
expect 0 "autoinstall for a described machine" -- "$BIN" autoinstall layout.json
contains "$OUT" "#cloud-config" "autoinstall is cloud-config"
contains "$OUT" "        uuid: \"root-uuid\"" "autoinstall keeps the filesystem UUID"
if command -v python3 > /dev/null 2>&1 && python3 -c 'import yaml' 2> /dev/null; then
  check "the autoinstall file is valid YAML" \
    python3 -c 'import sys, yaml; assert "autoinstall" in yaml.safe_load(sys.stdin)' < out.txt
fi
expect 0 "autoinstall --target=metal" -- "$BIN" autoinstall --target=metal layout.json
contains "$OUT" "size: largest" "autoinstall on new hardware picks the largest disk"
expect 2 "autoinstall for another system" -- "$BIN" autoinstall openbsd.json
contains "$ERR" "autoinstall files are for Ubuntu" "autoinstall says what it is for"

expect 0 "scan --all" -- "$BIN" scan -r tree --os=linux --all -q
contains "$OUT" '"class": "expendable"' "--all records expendable paths"
contains "$OUT" "/var/cache/apt/pkg.deb" "--all records the cache"
check "--quiet writes nothing to stderr" test -z "$ERR"

expect 0 "scan --progress" -- "$BIN" scan -r tree --os=linux -P -q -o progress.json
contains "$ERR" "restate: walking" "--progress reports the walk"
lacks "$ERR" "recorded" "--progress does not undo --quiet's silence"
expect 0 "scan without --progress" -- "$BIN" scan -r tree --os=linux -q -o progress.json
lacks "$ERR" "walking" "progress is off unless asked for"

expect 0 "scan --no-hash" -- "$BIN" scan -r tree --os=linux -n -q
contains "$OUT" '"hashed": false' "--no-hash says so"
lacks "$OUT" '"sha256": "' "--no-hash writes no digests"

expect 0 "scan -v" -- "$BIN" scan -r tree --os=linux -v
contains "$ERR" "skipped /tmp (ephemeral)" "--verbose names skipped paths"

expect 0 "scan -o" -- "$BIN" scan -r tree --os=linux -o m1.json -q
check "scan -o writes the file" test -f m1.json
check "the index is mode 600, not $(file_mode m1.json)" test "$(file_mode m1.json)" = "600"
refute "no temporary file is left behind" ls m1.json.?????? > /dev/null 2>&1

expect 2 "scan a missing root" -- "$BIN" scan -r nonexistent
expect 2 "scan into a missing directory" -- "$BIN" scan -r tree -o no/such/dir/m
refute "a failed scan creates no output" test -e no

# ---------------------------------------------------------------------------
# capture: the image
# ---------------------------------------------------------------------------
expect 2 "capture with no -o" -- "$BIN" capture -r tree
contains "$ERR" "give one with -o" "capture needs a file"
expect 0 "capture" -- "$BIN" capture -r tree --os=linux -o img1.tar
contains "$ERR" "kept the content of" "the capture summary"
check "the image is mode 600" test "$(file_mode img1.tar)" = "600"
tar -tf img1.tar > parts.txt 2>/dev/null
check "the image is three parts, the index first" \
  test "$(tr '\n' ' ' < parts.txt)" = "restate/index.json.gz restate/kit.tar.gz restate/files.tar.gz "
# Called through check.
# shellcheck disable=SC2317,SC2329
parts_are_gzip() {
  local p
  for p in index.json.gz kit.tar.gz files.tar.gz; do
    part img1.tar "$p" | gzip -t || return 1
  done
}
check "each part is gzip" parts_are_gzip
part img1.tar files.tar.gz | gzip -dc | tar -tf - > members.txt 2>/dev/null
contains "$(cat members.txt)" "restate/files/etc/ssh/sshd_config" "state content is in the image"
lacks "$(cat members.txt)" "restate/files/usr/bin/tool" "baseline content is not, by default"
expect 0 "capture --baseline-content" -- "$BIN" capture -r tree --os=linux -B -q -o img-b.tar
part img-b.tar files.tar.gz | gzip -dc | tar -tf - > members-b.txt 2>/dev/null
contains "$(cat members-b.txt)" "restate/files/usr/bin/tool" "-B keeps baseline content too"
expect 0 "capture again" -- "$BIN" capture -r tree --os=linux -q -o img2.tar

# The image is also plain tar: system tar restores it by hand.
mkdir -p unpacked
part img1.tar files.tar.gz | ( cd unpacked && gzip -dc | tar -xf - ) 2>/dev/null
check "system tar restores a file's content" \
  cmp tree/etc/ssh/sshd_config unpacked/restate/files/etc/ssh/sshd_config
chmod 640 tree/etc/hostname
expect 0 "capture after a mode change" -- "$BIN" capture -r tree --os=linux -q -o img-m.tar
mkdir -p unpacked-m
part img-m.tar files.tar.gz | ( cd unpacked-m && gzip -dc | tar -xpf - ) 2>/dev/null
check "and its mode" test "$(file_mode unpacked-m/restate/files/etc/hostname)" = "640"
check "and a symlink" test -L unpacked/restate/files/home/u/link

# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------
mkdir -p rtree/etc/app rtree/home/u rtree/var/lib/x
echo "127.0.0.1 localhost" > rtree/etc/hosts
printf 'secret\n' > rtree/etc/app/key
chmod 600 rtree/etc/app/key
chmod 750 rtree/etc/app
echo doc > "rtree/home/u/with space"
ln -s ../../etc/hosts rtree/home/u/link
echo shared > rtree/var/lib/x/one
ln rtree/var/lib/x/one rtree/var/lib/x/two
expect 0 "capture for restore" -- "$BIN" capture -r rtree --os=linux -q -o rimg.tar

mkdir -p rout
expect 0 "restore" -- "$BIN" restore --allow-unverified --root rout rimg.tar
contains "$ERR" "put back 5 files" "restore says what it put back"
check "the content is back" cmp rtree/etc/app/key rout/etc/app/key
check "and its mode" test "$(file_mode rout/etc/app/key)" = "600"
check "and a directory's mode" test "$(file_mode rout/etc/app)" = "750"
check "and a symlink" test "$(readlink rout/home/u/link)" = "../../etc/hosts"
check "and a hard link is a link" test "$(inode rout/var/lib/x/one)" = "$(inode rout/var/lib/x/two)"
expect 0 "verify finds the restored tree the same" -- "$BIN" verify --root rout rimg.tar
# What differs, if anything does: verify lists it on standard output.
[ -z "$OUT" ] || printf '%s\n' "$OUT" | head -5 | sed 's/^/        verify: /'
contains "$ERR" "0 added, 0 deleted, 0 modified" "nothing differs"

mkdir -p rdry
expect 0 "restore --dry-run" -- "$BIN" restore --allow-unverified --dry-run --root rdry rimg.tar
contains "$OUT" "would restore /etc/app/key" "a dry run says what it would do"
check "and writes nothing" test -z "$(ls -A rdry)"

mkdir -p rex
expect 0 "restore --exclude" -- "$BIN" restore --allow-unverified --root rex --exclude /etc/app rimg.tar
check "leaves the excluded path out" test ! -e rex/etc/app
check "and everything beneath it" test ! -e rex/etc/app/key
check "but restores the rest" test -f rex/etc/hosts
contains "$ERR" "left out 2 paths" "and says what it left out"

# A symlink where a directory should be is replaced, not followed.
mkdir -p rtrap elsewhere
ln -s "$WORK/elsewhere" rtrap/etc
expect 0 "restore over a planted symlink" -- "$BIN" restore --allow-unverified --root rtrap rimg.tar
check "the symlink did not lead out" test -z "$(ls -A elsewhere)"
check "a directory is there instead" test -d rtrap/etc -a ! -L rtrap/etc

# A tampered file: the index says one thing, the files part another.
mkdir -p tamper && ( cd tamper && tar -xf ../rimg.tar && gzip -dc restate/files.tar.gz > files.tar &&
  sed 's/secret/SECRET/' files.tar > tampered.tar && gzip -c tampered.tar > restate/files.tar.gz &&
  tar -cf ../rbad.tar restate/index.json.gz restate/kit.tar.gz restate/files.tar.gz )
mkdir -p rbad
expect 3 "restore a tampered image" -- "$BIN" restore --allow-unverified --root rbad rbad.tar
contains "$ERR" "/etc/app/key: its content is not what the index says it is; not put back" \
  "a file that does not match its digest is refused"
check "and never lands" test ! -e rbad/etc/app/key
check "while the rest is put back" test -f rbad/etc/hosts

# A files part that runs on past its end-of-archive blocks, as some tars
# pad it -- more than a pipe holds: read to its end, not gzip killed.
mkdir -p padded && ( cd padded && tar -xf ../rimg.tar && gzip -dc restate/files.tar.gz > files.tar &&
  dd if=/dev/zero bs=1024 count=512 >> files.tar 2> /dev/null &&
  gzip -c files.tar > restate/files.tar.gz &&
  tar -cf ../rpad.tar restate/index.json.gz restate/kit.tar.gz restate/files.tar.gz )
mkdir -p rpad
expect 0 "restore an image padded past its end" -- "$BIN" restore --allow-unverified --root rpad rpad.tar
check "puts its files back" cmp rtree/etc/app/key rpad/etc/app/key

# A member the index does not list.
mkdir -p extra/restate/files/etc && echo evil > extra/restate/files/etc/evil
( cd tamper && gzip -dc ../tamper/restate/files.tar.gz > /dev/null; tar -xf ../rimg.tar &&
  gzip -dc restate/files.tar.gz > clean.tar && tar -rf clean.tar -C ../extra restate/files/etc/evil &&
  gzip -c clean.tar > restate/files.tar.gz &&
  tar -cf ../rextra.tar restate/index.json.gz restate/kit.tar.gz restate/files.tar.gz )
mkdir -p rextra
expect 3 "restore an image with a member the index does not list" -- \
  "$BIN" restore --allow-unverified --root rextra rextra.tar
contains "$ERR" "/etc/evil: in the image, but not as the index records it; refused" \
  "a member the index does not list is refused"
check "and not written" test ! -e rextra/etc/evil

# Extended attributes: set with whatever this system sets them with, where
# its filesystem keeps them at all; captured, restored and verified.
mkdir -p xtree/etc xout
printf 'x' > xtree/etc/f
# Called through set_xattr below.
# shellcheck disable=SC2317,SC2329
set_xattr() {
  if command -v setfattr > /dev/null 2>&1; then
    setfattr -n user.color -v blue "$1"
  elif [ "$(uname -s)" = Darwin ]; then
    xattr -w user.color blue "$1"
  elif command -v setextattr > /dev/null 2>&1; then
    setextattr user color blue "$1"
  elif command -v python3 > /dev/null 2>&1; then
    python3 -c 'import os, sys; os.setxattr(sys.argv[1], "user.color", b"blue")' "$1"
  else
    return 1
  fi
}
if set_xattr xtree/etc/f 2> /dev/null; then
  expect 0 "capture a file with an extended attribute" -- "$BIN" capture -q --root xtree -o x.tar
  contains "$(part x.tar index.json.gz | gzip -dc | grep '"/etc/f"')" '"name": "user.color", "value": "Ymx1ZQ=="' \
    "the index records it"
  expect 0 "restore it" -- "$BIN" restore --allow-unverified --root xout x.tar
  expect 0 "verify finds the attribute put back" -- "$BIN" verify --root xout x.tar
  contains "$ERR" "0 added, 0 deleted, 0 modified" "and nothing differs"
  printf 'y' > xtree/etc/g
  set_xattr xtree/etc/g
  rm -f xtree/etc/f && printf 'x' > xtree/etc/f
  expect 1 "verify sees the attribute gone" -- "$BIN" verify --root xtree x.tar
  contains "$OUT" "xattrs" "and says it is the attributes that changed"
fi
# A file capability: root's to set, and cleared by a change of owner, so put
# back after it.
if [ "$(id -u)" = 0 ] && command -v setcap > /dev/null 2>&1 && command -v getcap > /dev/null 2>&1; then
  mkdir -p ctree/usr/local/bin cout
  printf '#!/bin/sh\n' > ctree/usr/local/bin/ping-ish
  if setcap cap_net_raw+ep ctree/usr/local/bin/ping-ish 2> /dev/null; then
    chown 1:1 ctree/usr/local/bin/ping-ish && setcap cap_net_raw+ep ctree/usr/local/bin/ping-ish
    expect 0 "capture a file with a capability" -- "$BIN" capture -q --root ctree -o c.tar
    expect 0 "restore it" -- "$BIN" restore --allow-unverified --root cout c.tar
    contains "$(getcap cout/usr/local/bin/ping-ish)" "cap_net_raw" "the capability is put back, after the owner"
  fi
fi

# Signed images: capture --sign-with, restate sign, and restore, verify and
# diff --trusted-key. A throwaway key, in a GnuPG home of the test's own.
if command -v gpg > /dev/null 2>&1 && command -v gpgv > /dev/null 2>&1; then
  mkdir -m 700 gnupg
  gk() { GNUPGHOME="$WORK/gnupg" gpg --batch --quiet --pinentry-mode loopback --passphrase '' "$@"; }
  gk --quick-gen-key 'restate test <signer@example.invalid>' ed25519 sign never 2> /dev/null
  gk --quick-gen-key 'someone else <other@example.invalid>' ed25519 sign never 2> /dev/null
  gk --export-secret-keys --armor signer@example.invalid > signer.sec 2> /dev/null
  gk --export signer@example.invalid > signer.pub 2> /dev/null
  gk --export --armor signer@example.invalid > signer.asc 2> /dev/null
  gk --export other@example.invalid > other.pub 2> /dev/null

  expect 0 "capture --sign-with" -- "$BIN" capture -r rtree --os=linux --sign-with signer.sec -o simg.tar
  contains "$ERR" "signed by restate test <signer@example.invalid>" "capture says who signed it"
  check "the image carries the signature, last" eval 'tar -tf simg.tar | tail -1 | grep -qx restate/index.sig'
  mkdir -p sout
  expect 0 "restore --trusted-key" -- "$BIN" restore --trusted-key signer.pub --root sout simg.tar
  contains "$ERR" "simg.tar is signed by restate test <signer@example.invalid>" "restore says who signed it"
  contains "$ERR" "captured on" "and where and when it was captured"
  check "and puts the files back" cmp rtree/etc/app/key sout/etc/app/key
  expect 0 "restore --trusted-key, the key armored" -- \
    "$BIN" restore --dry-run --trusted-key signer.asc --root sout simg.tar
  expect 4 "restore with no --trusted-key" -- "$BIN" restore --root sout simg.tar
  contains "$ERR" "no --trusted-key was given to check it against: not restoring it" "is refused"
  expect 4 "restore --trusted-key someone else's" -- \
    "$BIN" restore --trusted-key other.pub --root sout simg.tar
  contains "$ERR" "signed by a key that is not given" "is refused, naming the key"
  expect 0 "restore --allow-unverified, someone else's key" -- \
    "$BIN" restore --allow-unverified --trusted-key other.pub --dry-run --root sout simg.tar
  contains "$ERR" "restoring it anyway, as --allow-unverified says" "warns, and restores"
  expect 4 "restore an unsigned image --trusted-key" -- \
    "$BIN" restore --trusted-key signer.pub --root sout rimg.tar
  contains "$ERR" "it is not signed" "is refused"
  expect 2 "restore --trusted-key a file that is not a key" -- \
    "$BIN" restore --trusted-key rtree/etc/hosts --root sout simg.tar
  expect 0 "verify --trusted-key" -- "$BIN" verify --trusted-key signer.pub --root rtree simg.tar
  expect 4 "verify --trusted-key someone else's" -- "$BIN" verify --trusted-key other.pub --root rtree simg.tar
  expect 0 "verify, nothing checked" -- "$BIN" verify --root rtree simg.tar
  expect 0 "diff --trusted-key" -- "$BIN" diff --trusted-key signer.pub simg.tar simg.tar
  expect 4 "diff --trusted-key, one unsigned" -- "$BIN" diff --trusted-key signer.pub simg.tar rimg.tar

  # Signed afterwards, in place.
  cp rimg.tar later.tar
  expect 0 "sign" -- "$BIN" sign --sign-with signer.sec later.tar
  contains "$ERR" "signed by restate test" "says who signed it"
  expect 0 "and the signature holds" -- "$BIN" restore --dry-run --trusted-key signer.pub --root sout later.tar
  expect 2 "sign it again" -- "$BIN" sign --sign-with signer.sec later.tar
  contains "$ERR" "it is signed already" "is refused"
  expect 2 "sign with no key" -- "$BIN" sign later.tar
  expect 2 "sign a bare index" -- "$BIN" sign --sign-with signer.sec rindex.json
  expect 2 "capture --sign-with a key that is not there" -- \
    "$BIN" capture -r rtree --sign-with no-such.key -o x.tar

  # The index changed after it was signed.
  cp simg.tar forged.tar
  printf 'X' | dd of=forged.tar bs=1 seek=1600 conv=notrunc 2> /dev/null
  expect 4 "restore an image whose index changed" -- \
    "$BIN" restore --trusted-key signer.pub --root sout forged.tar
  contains "$ERR" "a bad signature" "is refused as a bad signature"

  # A rebuild: the restore is told what to trust. Of this machine's own root,
  # which has the description a rebuild is made from -- an Ubuntu one.
  if [ "$(uname -s)" = Linux ] && grep -qx 'ID=ubuntu' /etc/os-release 2> /dev/null; then
    echo "ephemeral /*" > signed-nothing.rules
    expect 0 "capture of / --sign-with" -- \
      "$BIN" capture -N -R signed-nothing.rules -q --sign-with signer.sec -o sroot.tar
    expect 0 "autoinstall --trusted-key" -- \
      "$BIN" autoinstall --trusted-key signer.pub --image-at /restate/sroot.tar sroot.tar
    contains "$OUT" "base64 -d > /tmp/restate-trusted.gpg" "the key goes into the installer"
    contains "$OUT" "--exclude /etc/crypttab --trusted-key /tmp/restate-trusted.gpg /restate/sroot.tar" \
      "and restore checks the image against it"
    expect 0 "autoinstall, no --trusted-key" -- "$BIN" autoinstall --image-at /restate/sroot.tar sroot.tar
    contains "$OUT" "--exclude /etc/crypttab --allow-unverified /restate/sroot.tar" "restore is told not to check"
    expect 0 "buildsheet --trusted-key" -- "$BIN" buildsheet --trusted-key signer.pub sroot.tar
    contains "$OUT" "--trusted-key signer.pub sroot.tar" "the sheet's restore checks too"
  fi
  GNUPGHOME="$WORK/gnupg" gpgconf --kill gpg-agent 2> /dev/null || true
fi

# An image from before 1.1: one gzip'd stream, index.json first.
mkdir -p old && ( cd old && tar -xf ../rimg.tar && gzip -dc restate/index.json.gz > restate/index.json &&
  tar -xzf restate/files.tar.gz && tar -czf ../rold.tgz restate/index.json restate/files )
mkdir -p rold
expect 0 "restore an image from before 1.1" -- "$BIN" restore --allow-unverified --root rold rold.tgz
check "puts its files back" cmp rtree/etc/app/key rold/etc/app/key

# The kit carries the restate that made the image, so a new system can run
# restore before restate is installed. Only a capture of the live root, and
# only where /proc names the running program; everything else ruled out.
# Linux only: NetBSD has a /proc/self/exe of sorts, but restate asks Linux's.
if [ "$(uname -s)" = Linux ] && [ -r /proc/self/exe ]; then
  echo "ephemeral /*" > nothing.rules
  expect 0 "capture of / with nothing kept" -- "$BIN" capture -N -R nothing.rules -q -o self.tar
  # Called through check.
  # shellcheck disable=SC2317,SC2329
  kit_holds() { part self.tar kit.tar.gz | gzip -dc | tar -tf - | grep -qx "restate/files$1"; }
  check "the kit holds the restate binary" kit_holds "$(readlink -f "$BIN")"
fi

# What is live: a process that looks like a database to /proc is named by
# capture, and with --quiesce its hook pauses it while its files are copied.
# A copy of sleep called redis-server, running in its data directory, is
# Redis as far as /proc can tell. Root's, Linux's, and only on a machine with
# no /etc/restate of its own: the test puts a hook there and takes it away.
if [ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] && [ -d /proc/self ] && [ ! -e /etc/restate ] &&
   [ ! -e /srv/restate-redis ] && [ ! -e /var/lib/restate ]; then
  mkdir -p /srv/restate-redis /etc/restate/hooks.d
  echo data > /srv/restate-redis/dump.rdb
  cp "$(command -v sleep)" "$WORK/redis-server"
  ( cd /srv/restate-redis && exec "$WORK/redis-server" 600 ) &
  live_pid=$!
  printf '%s\n' 'ephemeral /*' 'state /srv' 'state /var' 'ephemeral /var/*' 'state /var/lib' \
    'ephemeral /var/lib/*' 'state /var/lib/restate' > live.rules
  sleep 1

  expect 0 "capture names what is running" -- "$BIN" capture -N -R live.rules -o live.tar
  contains "$ERR" "Redis redis-server (/srv/restate-redis) is running" "and what it is, and where"
  contains "$ERR" "systemctl stop redis-server" "and how to stop it"
  contains "$ERR" "--quiesce" "and that capture can pause it"

  expect 0 "with --quiesce and no hook for it" -- "$BIN" capture -N -R live.rules --quiesce -o live.tar
  contains "$ERR" "no hook pauses redis (/etc/restate/hooks.d/redis)" "it says there is no hook"

  cat > /etc/restate/hooks.d/redis <<HOOK
#!/bin/sh
{ echo "\$1 \$2 uid=\$RESTATE_UID"; echo "\$RESTATE_PATHS"; echo "dump=\$RESTATE_DUMP_DIR"; } >> "$WORK/hook.log"
[ "\$1" = pause ] && echo dumped > "\$RESTATE_DUMP_DIR/dump.txt"
exit 0
HOOK
  chmod 0755 /etc/restate/hooks.d/redis
  expect 0 "with --quiesce, through its hook" -- "$BIN" capture -N -R live.rules --quiesce -o live.tar
  contains "$ERR" "pausing Redis redis-server" "it says it is pausing it"
  contains "$ERR" "resumed Redis redis-server" "and that it resumed it"
  hook_log="$(cat "$WORK/hook.log" 2> /dev/null)"
  contains "$hook_log" "pause redis-server uid=0" "the hook is told what to pause"
  contains "$hook_log" "resume redis-server" "and then to resume it"
  contains "$hook_log" "/srv/restate-redis" "and which files are about to be copied"
  contains "$hook_log" "dump=/var/lib/restate/dumps/redis-redis-server" "and where a dump goes"
  live_files="$(part live.tar files.tar.gz | gzip -dc | tar -tf -)"
  contains "$live_files" "restate/files/srv/restate-redis/dump.rdb" "the files are in the image"
  contains "$live_files" "restate/files/var/lib/restate/dumps/redis-redis-server/dump.txt" \
    "and the dump with them"
  check "the dump directory is root's alone" test "$(file_mode /var/lib/restate/dumps/redis-redis-server)" = 700

  # A script, written as it is: nothing to expand here.
  # shellcheck disable=SC2016
  printf '#!/bin/sh\n[ "$1" = pause ] && exit 3\nexit 0\n' > /etc/restate/hooks.d/redis
  expect 0 "a hook that cannot pause" -- "$BIN" capture -N -R live.rules --quiesce -o live.tar
  contains "$ERR" "was not paused" "is warned about"
  contains "$ERR" "resumed Redis redis-server" "and resume is run anyway"

  chmod 0777 /etc/restate/hooks.d/redis
  expect 0 "a hook anyone could change" -- "$BIN" capture -N -R live.rules --quiesce -o live.tar
  contains "$ERR" "no hook pauses redis" "is not run"

  kill "$live_pid" 2> /dev/null
  wait "$live_pid" 2> /dev/null
  rm -rf /srv/restate-redis /etc/restate /var/lib/restate
fi

# Owners by name: the image's accounts merged with the system's own.
me="$(id -un)"
myuid="$(id -u)"
mygid="$(id -g)"
mygroup="$(id -gn)"
mkdir -p atree/etc atree/home/me
# Only this user and one other, nothing fixed such as root: the test may run
# as root itself, as CI's containers do.
printf '%s:x:4242:4242:Me:/home/me:/bin/zsh\nold:x:1500:1500::/home/old:/bin/sh\n' \
  "$me" > atree/etc/passwd
printf '%s:x:4242:\nold:x:1500:\n' "$mygroup" > atree/etc/group
printf '%s:%s:1:0:99999:7:::\n' "$me" "\$6\$oldhash" > atree/etc/shadow
echo note > atree/home/me/note
expect 0 "capture a tree with accounts" -- "$BIN" capture -r atree --os=linux -q -o aimg.tar
check "the kit holds the accounts" \
  eval 'part aimg.tar kit.tar.gz | gzip -dc | tar -tf - | grep -qx restate/files/etc/passwd'
mkdir -p aout/etc
printf '%s:x:%s:%s:Installer:/home/me:/bin/sh\n' "$me" "$myuid" "$mygid" > aout/etc/passwd
printf '%s:x:%s:\n' "$mygroup" "$mygid" > aout/etc/group
expect 0 "restore onto a system with accounts of its own" -- "$BIN" restore --allow-unverified --root aout aimg.tar
contains "$ERR" "owners mapped by name" "restore maps owners by name"
contains "$(cat aout/etc/passwd)" "$me:x:$myuid:$mygid:Me:/home/me:/bin/zsh" \
  "a person both have: the system's number, the image's name, home and shell"
contains "$(cat aout/etc/passwd)" "old:x:1500:1500::/home/old:/bin/sh" \
  "a user only the image had, at its own number"
contains "$(cat aout/etc/shadow)" "$me:\$6\$oldhash:" "the image's password"
mkdir -p anum
expect 0 "restore --numeric-owner" -- "$BIN" restore --allow-unverified --numeric-owner --root anum aimg.tar
lacks "$ERR" "owners mapped by name" "--numeric-owner does not merge"
check "and lays down the image's account files as they are" cmp atree/etc/passwd anum/etc/passwd

expect 2 "restore a missing image" -- "$BIN" restore --allow-unverified --root rout no-such.tar
expect 2 "restore into a missing root" -- "$BIN" restore --allow-unverified --root no-such-dir rimg.tar

# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
expect 0 "diff identical images" -- "$BIN" diff img1.tar img2.tar
check "diff of identical images prints nothing" test -z "$OUT"
contains "$ERR" "0 added, 0 deleted, 0 modified" "the diff summary"
expect 0 "diff an image against an index" -- "$BIN" diff img1.tar m1.json

printf 'Port 2222\n' > tree/etc/ssh/sshd_config
chmod 700 tree/usr/bin/tool
rm tree/etc/hostname
printf 'new\n' > tree/etc/motd
expect 0 "scan the changed tree" -- "$BIN" scan -r tree --os=linux -o m2.json -q
expect 1 "diff a changed tree" -- "$BIN" diff img1.tar m2.json
contains "$OUT" "M	/etc/ssh/sshd_config	content" "a content change"
contains "$OUT" "M	/usr/bin/tool	mode" "a mode change"
contains "$OUT" "D	/etc/hostname" "a deletion"
contains "$OUT" "A	/etc/motd" "an addition"
expect 1 "diff an index from standard input" -- sh -c "\"$BIN\" diff - m2.json < m1.json"
contains "$OUT" "A	/etc/motd" "diff reads standard input"
expect 2 "an image on standard input" -- sh -c "\"$BIN\" diff - m2.json < img1.tar"
contains "$ERR" "name the file instead" "an image on stdin says what to do"
expect 2 "diff of two standard inputs" -- "$BIN" diff - -
expect 2 "diff of a missing file" -- "$BIN" diff m1.json nonexistent
printf 'not an index\n' > bogus.json
expect 2 "diff of a non-index" -- "$BIN" diff m1.json bogus.json
contains "$ERR" "not a restate index" "a non-index is named"
printf '{"format": "restate-index", "version": 1, "entries": [{"path": "/etc/../../root/x", "type": "file", "class": "state", "mode": "0644", "uid": 0, "gid": 0, "size": 0, "mtime": "2026-01-01T00:00:00.000000000Z"}]}' > evil.json
expect 2 "an index with a traversal path" -- "$BIN" diff m1.json evil.json
contains "$ERR" "not a clean absolute path" "a traversal path is refused"
expect 0 "diff -o" -- "$BIN" diff m1.json m1.json -o d.txt -q
check "diff -o writes the file" test -f d.txt

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------
expect 0 "scan for verify" -- "$BIN" capture -r tree --os=linux -q -o img3.tar
expect 0 "verify an unchanged tree" -- "$BIN" verify img3.tar --os=linux
contains "$ERR" "0 added, 0 deleted, 0 modified" "verify with no changes"
touch tree/etc/motd
expect 0 "verify after touch(1)" -- "$BIN" verify img3.tar --os=linux
printf 'changed\n' > tree/etc/motd
expect 1 "verify a changed tree" -- "$BIN" verify img3.tar --os=linux
contains "$OUT" "M	/etc/motd	content" "verify finds the change"
expect 1 "verify an index against another root" -- "$BIN" verify m2.json --os=linux -r outside
expect 2 "verify a missing image" -- "$BIN" verify nonexistent

# ---------------------------------------------------------------------------
# Unreadable files make a scan incomplete, never silently complete
# ---------------------------------------------------------------------------
if [ "$(id -u)" != "0" ]; then
  printf 'x\n' > tree/etc/locked
  chmod 000 tree/etc/locked
  expect 3 "scan with an unreadable file" -- "$BIN" scan -r tree --os=linux
  contains "$ERR" "/etc/locked" "the unreadable file is named"
  contains "$ERR" "incomplete" "the summary says the index is incomplete"
  contains "$OUT" '"unreadable": true' "it is recorded as unreadable"
  expect 3 "capture with an unreadable file" -- "$BIN" capture -r tree --os=linux -o img4.tar
  chmod 600 tree/etc/locked
fi

# ---------------------------------------------------------------------------
# classify and rules
# ---------------------------------------------------------------------------
expect 0 "classify" -- "$BIN" --os=linux classify /etc/passwd /usr/bin/ls /tmp/x /var/cache/apt
contains "$OUT" "state	/etc/passwd	state /etc" "classify /etc/passwd"
contains "$OUT" "baseline	/usr/bin/ls" "classify /usr/bin/ls"
contains "$OUT" "ephemeral	/tmp/x" "classify /tmp/x"
contains "$OUT" "expendable	/var/cache/apt" "classify /var/cache/apt"
expect 2 "classify a relative path" -- "$BIN" classify etc/passwd
expect 2 "classify a dot-dot path" -- "$BIN" classify /etc/../x

for os in linux freebsd openbsd netbsd darwin; do
  expect 0 "rules --os=$os" -- "$BIN" rules --os="$os"
  contains "$OUT" "# from built-in ($os)" "rules for $os"
done

expect 0 "rules to a file" -- "$BIN" rules --os=linux -o site.rules
printf 'expendable /etc/ssh\n' >> site.rules
expect 0 "a site rules file read back" -- "$BIN" -N -R site.rules classify /etc/ssh/x /usr/bin/ls
contains "$OUT" "expendable	/etc/ssh/x" "the appended rule wins"
contains "$OUT" "site.rules:" "the rule's source is named"
printf 'keep /x\n' > bad.rules
expect 2 "a bad rules file" -- "$BIN" -R bad.rules classify /x
contains "$ERR" "bad.rules:1: unknown class" "a bad rules file says where"
expect 2 "a missing rules file" -- "$BIN" -R nonexistent.rules classify /x

# ---------------------------------------------------------------------------
printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '  \033[92m✓\033[0m %d end-to-end checks passed\n\n' "$PASS"
  exit 0
fi
printf '  \033[91m✗\033[0m %d of %d end-to-end checks failed\n\n' "$FAIL" $((PASS + FAIL))
exit 1
