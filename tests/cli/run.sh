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
expect 2 "an unknown command" -- "$BIN" restore
contains "$ERR" 'unknown command "restore"' "unknown command"
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
contains "$OUT" "tar -xpzf layout.json" "buildsheet says how to restore"
expect 0 "buildsheet --target=vm" -- "$BIN" buildsheet --target=vm layout.json -o sheet.txt
check "buildsheet -o writes the file" test -s sheet.txt
contains "$(cat sheet.txt)" "virt-install --name db01" "a VM build sheet defines the VM"
contains "$(cat sheet.txt)" "--disk size=7," "the VM disk is sized to what is used"
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
expect 0 "capture" -- "$BIN" capture -r tree --os=linux -o img1.tgz
contains "$ERR" "kept the content of" "the capture summary"
check "the image is mode 600" test "$(file_mode img1.tgz)" = "600"
check "the image is gzip" sh -c 'gzip -t img1.tgz'
gzip -dc img1.tgz | tar -tf - > members.txt 2>/dev/null
check "index.json is the first member" test "$(head -1 members.txt)" = "restate/index.json"
contains "$(cat members.txt)" "restate/files/etc/ssh/sshd_config" "state content is in the image"
lacks "$(cat members.txt)" "restate/files/usr/bin/tool" "baseline content is not, by default"
expect 0 "capture --baseline-content" -- "$BIN" capture -r tree --os=linux -B -q -o img-b.tgz
gzip -dc img-b.tgz | tar -tf - > members-b.txt 2>/dev/null
contains "$(cat members-b.txt)" "restate/files/usr/bin/tool" "-B keeps baseline content too"
expect 0 "capture again" -- "$BIN" capture -r tree --os=linux -q -o img2.tgz

# The image is also a plain tarball: system tar restores it by hand.
mkdir -p unpacked
gzip -dc img1.tgz | ( cd unpacked && tar -xf - ) 2>/dev/null
check "system tar restores a file's content" \
  cmp tree/etc/ssh/sshd_config unpacked/restate/files/etc/ssh/sshd_config
chmod 640 tree/etc/hostname
expect 0 "capture after a mode change" -- "$BIN" capture -r tree --os=linux -q -o img-m.tgz
mkdir -p unpacked-m
gzip -dc img-m.tgz | ( cd unpacked-m && tar -xpf - ) 2>/dev/null
check "and its mode" test "$(file_mode unpacked-m/restate/files/etc/hostname)" = "640"
check "and a symlink" test -L unpacked/restate/files/home/u/link

# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
expect 0 "diff identical images" -- "$BIN" diff img1.tgz img2.tgz
check "diff of identical images prints nothing" test -z "$OUT"
contains "$ERR" "0 added, 0 deleted, 0 modified" "the diff summary"
expect 0 "diff an image against an index" -- "$BIN" diff img1.tgz m1.json

printf 'Port 2222\n' > tree/etc/ssh/sshd_config
chmod 700 tree/usr/bin/tool
rm tree/etc/hostname
printf 'new\n' > tree/etc/motd
expect 0 "scan the changed tree" -- "$BIN" scan -r tree --os=linux -o m2.json -q
expect 1 "diff a changed tree" -- "$BIN" diff img1.tgz m2.json
contains "$OUT" "M	/etc/ssh/sshd_config	content" "a content change"
contains "$OUT" "M	/usr/bin/tool	mode" "a mode change"
contains "$OUT" "D	/etc/hostname" "a deletion"
contains "$OUT" "A	/etc/motd" "an addition"
expect 1 "diff an index from standard input" -- sh -c "\"$BIN\" diff - m2.json < m1.json"
contains "$OUT" "A	/etc/motd" "diff reads standard input"
expect 2 "an image on standard input" -- sh -c "\"$BIN\" diff - m2.json < img1.tgz"
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
expect 0 "scan for verify" -- "$BIN" capture -r tree --os=linux -q -o img3.tgz
expect 0 "verify an unchanged tree" -- "$BIN" verify img3.tgz --os=linux
contains "$ERR" "0 added, 0 deleted, 0 modified" "verify with no changes"
touch tree/etc/motd
expect 0 "verify after touch(1)" -- "$BIN" verify img3.tgz --os=linux
printf 'changed\n' > tree/etc/motd
expect 1 "verify a changed tree" -- "$BIN" verify img3.tgz --os=linux
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
  expect 3 "capture with an unreadable file" -- "$BIN" capture -r tree --os=linux -o img4.tgz
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
