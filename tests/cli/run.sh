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
# macOS's TMPDIR ends in a slash, so that is ".../T//restate-cli.x" -- which a
# job refuses as a path, rightly, since it is not one written the plain way.
WORK="$(printf '%s' "$WORK" | tr -s /)"
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
  # The BSDs' %Lp leaves out the sticky and set-id bits: %p is the whole
  # mode, the file's type before its last four digits.
  stat -c '%a' "$1" 2>/dev/null || stat -f '%p' "$1" | sed 's/.*\(....\)$/\1/; s/^0*//'
}

# Whether restate will run a program: where it looks, root's, and writable by
# no one else (see run.c). Homebrew's gpg on macOS is the runner's, not root's.
usable() {
  for d in /usr/bin /usr/local/bin /bin; do
    if [ -n "$(find -L "$d/$1" -prune -type f -user 0 ! -perm -020 ! -perm -002 2> /dev/null)" ]; then
      return 0
    fi
  done
  return 1
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
# Paths only: the rules the index records name a secret or two of their own.
lacks "$OUT" '/secret"' "the walk does not follow a symlink"
contains "$OUT" '"type": "fifo"' "a FIFO is recorded"
lacks "$OUT" '"path": "/tmp/scratch' "ephemeral paths are skipped"
lacks "$OUT" '"path": "/var/cache' "expendable paths are skipped"
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
if usable gpgv; then
  contains "$OUT" '"problem": "http://deb.example.com/debian stable: apt has no index of it' \
    "and that apt cannot use it"
fi
if command -v python3 > /dev/null 2>&1; then
  check "the inventory is valid JSON" \
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["apt"]["count"] == 2' < out.txt
fi
expect 0 "packages --fetch-sources" -- "$BIN" packages --fetch-sources --root pkgtree
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
  eval 'part kept.tar files.tar.gz | gzip -dc | tar -tf - | grep -x "restate/files/var/cache/apt/archives/by-hand_1.0_amd64.deb" > /dev/null'
check "and nothing else of /var/cache" \
  eval '! part kept.tar files.tar.gz | gzip -dc | tar -tf - | grep -v by-hand_1.0_amd64.deb | grep "var/cache/apt/archives/" > /dev/null'
check "the kit holds it, and /etc/apt" \
  eval 'part kept.tar kit.tar.gz | gzip -dc | tar -tf - | tr "\n" " " | grep "restate/files/etc/apt/sources.list .*restate/files/var/cache/apt/archives/by-hand_1.0_amd64.deb" > /dev/null'
check "and nothing else" \
  eval '! part kept.tar kit.tar.gz | gzip -dc | tar -tf - | grep -v -e etc/apt -e by-hand | grep . > /dev/null'
expect 0 "verify the image with kept packages" -- "$BIN" verify --root pkgtree kept.tar
lacks "$OUT" "by-hand_1.0_amd64.deb" "verify walks what the image kept, and finds it unchanged"
expect 0 "packages of the image" -- "$BIN" packages kept.tar
contains "$OUT" '"kept": "/var/cache/apt/archives/by-hand_1.0_amd64.deb"' "the inventory says what it kept"
expect 2 "autoinstall --image-at a relative path" -- "$BIN" autoinstall --image-at x.tar
contains "$ERR" "not an absolute path" "--image-at has to be absolute"
printf '{"format": "restate-index", "version": 1, "entries": []}' > old-index.json
expect 2 "packages of an old index" -- "$BIN" packages old-index.json
contains "$ERR" "has no package inventory" "an index from before the inventory says so"

# The baseline, restore --packages and diff --packages
expect 0 "baseline" -- "$BIN" baseline kept.tar
contains "$OUT" "$(printf 'hello 2.10-3 amd64\tto fetch')" "baseline lists each package, and whether it is cached"
contains "$OUT" "$(printf 'by-hand 1.0 amd64\tinstalled from a .deb the image keeps')" \
  "and what only the image has"
expect 4 "baseline fetch of an unsigned image" -- "$BIN" baseline fetch kept.tar
contains "$ERR" "not fetching its packages" "is refused, as restore refuses it"
expect 2 "baseline with two arguments and no fetch" -- "$BIN" baseline kept.tar kept.tar
mkdir -p rp
expect 0 "restore --packages --dry-run" -- \
  "$BIN" restore --packages --dry-run --allow-unverified --root rp kept.tar
contains "$OUT" "apt-get update" "writes the script that would put the packages back"
contains "$OUT" "hello=2.10-3" "with what was installed by hand, at its version"
contains "$OUT" "[ -f /var/cache/apt/archives/by-hand_1.0_amd64.deb ]" "and the .deb the image kept"
check "the script is sh" sh -n out.txt
expect 2 "restore --packages onto another root" -- \
  "$BIN" restore --packages --allow-unverified --root rp kept.tar
contains "$ERR" "installs onto the running system" "is refused: it installs onto this one"
expect 2 "restore --offline without --packages" -- \
  "$BIN" restore --offline --dry-run --allow-unverified --root rp kept.tar
contains "$ERR" "give --packages too" "is refused"
expect 2 "restore --offline --exact-versions" -- \
  "$BIN" restore --packages --offline --exact-versions --dry-run --allow-unverified --root rp kept.tar
contains "$ERR" "the archive's snapshot is on the network" "is refused"
expect 2 "restore --offline with no baseline cache" -- \
  "$BIN" restore --packages --offline --cache "$PWD/no-cache" --dry-run --allow-unverified \
    --root rp kept.tar
contains "$ERR" "run restate baseline fetch" "says how to make one"
mkdir -p loose-cache && chmod 0775 loose-cache
expect 2 "restore --offline from a cache others can write" -- \
  "$BIN" restore --packages --offline --cache "$PWD/loose-cache" --dry-run --allow-unverified \
    --root rp kept.tar
contains "$ERR" "not root's alone" "is refused: what is in it is installed as root"
if [ "$(id -u)" = 0 ]; then
  mkdir -p offline-cache && chmod 0755 offline-cache
  printf deb > offline-cache/hello_2.10-3_amd64.deb
  expect 0 "restore --packages --offline --dry-run" -- \
    "$BIN" restore --packages --offline --cache "$PWD/offline-cache" --dry-run \
      --allow-unverified --root rp kept.tar
  contains "$ERR" "offline: 1 of the image's 1 packages from repositories are in" \
    "says how much of the baseline the cache has"
  contains "$OUT" "deb [trusted=yes] file:" "gives apt the cache as its one repository"
  contains "$OUT" "hello_2.10-3_amd64.deb" "with the package in it"
  check "the offline script is sh" sh -n out.txt
fi
sed 's/^Version: 2.10-3$/Version: 2.11-1/' pkgtree/var/lib/dpkg/status > status.new &&
  mv status.new pkgtree/var/lib/dpkg/status
expect 0 "capture after an upgrade" -- \
  "$BIN" capture --root pkgtree --keep-local-packages -o kept2.tar
expect 1 "diff --packages" -- "$BIN" diff --packages kept.tar kept2.tar
contains "$OUT" "$(printf 'U\tapt:hello\t2.10-3 -> 2.11-1')" "names the package upgraded"
contains "$ERR" "1 packages changed" "and counts it"
# dpkg's status file changed too: on Linux its rules leave it out, and
# elsewhere it is an ordinary file kept and listed, so either status will do.
"$BIN" diff kept.tar kept2.tar > out.txt 2> err.txt < /dev/null
status=$?
OUT="$(cat out.txt)"
check "diff without --packages ends normally" test "$status" -le 1
lacks "$OUT" "apt:hello" "diff without --packages lists files alone"
expect 2 "--firmware without --target" -- "$BIN" buildsheet --firmware uefi kept.tar
contains "$ERR" "--firmware needs --target" "is refused"
expect 2 "--firmware of an unknown kind" -- "$BIN" buildsheet --target vm --firmware efi kept.tar
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
# --exact-versions: the packages' versions from the archive's snapshot as of
# the capture, where the archive has moved on.
sed -e 's/"content": "none",/"content": "none", "created": "2026-10-10T19:14:40.031046870Z",/' \
    -e 's/^ "entries": \[/ "packages": {"apt": {"architectures": ["amd64"], "packages": [{"name": "vim", "architecture": "amd64", "version": "2:9.1", "manual": true}]}}, "entries": [/' \
    captured.json > captured-apt.json
expect 0 "buildsheet --exact-versions" -- "$BIN" buildsheet --exact-versions captured-apt.json
contains "$OUT" "snap='20261010T191440Z'" "takes versions from the snapshot as of the capture"
expect 0 "buildsheet, the versions there are now" -- "$BIN" buildsheet captured-apt.json
lacks "$OUT" "snap=" "unless asked"
expect 0 "autoinstall --exact-versions" -- \
  "$BIN" autoinstall --exact-versions --image-at /restate/x.tar captured-apt.json

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
printf 'name,mac,address,gateway\nweb1,52:54:00:00:00:01,10.0.0.11/24,10.0.0.1\nweb2,52:54:00:00:00:02,,\n' > lab.csv
expect 0 "autoinstall --clones" -- "$BIN" autoinstall --clones lab.csv layout.json
contains "$OUT" "# One file for 2 copies of the machine, from lab.csv." "autoinstall --clones says so"
contains "$OUT" "  early-commands:" "and picks the copy in an early-command"
if command -v python3 > /dev/null 2>&1 && python3 -c 'import yaml' 2> /dev/null; then
  check "the copies' autoinstall file is valid YAML" \
    python3 -c 'import sys, yaml; assert "early-commands" in yaml.safe_load(sys.stdin)["autoinstall"]' < out.txt
fi
printf 'name,mac\nweb1,52:54:00:00:00:01\nweb1,52:54:00:00:00:02\n' > twice.csv
expect 2 "autoinstall --clones with a name twice" -- "$BIN" autoinstall --clones twice.csv layout.json
contains "$ERR" "twice.csv:3: a name given to another copy already" "says where"
expect 2 "autoinstall --clones with no such file" -- "$BIN" autoinstall --clones none.csv layout.json
contains "$ERR" "--clones: none.csv" "says which"
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

printf 'ephemeral /**\nstate /var/cache/apt\n' > only.rules
expect 0 "scan with rules that keep one directory and nothing else" -- \
  "$BIN" scan -r tree --os=linux -N -R only.rules -q
contains "$OUT" "/var/cache/apt/pkg.deb" "the walk goes through what is left out to what is kept"
lacks "$OUT" '"path": "/etc' "and records nothing beside it"
printf 'ephemeral /\n' > slash.rules
expect 0 "classify with a rule for / alone" -- "$BIN" classify -N -R slash.rules /etc
contains "$ERR" '"ephemeral /" names the root directory alone' "is warned of"

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
key_inode=$(inode rout/etc/app/key)
linked_inode=$(inode rout/var/lib/x/one)
expect 0 "restore again, over itself" -- "$BIN" restore --allow-unverified --root rout rimg.tar
contains "$ERR" "5 of those files were in place already" "says what it left in place"
check "and leaves it, not writing it again" test "$(inode rout/etc/app/key)" = "$key_inode"
check "a hard-linked file too, with both its names" \
  test "$(inode rout/var/lib/x/two)" = "$linked_inode" -a "$(inode rout/var/lib/x/one)" = "$linked_inode"

# An image whose fstab and crypttab name disks this machine does not have, as
# when it goes onto a machine laid out afresh: the root's own are kept. A
# capture of a tree records no machine description, so one is put in.
mkdir -p ftree/etc
printf 'UUID=restate-test-none /boot/efi vfat umask=0077 0 1\n' > ftree/etc/fstab
printf 'crypt UUID=restate-test-gone none luks\n' > ftree/etc/crypttab
echo motd > ftree/etc/motd
expect 0 "capture for an fstab of other disks" -- "$BIN" capture -r ftree --os=linux -q -o fplain.tar
mkdir -p fimg && ( cd fimg && tar -xf ../fplain.tar &&
  gzip -dc restate/index.json.gz |
    sed 's|^  "packages": {|  "machine": {"fstab": [{"spec": "UUID=restate-test-none", "file": "/boot/efi", "type": "vfat", "options": "umask=0077"}, {"spec": "/dev/null", "file": "/x", "type": "none", "options": "bind"}], "crypttab": [{"name": "crypt", "device": "UUID=restate-test-gone", "keyfile": "none", "options": "luks"}]}, "packages": {|' |
    gzip -c > index.json.gz && mv index.json.gz restate/index.json.gz &&
  tar -cf ../fimg.tar restate/index.json.gz restate/kit.tar.gz restate/files.tar.gz )
mkdir -p fown/etc
echo 'own fstab' > fown/etc/fstab
expect 0 "restore an image whose fstab names other disks" -- \
  "$BIN" restore --allow-unverified --root fown fimg.tar
contains "$ERR" "keeping fown's own /etc/fstab and /etc/crypttab, not the image's" \
  "says it keeps the root's own fstab and crypttab"
contains "$ERR" "UUID=restate-test-none (/boot/efi), UUID=restate-test-gone (crypt)" \
  "and names the disks that are not here"
check "the root's own fstab is kept" test "$(cat fown/etc/fstab)" = "own fstab"
check "the image's crypttab is not put in" test ! -e fown/etc/crypttab
check "the rest is put back" test -f fown/etc/motd
contains "$ERR" "left out 2 paths (--exclude, and the image's fstab and crypttab)" \
  "counts them as left out"
mkdir -p fdry/etc
echo 'own fstab' > fdry/etc/fstab
expect 0 "restore --dry-run, an fstab naming other disks" -- \
  "$BIN" restore --allow-unverified --dry-run --root fdry fimg.tar
contains "$ERR" "would keep fdry's own /etc/fstab" "a dry run says it would keep them"
expect 0 "restore --image-fstab" -- \
  "$BIN" restore --allow-unverified --image-fstab --root fown fimg.tar
contains "$ERR" "put back all the same, as --image-fstab says" "--image-fstab warns"
check "and puts the image's fstab back" cmp ftree/etc/fstab fown/etc/fstab
check "and its crypttab" cmp ftree/etc/crypttab fown/etc/crypttab
mkdir -p fnew
expect 0 "restore onto a root with no fstab of its own" -- \
  "$BIN" restore --allow-unverified --root fnew fimg.tar
lacks "$ERR" "keeping" "keeps nothing where there is nothing to keep"
check "and puts the image's fstab in" cmp ftree/etc/fstab fnew/etc/fstab

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

# restore --as: a copy with an identity of its own.
mkdir -p itree/etc/ssh itree/var/lib/tailscale itree/home/u
echo 0123456789abcdef0123456789abcdef > itree/etc/machine-id
echo oldbox > itree/etc/hostname
echo KEY > itree/etc/ssh/ssh_host_ed25519_key
echo node > itree/var/lib/tailscale/tailscaled.state
echo doc > itree/home/u/doc
expect 0 "capture a machine's identity" -- "$BIN" capture -r itree --os=linux -o iimg.tar
contains "$ERR" " 4 identity," "capture counts what is identity"
expect 2 "restore --as a name that is not a host name" -- \
  "$BIN" restore --allow-unverified --as 'web 1' --root ifresh iimg.tar
contains "$ERR" "is not a host name" "and says why"
mkdir -p ifresh/etc
echo ffffffffffffffffffffffffffffffff > ifresh/etc/machine-id
expect 0 "restore --as onto a fresh install" -- \
  "$BIN" restore --allow-unverified --as web1 --root ifresh iimg.tar
contains "$ERR" "as web1: left out the image's identity (4 paths)" "says what it left out"
check "keeps the machine's own machine-id" \
  test "$(cat ifresh/etc/machine-id)" = ffffffffffffffffffffffffffffffff
check "gives it the new host name" test "$(cat ifresh/etc/hostname)" = web1
check "leaves out the image's node key" test ! -e ifresh/var/lib/tailscale/tailscaled.state
check "and puts the rest back" test -f ifresh/home/u/doc
cp -R itree icopy
mkdir -p icopy/usr/sbin && : > icopy/usr/sbin/sshd
if usable ssh-keygen; then keygen=0; else keygen=3; fi
expect "$keygen" "restore --as onto a copy of the image's disk" -- \
  "$BIN" restore --allow-unverified --as web2 --root icopy iimg.tar
contains "$ERR" "of the image's own removed" "says what it removed"
check "a new machine-id" \
  test "$(cat icopy/etc/machine-id)" != 0123456789abcdef0123456789abcdef
check "the image's node key removed" test ! -e icopy/var/lib/tailscale/tailscaled.state
check "the image's host key removed" \
  test "$(cat icopy/etc/ssh/ssh_host_ed25519_key 2> /dev/null)" != KEY
check "the new host name" test "$(cat icopy/etc/hostname)" = web2
expect 0 "restore --as --dry-run" -- \
  "$BIN" restore --allow-unverified --as web3 --dry-run --root icopy iimg.tar
contains "$OUT" "would set the host name in /etc/hostname" "a dry run says what --as would do"
check "and does not" test "$(cat icopy/etc/hostname)" = web2

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
mkdir -p rcheck
expect 2 "restore --check-first a tampered image" -- \
  "$BIN" restore --allow-unverified --check-first --root rcheck rbad.tar
contains "$ERR" "nothing was written (--check-first)" "is refused whole"
check "and writes nothing" test ! -e rcheck/etc/hosts
expect 0 "restore --check-first a whole one" -- \
  "$BIN" restore --allow-unverified --check-first --root rcheck rimg.tar
contains "$ERR" "checked: every file is what its index says" "checks it first"
check "then puts it back" cmp rtree/etc/app/key rcheck/etc/app/key

# A files part that runs on past its end-of-archive blocks, as some tars
# pad it -- more than a pipe holds: read to its end, not gzip killed.
mkdir -p padded && ( cd padded && tar -xf ../rimg.tar && gzip -dc restate/files.tar.gz > files.tar &&
  dd if=/dev/zero bs=1024 count=512 >> files.tar 2> /dev/null &&
  gzip -c files.tar > restate/files.tar.gz &&
  tar -cf ../rpad.tar restate/index.json.gz restate/kit.tar.gz restate/files.tar.gz )
mkdir -p rpad
expect 0 "restore an image padded past its end" -- "$BIN" restore --allow-unverified --root rpad rpad.tar
check "puts its files back" cmp rtree/etc/app/key rpad/etc/app/key

# A repository: snapshots, each file's content stored once, and what has not
# changed since the last not read again.
expect 0 "init" -- "$BIN" init repo
contains "$ERR" "made the repository repo" "init says what it made"
check "a repository is its owner's alone" test "$(file_mode repo)" = 700
expect 2 "init it again" -- "$BIN" init repo
contains "$ERR" "it is a repository already" "is refused"
expect 2 "init over a file" -- "$BIN" init rimg.tar
expect 0 "capture into a repository" -- \
  env SOURCE_DATE_EPOCH=1767225600 "$BIN" capture -r rtree --os=linux -o repo
contains "$ERR" "snapshot repo::20260101T000000Z:" "capture names the snapshot"
echo "changed" > rtree/etc/hosts
expect 0 "capture into it again" -- \
  env SOURCE_DATE_EPOCH=1767312000 "$BIN" capture -r rtree --os=linux --syslog -o repo
contains "$ERR" "new to the repository, from 1 files" "only what changed is new"
contains "$ERR" "4 files unchanged since the last snapshot were not read" "and the rest is not read"
expect 0 "snapshots" -- "$BIN" snapshots repo
contains "$OUT" "20260101T000000Z" "lists the first"
contains "$OUT" "20260102T000000Z" "and the second"
expect 2 "snapshots of what is not a repository" -- "$BIN" snapshots rtree
expect 0 "status, nothing changed since" -- "$BIN" status repo
contains "$ERR" "0 added, 0 deleted, 0 modified" "status finds nothing changed"
echo "doc, edited" > "rtree/home/u/with space"
expect 1 "status, a file changed since" -- "$BIN" status repo --result st.json
contains "$OUT" "/home/u/with space" "status names it"
contains "$(cat st.json)" '"snapshot": "repo::20260102T000000Z"' "its result names the newest snapshot"
contains "$(cat st.json)" '"path": "/home/u/with space", "what": "content"' "and the change, and how"
contains "$(cat st.json)" '"truncated": false' "all of them"

# list: a snapshot's directories, from its index alone.
expect 0 "list a snapshot's top" -- "$BIN" list repo
contains "$OUT" "  etc" "names what is in it"
expect 0 "list a directory of it" -- "$BIN" list repo::20260101T000000Z /etc/ --result ls.json
contains "$OUT" "  hosts" "names its files"
contains "$OUT" "  app" "and its directories"
contains "$(cat ls.json)" '"path": "/etc"' "the result names the directory"
contains "$(cat ls.json)" '"name": "hosts", "type": "file", "size": ' "and what is in it"
contains "$(cat ls.json)" '"truncated": false' "all of it"
expect 0 "list --json" -- "$BIN" list --json repo /home/u
contains "$OUT" '"type": "link"' "says a symlink is one"
contains "$OUT" '"target": "../../etc/hosts"' "and where it points"
expect 2 "list a file" -- "$BIN" list repo /etc/hosts
contains "$ERR" "is a file in repo, not a directory" "is refused"
expect 2 "list what is not there" -- "$BIN" list repo /nowhere
contains "$ERR" "has no /nowhere" "is refused"
expect 2 "list a path that is not clean" -- "$BIN" list repo etc
expect 1 "diff two snapshots" -- "$BIN" diff repo::20260101T000000Z repo
contains "$OUT" "/etc/hosts" "diff names what changed between them"
expect 2 "a snapshot that is not there" -- "$BIN" diff repo::19990101T000000Z repo
contains "$ERR" "no snapshot \"19990101T000000Z\"" "is named"
expect 0 "verify a snapshot" -- "$BIN" verify --root rout repo::20260101T000000Z
mkdir -p repout
expect 4 "restore a snapshot, unsigned" -- "$BIN" restore --root repout repo
expect 0 "restore a snapshot" -- "$BIN" restore --allow-unverified --root repout repo
contains "$ERR" "put back 5 files" "restore puts its files back"
check "its content" test "$(cat repout/etc/hosts)" = changed
check "with its mode" test "$(file_mode repout/etc/app/key)" = "600"
check "a symlink" test "$(readlink repout/home/u/link)" = "../../etc/hosts"
check "and a hard link" test "$(inode repout/var/lib/x/one)" = "$(inode repout/var/lib/x/two)"
expect 0 "export a snapshot" -- "$BIN" export repo::20260101T000000Z -o exported.tar
mkdir -p expout
expect 0 "restore what was exported" -- "$BIN" restore --allow-unverified --root expout exported.tar
check "it is the snapshot's" test "$(cat expout/etc/hosts)" = "127.0.0.1 localhost"
check "and keeps the kit" eval 'tar -tf exported.tar | grep -x restate/kit.tar.gz > /dev/null'
expect 2 "buildsheet from a snapshot" -- "$BIN" buildsheet repo
contains "$ERR" "export it first" "says to export it"
expect 2 "autoinstall from a snapshot" -- "$BIN" autoinstall repo::20260101T000000Z
expect 0 "packages from a snapshot" -- "$BIN" packages repo
expect 2 "export with nowhere to write" -- "$BIN" export repo
expect 2 "export an image" -- "$BIN" export rimg.tar -o x.tar
expect 2 "capture --encrypt-to into a repository" -- \
  "$BIN" capture -r rtree --encrypt-to rtree/etc/hosts -o repo
contains "$ERR" "is a repository that is not encrypted" "is refused, saying why"
expect 2 "prune --encrypt-to a repository that is not encrypted" -- \
  "$BIN" prune --keep-last 1 --encrypt-to rtree/etc/hosts repo
expect 2 "prune, keeping nothing named" -- "$BIN" prune repo
expect 0 "prune --dry-run" -- "$BIN" prune --dry-run --keep-last 1 repo
contains "$OUT" "would drop 20260101T000000Z" "says what it would drop"
expect 2 "--keep-last is a number" -- "$BIN" prune --keep-last=x repo
if command -v flock > /dev/null 2>&1; then
  flock repo/lock sleep 3 &
  locker=$!
  sleep 1
  expect 5 "capture while another holds the repository" -- "$BIN" capture -r rtree -o repo
  contains "$ERR" "another capture or prune is using it" "says why"
  expect 5 "prune while another holds it" -- "$BIN" prune --keep-last 1 repo
  wait "$locker"
fi
expect 0 "prune" -- "$BIN" prune --keep-last 1 --syslog repo
contains "$OUT" "dropped 20260101T000000Z" "drops the older"
expect 0 "the one kept is whole" -- "$BIN" restore --allow-unverified --dry-run --root repout repo
expect 2 "a snapshot dropped" -- "$BIN" status repo::20260101T000000Z
expect 0 "check a repository" -- "$BIN" check repo
contains "$ERR" "the repository is whole" "check finds it whole"
expect 0 "check --read-all" -- "$BIN" check --read-all --syslog repo
contains "$ERR" "read 1 snapshots in full, as restore would" "and reads every snapshot"
expect 2 "check what is not a repository" -- "$BIN" check rtree
# Damage: a pack's content changed, its index left as it was.
cp -R repo crepo
for p in crepo/packs/*.tar.gz; do
  gzip -dc "$p" > cpack.tar
  # A byte changed in the first member: its header or its content.
  printf 'X' | dd of=cpack.tar bs=1 seek=512 conv=notrunc 2> /dev/null
  gzip -c cpack.tar > "$p"
  break
done
expect 3 "check a damaged repository" -- "$BIN" check crepo
contains "$ERR" "crepo/packs/" "check names the damaged pack"
contains "$ERR" "its content is not all in the repository" "and which files it breaks"
contains "$ERR" "the repository is damaged" "and that it is damaged"
expect 3 "check --read-all a damaged repository" -- "$BIN" check --read-all crepo
contains "$ERR" "not as their indexes say" "the full read finds it too"

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
if usable gpg && usable gpgv && usable gpgconf; then
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
  check "the image carries the signature, last" eval 'tar -tf simg.tar | tail -1 | grep -x restate/index.sig > /dev/null'
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

  # The index changed after it was signed: a byte in the middle of the first
  # member, the compressed index. Its data follows its header and any pax
  # headers ('x') before it; a header's size is the octal at 124, its type at 156.
  cp simg.tar forged.tar
  check "the index is the image's first member" \
    eval 'tar -tf forged.tar | sed -n 1p | grep -x restate/index.json.gz > /dev/null'
  hat=0
  while :; do
    isize="$(printf '%d' "0$(dd if=forged.tar bs=1 skip=$((hat + 124)) count=11 2> /dev/null)")"
    [ "$(dd if=forged.tar bs=1 skip=$((hat + 156)) count=1 2> /dev/null)" = x ] || break
    hat=$((hat + 512 + (isize + 511) / 512 * 512))
  done
  iat=$((hat + 512 + isize / 2))
  forge=X
  if [ "$(dd if=forged.tar bs=1 skip="$iat" count=1 2> /dev/null)" = X ]; then
    forge=Y
  fi
  printf '%s' "$forge" | dd of=forged.tar bs=1 seek="$iat" conv=notrunc 2> /dev/null
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
  # Snapshots, signed as they are taken or afterwards, and checked as images are.
  expect 0 "init a repository to sign in" -- "$BIN" init srepo
  expect 0 "capture --sign-with into a repository" -- \
    "$BIN" capture -r rtree --os=linux --sign-with signer.sec -o srepo
  contains "$ERR" "signed by restate test <signer@example.invalid>" "says who signed it"
  mkdir -p srout
  expect 0 "restore a signed snapshot --trusted-key" -- \
    "$BIN" restore --trusted-key signer.pub --root srout srepo
  contains "$ERR" "is signed by restate test" "says who signed it"
  expect 4 "restore it --trusted-key someone else's" -- \
    "$BIN" restore --trusted-key other.pub --root srout srepo
  expect 0 "export it, signed and checked" -- \
    "$BIN" export --trusted-key signer.pub --sign-with signer.sec srepo -o sexport.tar
  expect 0 "and the export's own signature holds" -- \
    "$BIN" restore --dry-run --trusted-key signer.pub --root srout sexport.tar
  expect 0 "status --trusted-key" -- "$BIN" status --trusted-key signer.pub srepo
  expect 0 "capture into it unsigned" -- "$BIN" capture -r rtree --os=linux -q -o srepo
  expect 4 "is not trusted" -- "$BIN" restore --trusted-key signer.pub --root srout srepo
  expect 0 "sign the snapshot afterwards" -- "$BIN" sign --sign-with signer.sec srepo
  expect 0 "and it is trusted" -- "$BIN" restore --dry-run --trusted-key signer.pub --root srout srepo
  expect 2 "sign it again" -- "$BIN" sign --sign-with signer.sec srepo
  contains "$ERR" "it is signed already" "is refused"

  # A key with a passphrase, given on a file descriptor rather than asked for:
  # for signing unattended, and for a restore a program runs.
  mkdir -m 700 pgnupg pnokey
  pk() { GNUPGHOME="$WORK/pgnupg" gpg --batch --quiet --pinentry-mode loopback --passphrase pw "$@"; }
  pk --quick-gen-key 'with pass <pass@example.invalid>' default default never 2> /dev/null
  pk --export-secret-keys --armor pass@example.invalid > pass.sec 2> /dev/null
  pk --export pass@example.invalid > pass.pub 2> /dev/null
  printf 'pw\n' > pw.txt
  # The command, with the passphrase readable on file descriptor 3. Called
  # through expect.
  # shellcheck disable=SC2317,SC2329
  with_pw() { "$@" 3< "$WORK/pw.txt"; }
  cp rimg.tar psigned.tar
  expect 0 "sign with a key that has a passphrase, --passphrase-fd" -- \
    with_pw "$BIN" sign --sign-with pass.sec --passphrase-fd 3 psigned.tar
  expect 0 "and the signature holds" -- \
    "$BIN" restore --dry-run --trusted-key pass.pub --root sout psigned.tar
  expect 0 "an encrypted repository whose key has a passphrase" -- \
    "$BIN" init -q --encrypt-to pass.pub prepo-enc
  expect 0 "capture into it" -- \
    env XDG_CACHE_HOME="$WORK/pcache" GNUPGHOME="$WORK/pnokey" \
    "$BIN" capture -q -r rtree --os=linux --encrypt-to pass.pub -o prepo-enc
  mkdir -p ppout
  expect 0 "restore it, the passphrase on a file descriptor" -- \
    with_pw env XDG_CACHE_HOME="$WORK/pcache2" GNUPGHOME="$WORK/pgnupg" \
    "$BIN" restore -q --allow-unverified --passphrase-fd 3 --root ppout prepo-enc
  check "and its files are back" cmp rtree/etc/app/key ppout/etc/app/key
  expect 0 "check --metadata-only an encrypted repository, with no key at all" -- \
    env XDG_CACHE_HOME="$WORK/pcache3" GNUPGHOME="$WORK/pnokey" \
    "$BIN" check --metadata-only prepo-enc
  expect 0 "copy an encrypted repository, with no key at all" -- \
    env XDG_CACHE_HOME="$WORK/pcache3" GNUPGHOME="$WORK/pnokey" "$BIN" copy prepo-enc poff-enc
  check "its copy is encrypted as it was" sh -c '! cat poff-enc/packs/*.idx | grep restate-pack > /dev/null'
  expect 0 "and reads back with the key" -- \
    with_pw env XDG_CACHE_HOME="$WORK/pcache4" GNUPGHOME="$WORK/pgnupg" \
    "$BIN" check -q --passphrase-fd 3 poff-enc
  expect 0 "prune --whole-packs an encrypted repository, with no key at all" -- \
    env XDG_CACHE_HOME="$WORK/pcache3" GNUPGHOME="$WORK/pnokey" \
    "$BIN" prune --whole-packs --keep-last 1 prepo-enc
  GNUPGHOME="$WORK/pgnupg" gpgconf --kill gpg-agent 2> /dev/null || true

  # An encrypted repository: the keys given each time, a capture needing no
  # secret key, and a restore needing it.
  gk --quick-gen-key 'restate enc <enc@example.invalid>' default default never 2> /dev/null
  gk --export enc@example.invalid > enc.pub 2> /dev/null
  mkdir -m 700 nokey
  expect 0 "init an encrypted repository" -- "$BIN" init --encrypt-to enc.pub erepo
  contains "$ERR" "made the encrypted repository erepo" "says it is encrypted"
  expect 2 "init --encrypt-to a key that is not there" -- "$BIN" init --encrypt-to no-such.pub erepo2
  expect 0 "capture --create --encrypt-to" -- \
    env XDG_CACHE_HOME="$WORK/cache" GNUPGHOME="$WORK/nokey" \
    "$BIN" capture -r rtree --os=linux --encrypt-to enc.pub -o ecrepo --create
  contains "$ERR" "made the encrypted repository ecrepo" "makes an encrypted one"
  check "encrypted, as init would make it" sh -c '! gzip -t ecrepo/snapshots/*/index.json.gz 2> /dev/null'
  expect 2 "capture --create --encrypt-to a key that is not there" -- \
    "$BIN" capture -r rtree --os=linux --encrypt-to no-such.pub -o ecrepo2 --create
  check "makes nothing" test ! -e ecrepo2
  expect 2 "capture into it with no keys" -- "$BIN" capture -r rtree --os=linux -o erepo
  contains "$ERR" "is an encrypted repository: give the public keys" "is refused, saying why"
  expect 0 "capture into it" -- \
    env XDG_CACHE_HOME="$WORK/cache" GNUPGHOME="$WORK/nokey" \
    "$BIN" capture -r rtree --os=linux --encrypt-to enc.pub -o erepo
  check "its packs' indexes are encrypted" sh -c '! cat erepo/packs/*.idx | grep restate-pack > /dev/null'
  check "and its snapshots' indexes" sh -c '! gzip -t erepo/snapshots/*/index.json.gz 2> /dev/null'
  expect 0 "capture into it again, with no secret key" -- \
    env XDG_CACHE_HOME="$WORK/cache" GNUPGHOME="$WORK/nokey" \
    "$BIN" capture -r rtree --os=linux --encrypt-to enc.pub -o erepo --result ecap.json
  contains "$(cat ecap.json)" "\"cache\": {\"path\": \"$WORK/cache/restate/repositories/" \
    "the result names this machine's cache of it"
  check "and how much it holds" \
    sh -c '! grep -q "\"cache\": {[^}]*\"bytes\": 0}" ecap.json && grep -q "\"bytes\": " ecap.json'
  contains "$ERR" "unchanged since the last snapshot were not read" "reads only what changed"
  mkdir -p erout
  expect 2 "restore it without the secret key" -- \
    env XDG_CACHE_HOME="$WORK/cache" GNUPGHOME="$WORK/nokey" \
    "$BIN" restore --allow-unverified --root erout erepo
  contains "$ERR" "could not be decrypted" "says why"
  expect 0 "restore it with the secret key" -- \
    env XDG_CACHE_HOME="$WORK/cache" GNUPGHOME="$WORK/gnupg" \
    "$BIN" restore --allow-unverified --root erout erepo
  check "its files back" cmp rtree/etc/app/key erout/etc/app/key
  expect 0 "snapshots, with the secret key" -- \
    env XDG_CACHE_HOME="$WORK/cache" GNUPGHOME="$WORK/gnupg" "$BIN" snapshots erepo
  contains "$OUT" "files," "lists them with their summaries"
  expect 0 "prune it" -- \
    env XDG_CACHE_HOME="$WORK/cache" GNUPGHOME="$WORK/gnupg" \
    "$BIN" prune --keep-last 1 --encrypt-to enc.pub erepo
  contains "$OUT" "dropped" "drops the older"
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
  kit_holds() { part self.tar kit.tar.gz | gzip -dc | tar -tf - | grep -x "restate/files$1" > /dev/null; }
  check "the kit holds the restate binary" kit_holds "$(readlink -f "$BIN")"
fi

# What is live: a process that looks like a database to /proc is named by
# capture, and with --quiesce its hook pauses it while its files are copied.
# A script called redis-server, running in its data directory, is Redis as far
# as /proc can tell: a script's comm is its own name. (A copy of sleep is not,
# where sleep is a multi-call coreutils that goes by the name it is run as.) Root's, Linux's, and only on a machine with
# no /etc/restate of its own: the test puts a hook there and takes it away.
if [ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] && [ -d /proc/self ] && [ ! -e /etc/restate ] &&
   [ ! -e /srv/restate-redis ] && [ ! -e /var/lib/restate ]; then
  mkdir -p /srv/restate-redis /etc/restate/hooks.d
  echo data > /srv/restate-redis/dump.rdb
  printf '#!/bin/sh\ntrap "exit 0" TERM\nwhile :; do sleep 1; done\n' > "$WORK/redis-server"
  chmod 0755 "$WORK/redis-server"
  ( cd /srv/restate-redis && exec "$WORK/redis-server" ) &
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
{ echo "\$1 \$2 uid=\$RESTATE_UID quiesce=\$RESTATE_QUIESCE"; echo "\$RESTATE_PATHS"; echo "dump=\$RESTATE_DUMP_DIR"; } >> "$WORK/hook.log"
[ "\$1" = pause ] && echo dumped > "\$RESTATE_DUMP_DIR/dump.txt"
exit 0
HOOK
  chmod 0755 /etc/restate/hooks.d/redis
  expect 0 "with --quiesce, through its hook" -- "$BIN" capture -N -R live.rules --quiesce -o live.tar
  contains "$ERR" "pausing Redis redis-server" "it says it is pausing it"
  contains "$ERR" "resumed Redis redis-server" "and that it resumed it"
  hook_log="$(cat "$WORK/hook.log" 2> /dev/null)"
  contains "$hook_log" "pause redis-server uid=0 quiesce=yes" "the hook is told what to pause"
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
  expect 3 "a hook that cannot pause" -- "$BIN" capture -N -R live.rules --quiesce -o live.tar \
    --result live.json
  contains "$ERR" "was not paused" "is warned about"
  contains "$ERR" "resumed Redis redis-server" "and resume is run anyway"
  contains "$ERR" "the capture is incomplete" "and the capture is incomplete"
  contains "$(cat live.json)" '"status": "failed"' "the result says the pause failed"
  contains "$(cat live.json)" '"kind": "redis"' "and of what"

  # A hook --quiesce-with names: run whether or not anything is found, for
  # the paths it says it covers -- or, naming none, for the whole walk.
  mkdir -p /srv/restate-named
  echo named > /srv/restate-named/data
  cat > /etc/restate/hooks.d/named <<HOOK
#!/bin/sh
case "\$1" in
paths) echo /srv/restate-named ;;
*) echo "\$1 \$2" >> "$WORK/named.log" ;;
esac
exit 0
HOOK
  chmod 0755 /etc/restate/hooks.d/named
  expect 0 "capture --quiesce-with a hook" -- \
    "$BIN" capture -N -R live.rules --quiesce-with named -o live.tar --result named.json
  contains "$(cat "$WORK/named.log")" "pause named" "its hook pauses it"
  contains "$(cat "$WORK/named.log")" "resume named" "and resumes it"
  contains "$(cat named.json)" '"kind": "named"' "the result says what it paused"
  contains "$(cat named.json)" '"status": "ok"' "and that it went well"
  contains "$(part live.tar files.tar.gz | gzip -dc | tar -tf -)" "srv/restate-named/data" \
    "and what it covers is in the image"
  printf '#!/bin/sh\nexit 0\n' > /etc/restate/hooks.d/whole
  chmod 0755 /etc/restate/hooks.d/whole
  expect 0 "capture --quiesce-with a hook that names no paths" -- \
    "$BIN" capture -N -R live.rules --quiesce-with whole -o live.tar
  contains "$ERR" "pausing whole whole" "it is paused, for the whole walk"
  expect 2 "capture --quiesce-with a hook there is not" -- \
    "$BIN" capture -N -R live.rules --quiesce-with nosuch -o live.tar
  contains "$ERR" "there is no hook by that name" "says so"
  # One that says what it pauses is not on this host: a policy every host
  # shares may name it. It is left out of features, and not run.
  cat > /etc/restate/hooks.d/gone <<HOOK
#!/bin/sh
case "\$1" in
present) echo absent ;;
*) echo "\$1 \$2" >> "$WORK/gone.log" ;;
esac
exit 0
HOOK
  chmod 0755 /etc/restate/hooks.d/gone
  expect 0 "capture --quiesce-with a hook for what is not here" -- \
    "$BIN" capture -N -R live.rules --quiesce-with gone -o live.tar
  contains "$ERR" "--quiesce-with gone: /etc/restate/hooks.d/gone says there is none on this host" \
    "says so"
  check "and does not run it" test ! -e "$WORK/gone.log"
  expect 0 "features, with that hook" -- "$BIN" features --json
  contains "$OUT" '"named"' "lists a hook that does not say"
  lacks "$OUT" '"gone"' "and leaves out one for what is not here"
  # One that covers where something found running keeps its files pauses it:
  # UniFi's own mongod is the unifi hook's, not the mongodb hook's.
  cat > /etc/restate/hooks.d/owner <<HOOK
#!/bin/sh
case "\$1" in
paths) echo /srv/restate-redis ;;
*) echo "\$1 \$2 quiesce=\$RESTATE_QUIESCE" >> "$WORK/owner.log" ;;
esac
exit 0
HOOK
  chmod 0755 /etc/restate/hooks.d/owner
  # The redis hook fails to pause, by now: run, it would make this exit 3.
  expect 0 "capture --quiesce-with a hook that covers what is running" -- \
    "$BIN" capture -N -R live.rules --quiesce --quiesce-with owner -o live.tar
  contains "$ERR" "Redis redis-server is owner's own, and paused with it" "says whose it is"
  contains "$(cat "$WORK/owner.log")" "pause owner quiesce=yes" "pauses it with its own hook"
  rm -rf /srv/restate-named

  chmod 0777 /etc/restate/hooks.d/redis
  expect 0 "a hook anyone could change" -- "$BIN" capture -N -R live.rules --quiesce -o live.tar
  contains "$ERR" "no hook pauses redis" "is not run"

  # One capture --quiesce at a time on a machine.
  if command -v flock > /dev/null 2>&1; then
    flock /run/restate/capture.lock sleep 3 &
    locker=$!
    sleep 1
    expect 5 "capture --quiesce while another runs" -- \
      "$BIN" capture -N -R live.rules --quiesce -o live.tar
    contains "$ERR" "another capture with --quiesce is running on this machine" "says why"
    wait "$locker"
  fi

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
  eval 'part aimg.tar kit.tar.gz | gzip -dc | tar -tf - | grep -x restate/files/etc/passwd > /dev/null'
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
# For a program running restate: results, progress, JSON, jobs, and the
# checks and prunes the storage can make without the keys
# ---------------------------------------------------------------------------
mkdir -p ptree/etc ptree/srv/data pstage
echo one > ptree/etc/one
echo two > ptree/srv/data/two
dd if=/dev/zero bs=1000 count=300 2> /dev/null | tr '\0' 'x' > ptree/srv/data/big

expect 0 "features" -- "$BIN" features
contains "$OUT" "job schema 1, result schema 1" "says what it can do"
expect 0 "features --json" -- "$BIN" features --json
contains "$OUT" '"job_schema": 1' "as JSON: the job schema"
contains "$OUT" '"result_schema": 1' "the result schema"
contains "$OUT" '"run"' "its commands"
contains "$OUT" '"quiesce_with"' "its options, as job keys spell them"
contains "$OUT" '"job_keys": [' "the keys a job takes"
contains "$OUT" '"job_commands": [' "the commands a job can be"
contains "$OUT" '"job_command_keys": {' "the keys each takes"
contains "$OUT" '"status.capture_rules"' "and that status says how it classified"
contains "$OUT" '"capture.cache"' "what results have gained"
contains "$OUT" '"programs": {' "and the programs it can use"

expect 0 "estimate" -- "$BIN" estimate -N -r ptree
contains "$OUT" "/srv/data" "says where the bytes are"
contains "$OUT" "in 3 files a first capture would keep" "and how many files"
expect 0 "estimate --json --result" -- "$BIN" estimate -N -r ptree --json --result est.json
contains "$OUT" '"by_dir": {' "as JSON"
contains "$(cat est.json)" '"command": "estimate"' "and in the result"

expect 2 "a failure, in the result" -- "$BIN" capture -N -r ptree --result fail.json
contains "$(cat fail.json)" '"status": "failed"' "the status"
contains "$(cat fail.json)" '"exit": 2' "and the exit status"
contains "$(cat fail.json)" '"errors": ["capture writes an image to a file' "and why"
contains "$(cat fail.json)" '"errors_count": 1' "counted"

expect 0 "init a repository for programs" -- "$BIN" init -q prepo
expect 0 "capture --result --progress-file" -- \
  "$BIN" capture -N -r ptree -q -o prepo --result cap.json --progress-file cap.ndjson
res="$(cat cap.json)"
contains "$res" '"command": "capture"' "the result names the command"
contains "$res" '"status": "ok"' "how it ended"
contains "$res" '"snapshot": "prepo::' "the snapshot"
contains "$res" '"new_bytes": ' "what was new"
contains "$res" '"repository_bytes": ' "and what the repository holds now"
contains "$res" '"cache": null' "and that it has no cache, not being encrypted"
check "the result is its owner's alone" test "$(file_mode cap.json)" = 600
contains "$(cat cap.ndjson)" '"phase": "walk"' "progress, a line at a time"
contains "$(cat cap.ndjson)" '"phase": "finish"' "to the end"
expect 0 "capture --report-group" -- \
  "$BIN" capture -N -r ptree -q -o prepo --result cap2.json --report-group "$(id -gn)"
check "the result is the group's to read too" test "$(file_mode cap2.json)" = 640
expect 2 "--report-group a group there is not" -- \
  "$BIN" capture -N -r ptree -q -o prepo --result cap3.json --report-group no-such-group-here
contains "$ERR" "there is no such group" "says so"
expect 0 "--progress=json" -- "$BIN" capture -N -r ptree -q -o prepo --progress=json
contains "$ERR" '{"phase": "walk"' "progress as JSON on standard error"
expect 2 "--progress=something else" -- "$BIN" capture -N -r ptree -o prepo --progress=yes
expect 0 "capture --append-only" -- "$BIN" capture -N -r ptree -q -o prepo --append-only
expect 2 "capture --append-only into an image" -- "$BIN" capture -N -r ptree -o pa.tar --append-only
contains "$ERR" "an image is written whole" "is refused"
expect 0 "capture --create, where there is no repository" -- \
  "$BIN" capture -N -r ptree -q -o newrepo --create --result cr1.json
check "makes one" test -f newrepo/restate-repository
check "its owner's alone" test "$(file_mode newrepo)" = 700
contains "$(cat cr1.json)" '"created_repository": true' "and says so in the result"
contains "$(cat cr1.json)" '"snapshot": "' "and captures into it"
expect 0 "capture --create, where there is one" -- \
  "$BIN" capture -N -r ptree -q -o newrepo --create --result cr2.json
contains "$(cat cr2.json)" '"created_repository": false' "makes nothing"
mkdir -m 700 cempty
expect 0 "capture --create --append-only into an empty directory" -- \
  "$BIN" capture -N -r ptree -q -o cempty --create --append-only
check "makes one there" test -f cempty/restate-repository
mkdir cfull
printf 'mine\n' > cfull/notes
expect 2 "capture --create into a directory with something else in it" -- \
  "$BIN" capture -N -r ptree -q -o cfull --create
contains "$ERR" "--create: " "is refused"
check "and writes nothing there" test "$(ls -A cfull)" = notes
expect 2 "capture --create where the parent is not there" -- \
  "$BIN" capture -N -r ptree -q -o cnone/repo --create
check "makes no parent" test ! -e cnone
expect 0 "capture --tmpdir" -- "$BIN" capture -N -r ptree -q -o pt.tar --tmpdir "$WORK/pstage"
check "nothing is left where it was staged" rmdir pstage

expect 0 "snapshots --json" -- "$BIN" snapshots --json prepo
contains "$OUT" '"snapshots": [' "lists them as JSON"
contains "$OUT" '"signed": false' "with whether each is signed"
expect 0 "du" -- "$BIN" du prepo
contains "$OUT" "needs      alone      added" "says what each snapshot needs"
expect 0 "du --json" -- "$BIN" du --json prepo
contains "$OUT" '"pack_bytes": ' "as JSON"

expect 0 "check --metadata-only" -- "$BIN" check --metadata-only prepo
contains "$ERR" "as far as can be told without reading its indexes" "says what it checked"
expect 2 "check --metadata-only --read-all" -- "$BIN" check --metadata-only --read-all prepo
expect 0 "check --record, the first" -- "$BIN" check --metadata-only --record prec prepo
expect 0 "check --record, again" -- "$BIN" check --record prec --result chk.json prepo
contains "$ERR" "0 files removed or changed since the last check" "nothing changed"
contains "$(cat chk.json)" '"recorded": true' "the result says so"
cp -R prepo ptamper
cp prec ptrec
for pack in ptamper/packs/*.tar.gz; do
  printf x >> "$pack"
  break
done
expect 3 "check --record a pack changed since" -- "$BIN" check --metadata-only --record ptrec ptamper
contains "$ERR" "changed since the last check" "says what changed"
contains "$ERR" "not what its .sum says" "and that it is not what it was written as"

expect 0 "copy" -- "$BIN" copy prepo poff
contains "$ERR" "made for it" "makes the copy's repository"
expect 0 "copy it again" -- "$BIN" copy prepo poff
contains "$ERR" "is in poff already" "copies nothing twice"
expect 0 "check the copy" -- "$BIN" check -q poff
expect 2 "copy what is not a repository" -- "$BIN" copy ptree poff
# How many files in DIR end in SUFFIX.
howmany() { find "$1" -name "*$2" | wc -l | tr -d ' '; }
check "every pack has a .seek" test "$(howmany prepo/packs .seek)" -eq "$(howmany prepo/packs .idx)"
check "and its copy has it too" test "$(howmany poff/packs .seek)" -eq "$(howmany poff/packs .idx)"

# repack: packs as an older restate wrote them, with no .seek.
cp -R prepo pold
rm -f pold/packs/*.seek
expect 0 "repack --dry-run" -- "$BIN" repack --dry-run pold
contains "$OUT" "would write again $(howmany pold/packs .idx) packs" "says how many"
check "and writes nothing" test "$(howmany pold/packs .seek)" -eq 0
expect 0 "repack" -- "$BIN" repack --syslog --record pold.rec --result rk.json pold
contains "$ERR" "wrote again" "says what it did"
contains "$(cat rk.json)" '"packs_rewritten": ' "and its result too"
check "every pack has a .seek now" test "$(howmany pold/packs .seek)" -eq "$(howmany pold/packs .idx)"
expect 0 "and a repack finds nothing to do" -- "$BIN" repack --dry-run pold
contains "$OUT" "would write again 0 packs" "says so"
expect 0 "check what repack wrote" -- "$BIN" check -q --read-all pold
expect 0 "check its record" -- "$BIN" check -q --metadata-only --record pold.rec pold
mkdir -p rkout
expect 0 "restore --include from it" -- \
  "$BIN" restore --allow-unverified --include /etc --root rkout pold
check "puts back what it should" test -f rkout/etc/one
expect 2 "repack what is not a repository" -- "$BIN" repack ptree

# protect: what is finished made read-only, the directories sticky -- or, where
# the filesystem has NFSv4 ACLs, 0770 with an ACL that says the same. For this
# user's group -- or nobody's, as root, whose own group protect refuses.
pgroup="--group=$(id -gn)"
if [ "$(id -u)" = 0 ]; then
  pgroup="--group=$(id -gn nobody)"
fi
cp -R prepo pprot
expect 0 "protect" -- "$BIN" protect "$pgroup" --syslog --result pr.json pprot
contains "$ERR" "restate: protected " "says what it did"
contains "$(cat pr.json)" '"files_protected": ' "and its result too"
contains "$(cat pr.json)" '"not_protected": 0' "with nothing it could not"
check "a pack is read-only" test "$(file_mode "$(find pprot/packs -name '*.idx' | head -n 1)")" = 440
check "and so is a snapshot" \
  test "$(file_mode "$(find pprot/snapshots -mindepth 1 -maxdepth 1 | head -n 1)")" = 550
if getfacl -q pprot/packs 2> /dev/null | grep -q '^ *group@:----D---------:-------:deny$'; then
  check "packs/ is its group's to add to, and to remove nothing from" \
    test "$(file_mode pprot/packs)" = 770
else
  check "packs/ is sticky" test "$(file_mode pprot/packs)" = 1770
fi
check "the lock is left as it was" test "$(file_mode pprot/lock)" = 600
expect 0 "protect again" -- "$BIN" protect "$pgroup" --result pr2.json pprot
contains "$(cat pr2.json)" '"files_protected": 0' "changes nothing"
expect 0 "capture --append-only into it" -- "$BIN" capture -N -r ptree -q -o pprot --append-only
expect 0 "check it" -- "$BIN" check -q --read-all pprot
expect 0 "du it" -- "$BIN" du pprot
mkdir -p prout
expect 0 "restore from it" -- "$BIN" restore --allow-unverified --include /etc --root prout pprot
check "puts back what it should" test -f prout/etc/one
ln -s ../../ptree/etc/one pprot/packs/planted.idx
expect 3 "protect, with a link planted" -- "$BIN" protect "$pgroup" pprot
contains "$ERR" "planted.idx: not a regular file" "touches it not, and says so"
rm -f pprot/packs/planted.idx
expect 2 "protect for a group that is not there" -- \
  "$BIN" protect --group restate-no-such-group pprot
contains "$ERR" "no such group" "says so"
expect 2 "protect what is not a repository" -- "$BIN" protect "$pgroup" ptree
chmod -R u+w pprot

# As a share is used: a machine mapped to one user, in the repository's
# group, captures into it; root protects it on the storage. Linux's, as root,
# where users can be made for it and are not there already.
if [ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] && command -v runuser > /dev/null 2>&1 &&
   command -v useradd > /dev/null 2>&1 && ! getent passwd restate-cli > /dev/null &&
   ! getent group restate-cli > /dev/null; then
  groupadd restate-cli
  useradd -M -N -g restate-cli -s /bin/sh restate-cli
  shared="$(mktemp -d /tmp/restate-shared.XXXXXX)"
  chmod 0755 "$shared"
  mkdir -p "$shared/tree/etc" "$shared/repo"
  echo one > "$shared/tree/etc/one"
  chmod -R a+rX "$shared/tree"
  chown root:restate-cli "$shared/repo"
  chmod 1770 "$shared/repo"
  # Called through expect and check.
  # shellcheck disable=SC2317,SC2329
  machine() { runuser -u restate-cli -- "$@"; }
  expect 0 "a machine's capture --create --append-only into a directory made ready" -- \
    machine "$BIN" capture -N -r "$shared/tree" -q -o "$shared/repo" --create --append-only
  check "which stays sticky" test "$(file_mode "$shared/repo")" = 1770
  expect 0 "protect it, as root" -- "$BIN" protect --result "$shared/p.json" "$shared/repo"
  contains "$(cat "$shared/p.json")" '"group": "restate-cli"' "for the repository's group"
  spack="$(find "$shared/repo/packs" -name '*.tar.gz' | head -n 1)"
  ssnap="$(find "$shared/repo/snapshots" -mindepth 1 -maxdepth 1 | head -n 1)"
  # Called through check: whether the machine is refused what it asks.
  # shellcheck disable=SC2317,SC2329
  refused() { ! runuser -u restate-cli -- "$@" 2> /dev/null; }
  check "the machine cannot remove a pack" refused rm -f "$spack"
  check "nor overwrite one" refused dd if=/dev/null of="$spack"
  check "nor rename one" refused mv "$spack" "$spack.x"
  check "nor change its mode" refused chmod 0644 "$spack"
  check "nor remove a snapshot" refused rm -rf "$ssnap"
  check "nor packs/" refused rm -rf "$shared/repo/packs"
  check "and the pack is there" test -s "$spack"
  check "and the snapshot" test -f "$ssnap/index.json.gz"
  echo two > "$shared/tree/etc/two"
  chmod a+r "$shared/tree/etc/two"
  expect 0 "the machine still adds snapshots" -- \
    machine "$BIN" capture -N -r "$shared/tree" -q -o "$shared/repo" --append-only
  expect 0 "and checks them" -- machine "$BIN" check -q --read-all "$shared/repo"
  expect 0 "root prunes it on the storage" -- "$BIN" prune -q --keep-last 1 "$shared/repo"
  expect 0 "and repacks it" -- "$BIN" repack -q "$shared/repo"
  expect 0 "and checks it" -- "$BIN" check -q "$shared/repo"
  expect 0 "and the machine still reads what root wrote" -- \
    machine "$BIN" check -q --read-all "$shared/repo"
  expect 0 "protect it again, as root" -- "$BIN" protect -q "$shared/repo"
  rm -rf "$shared"
  userdel restate-cli 2> /dev/null
  getent group restate-cli > /dev/null && groupdel restate-cli
fi

mkdir -p pout
expect 0 "restore --include --dry-run --result" -- \
  "$BIN" restore --allow-unverified --dry-run --include /etc --root pout --result rs.json prepo
contains "$(cat rs.json)" '"plan": [' "the result holds the plan"
contains "$(cat rs.json)" "/etc/one" "of what is included"
lacks "$OUT" "/srv/data/two" "and nothing else"
contains "$(cat rs.json)" '"content_read": true' "having read what it says it would put back"
cp -R prepo pnopacks
rm -f pnopacks/packs/*
expect 0 "restore --plan, with no pack to read" -- \
  "$BIN" restore --allow-unverified --plan --include /etc --root pout --result rp.json pnopacks
contains "$(cat rp.json)" '"content_read": false' "the result says nothing was read"
contains "$(cat rp.json)" '"dry_run": true' "and that nothing was written"
contains "$(cat rp.json)" "/etc/one" "the plan is the dry run's"
contains "$ERR" "planned from the index alone" "and says so"
check "writes nothing" test -z "$(ls -A pout)"
expect 2 "restore --plan --check-first" -- \
  "$BIN" restore --allow-unverified --plan --check-first --root pout prepo
contains "$ERR" "give --dry-run instead" "is refused"

if command -v python3 > /dev/null 2>&1; then
  # A TERM that came before it started, held over the exec, so that the
  # prune stops at its first chance rather than at a moment raced for.
  expect 3 "prune stopped by SIGTERM" -- python3 -c 'import os, signal, sys
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
os.kill(os.getpid(), signal.SIGTERM)
os.execv(sys.argv[1], sys.argv[1:])' \
    "$BIN" prune --whole-packs --keep-last 1 --record prec --result pt.json prepo
  contains "$ERR" "prune: stopped by SIGTERM" "says why"
  contains "$(cat pt.json)" '"status": "incomplete"' "the result says it did not finish"
  contains "$(cat pt.json)" '"errors": ["prune: stopped by SIGTERM' "and why"
  expect 0 "check --record after the stopped prune" -- \
    "$BIN" check --metadata-only --record prec prepo
  contains "$ERR" "0 files removed or changed since the last check" "its record follows it"
fi
expect 0 "prune --whole-packs" -- \
  "$BIN" prune --whole-packs --keep-last 1 --record prec --result pr.json prepo
contains "$(cat pr.json)" '"pruned": [' "the result says what it dropped"
contains "$(cat pr.json)" '"kept_snapshots": [' "and what it kept"
expect 0 "check --record after the prune" -- "$BIN" check --record prec prepo
contains "$ERR" "0 files removed or changed since the last check" "a prune with the record is expected"

expect 0 "capture an image to compare" -- "$BIN" capture -N -r ptree -q -o pd1.tar
echo three > ptree/etc/three
expect 0 "and another, after a change" -- "$BIN" capture -N -r ptree -q -o pd2.tar
expect 1 "diff --json" -- "$BIN" diff --json pd1.tar pd2.tar
contains "$OUT" '"change": "A", "path": "/etc/three"' "a diff as JSON"
expect 1 "verify --json" -- "$BIN" verify --json --root ptree pd1.tar
contains "$OUT" '"changes": [' "as JSON"
contains "$OUT" '"path": "' "each change a path"
contains "$OUT" '"added": 1' "with the counts"
expect 1 "status --json" -- "$BIN" status --json --root ptree pd1.tar
contains "$OUT" '"change": "A"' "status as JSON too"

# Jobs: the run, decided by a file only its owner can change.
mkdir -m 755 jobs
cat > jobs/check.conf <<JOB
# a check, as a program would schedule one
command = check
repository = $WORK/prepo
result = $WORK/job.json
JOB
chmod 644 jobs/check.conf
expect 0 "run a job" -- "$BIN" run "$WORK/jobs/check.conf"
contains "$(cat job.json)" '"command": "check"' "the job's result"
contains "$(cat job.json)" '"job": "' "names the job"
expect 2 "run a job with an option it does not take" -- "$BIN" run --root / "$WORK/jobs/check.conf"
contains "$ERR" "what to do is the job's to say" "is refused"
chmod 664 jobs/check.conf
expect 2 "run a job others can change" -- "$BIN" run "$WORK/jobs/check.conf"
contains "$ERR" "writable by no one else" "is refused"
chmod 644 jobs/check.conf
printf 'command = check\nrepository = %s/prepo\nshell = rm -rf /\n' "$WORK" > jobs/bad.conf
chmod 644 jobs/bad.conf
expect 2 "run a job with a key that is not one" -- "$BIN" run "$WORK/jobs/bad.conf"
contains "$ERR" "is not a key a job can have" "says which"
expect 2 "run a job that is not there" -- "$BIN" run "$WORK/jobs/none.conf"
printf 'command = capture\nrepository = %s/prepo\nroot = %s/ptree\nrules = %s/nothing-at-all.rules\n' \
  "$WORK" "$WORK" "$WORK" > jobs/cap.conf
chmod 644 jobs/cap.conf
expect 2 "run a capture job whose rules are not there" -- "$BIN" run "$WORK/jobs/cap.conf"
printf 'command = capture\nrepository = %s/jrepo\nroot = %s/ptree\ncreate = true\nresult = %s/jcr.json\n' \
  "$WORK" "$WORK" "$WORK" > jobs/create.conf
chmod 644 jobs/create.conf
expect 0 "run a capture job that makes its repository" -- "$BIN" run -q "$WORK/jobs/create.conf"
check "makes it" test -f jrepo/restate-repository
contains "$(cat jcr.json)" '"created_repository": true' "and says so in the result"
printf 'command = status\nrepository = %s/jrepo\nresult = %s/jst.json\n' "$WORK" "$WORK" > jobs/status.conf
chmod 644 jobs/status.conf
expect 0 "run a status job" -- "$BIN" run -q "$WORK/jobs/status.conf"
contains "$(cat jst.json)" '"command": "status"' "its result"
contains "$(cat jst.json)" '"snapshot": "'"$WORK"'/jrepo::' "names the newest snapshot"
contains "$(cat jst.json)" '"changes": []' "and what changed since: nothing"
printf 'command = list\nrepository = %s/jrepo\npath = /srv\nresult = %s/jls.json\n' "$WORK" "$WORK" > jobs/list.conf
chmod 644 jobs/list.conf
expect 0 "run a list job" -- "$BIN" run -q "$WORK/jobs/list.conf"
contains "$(cat jls.json)" '"path": "/srv"' "its result names the directory"
contains "$(cat jls.json)" '"name": "data"' "and what is in it"
# A status job classifies as the capture did: what its rules left out is not
# "added", unless the job gives rules of its own.
printf 'expendable /srv/data\n' > jskip.rules
printf 'command = capture\nrepository = %s/jrepo2\nroot = %s/ptree\ncreate = true\nrules = %s/jskip.rules\n' \
  "$WORK" "$WORK" "$WORK" > jobs/cap2.conf
chmod 644 jobs/cap2.conf
expect 0 "run a capture job with rules of its own" -- "$BIN" run -q "$WORK/jobs/cap2.conf"
printf 'command = status\nrepository = %s/jrepo2\nroot = %s/ptree\nresult = %s/jst2.json\n' \
  "$WORK" "$WORK" "$WORK" > jobs/status2.conf
chmod 644 jobs/status2.conf
expect 0 "a status job classifies by the capture's rules" -- "$BIN" run -q "$WORK/jobs/status2.conf"
contains "$(cat jst2.json)" '"capture_rules": true' "says so"
contains "$(cat jst2.json)" '"added": 0' "and nothing they left out is added"
: > jnone.rules
printf 'rules = %s/jnone.rules\nall = false\none_file_system = false\n' "$WORK" >> jobs/status2.conf
expect 1 "a status job with rules of its own" -- "$BIN" run -q "$WORK/jobs/status2.conf"
contains "$(cat jst2.json)" '"capture_rules": false' "classifies by those"
contains "$(cat jst2.json)" '"path": "/srv/data/big"' "and finds what the capture left out"
expect 1 "status --all adds to the capture's rules" -- \
  "$BIN" status --all --root ptree --result jst3.json jrepo2
contains "$(cat jst3.json)" '"capture_rules": true' "keeping them"
contains "$(cat jst3.json)" '"path": "/srv/data"' "and reports the expendable"
printf '{"format": "restate-index", "version": 1, "classification": {"rules": 5}, "entries": []}' \
  > badcl.json
expect 2 "status of an index whose classification is not rules" -- "$BIN" status badcl.json
contains "$ERR" "the index's classification is not a list of rules" "says so"
# A refused job still writes its result, if it names one.
printf 'command = status\nrepository = %s/jrepo2\npath = /etc\nresult = %s/jbad.json\n' \
  "$WORK" "$WORK" > jobs/refused.conf
chmod 644 jobs/refused.conf
expect 2 "a job refused" -- "$BIN" run -q "$WORK/jobs/refused.conf"
contains "$(cat jbad.json)" '"status": "failed"' "writes a failed run's result"
contains "$(cat jbad.json)" '"command": "status"' "for the command it names"
contains "$(cat jbad.json)" 'path means nothing to a status job' "with why"

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
