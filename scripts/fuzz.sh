#!/usr/bin/env bash
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# Throw mutated input at every parser restate has.
#
#   make fuzz                         30 seconds
#   FUZZ_SECONDS=600 make fuzz        longer
#   FUZZ_SEED=12345 make fuzz         reproduce a built-in-loop run
#   FUZZ_ENGINE=builtin make fuzz     skip libFuzzer even where clang is present
#
# The target is tests/fuzz/fuzz_restate.c: indexes, tar streams, rules files,
# patterns, timestamps, base64, LVM and LUKS metadata and checksum files,
# chosen by the first byte of each input. Two engines:
#
#   libFuzzer                   coverage-guided, and far better at reaching
#                               deep paths; used when clang can build it
#   the built-in mutation loop  runs anywhere the compiler in use supports the
#                               sanitizers, so fuzzing is not something that
#                               only happens on machines with clang
#
# Either way the target is built with AddressSanitizer and UndefinedBehavior-
# Sanitizer, because the fuzzer does not decide what a bug is -- they do.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

FUZZ_SECONDS="${FUZZ_SECONDS:-30}"
FUZZ_SEED="${FUZZ_SEED:-0}"
CC="${CC:-cc}"
VERSION="$(cat VERSION)"
WORK=".fuzz"

ok()   { printf '  \033[92m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[91m✗\033[0m %s\n' "$*"; }
note() { printf '    \033[2m%s\033[0m\n' "$*"; }

printf '\n\033[1mFuzzing\033[0m \033[2m(%ss)\033[0m\n' "$FUZZ_SECONDS"

mkdir -p "$WORK/corpus"

# ---------------------------------------------------------------------------
# The seed corpus: a valid example of each kind of input. A fuzzer with a poor
# corpus spends its whole run rediscovering what JSON is. The selector byte
# comes first: 0 index, 1 rules, 2 pattern+path, 3 tar, 4 time, 5 base64,
# 6 LVM metadata, 7 LUKS header.
# ---------------------------------------------------------------------------
# seed NAME SELECTOR BODY -- BODY may use \t, \n, \0 and \\ escapes.
seed() {
  local name="$1" selector="$2" body="$3"
  printf '%b%b' "\\0$(printf '%03o' "$selector")" "$body" > "$WORK/corpus/$name"
}

INDEX='{"format": "restate-index", "version": 1, "root": "/", "os": "linux", "hashed": true, "entries": [
{"path": "/", "name": "/", "type": "directory", "class": "state", "mode": "0755", "uid": 0, "user": "root", "gid": 0, "group": null, "size": 0, "nlink": 3, "device": 1, "inode": 2, "atime": "2026-10-03T00:00:00.000000000Z", "mtime": "2026-10-03T00:00:00.000000000Z", "ctime": "@-1.000000000", "btime": null, "sha256": null},
{"path": "/etc/hosts", "name": "hosts", "type": "file", "class": "state", "mode": "0644", "uid": 0, "gid": 0, "size": 0, "mtime": "2024-02-29T23:59:59.999999999Z", "xattrs": [{"name": "user.a", "value": "AAE="}, {"name": "x", "name_base64": "dXNlci5i/w==", "value": ""}], "package": "netbase", "modified": true, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "stored": "restate/files/etc/hosts"},
{"path": "x", "path_base64": "L2V0Yy9h/w==", "type": "symlink", "class": "baseline", "mode": "0777", "uid": 1, "gid": 1, "size": 1, "mtime": "1970-01-01T00:00:00.000000000Z", "target": "\\u00e9\\ud83d\\ude00\\n"},
{"path": "/dev/x", "type": "char", "class": "state", "mode": "0600", "uid": 0, "gid": 0, "size": 0, "rdev": 259, "mtime": "2026-10-03T00:00:00.000000000Z", "unreadable": false}
]}'

# The seeds are written every run, into a corpus kept from the last one too:
# a seed added since -- a new parser's -- is in the run that first needs it.
fresh=0
[ -z "$(ls -A "$WORK/corpus" 2>/dev/null)" ] && fresh=1
{
  printf '\000%s' "$INDEX" > "$WORK/corpus/index-full"
  seed index-min 0 '{"format": "restate-index", "version": 1, "entries": []}'
  seed rules-builtin 1 '# comment\nephemeral /proc\nstate /etc\nexpendable /var/cache   # why\nbaseline /usr/**/lib\nephemeral *.pid\nstate /a\\*b\n'
  seed rules-bad 1 'keep /x\nstate\n'
  seed glob-anydirs 2 '/var/**/x\0/var/a/b/x'
  seed glob-unanchored 2 '*.pid\0/run/sshd.pid'
  seed glob-stars 2 '/*a*a*a*b\0/aaaaaaaaaaaaaaaaaaaa'
  seed glob-below 2 '/home/*/Downloads/c\0/home/bob/Downloads/c'
  seed time-iso 4 '2026-10-03T14:05:09.123456789Z'
  seed time-epoch 4 '@-62167219201.000000000'
  seed base64 5 'L2V0Yy9h/w=='
  seed lvm 6 'contents = "Text Format Volume Group"\nversion = 1\nvg0 {\n\tid = "x"\n\textent_size = 8192\n\tstatus = ["READ", "WRITE"]\n\tlogical_volumes {\n\t\troot {\n\t\t\tstripes = [\n\t\t\t\t"pv0", 0\n\t\t\t]\n\t\t}\n\t}\n}\n'
  seed accounts 10 'root:x:0:0:root:/root:/bin/bash\npostgres:x:128:135::/var/lib/postgresql:/bin/bash\npat:x:1000:1000:Pat:/home/pat:/bin/sh\n\0root:x:0:\nsudo:x:27:pat\npostgres:x:135:\n\0pat:!:1:0:99999:7:::\n\0\0root:x:0:0:root:/root:/bin/zsh\npostgres:x:125:131::/var/lib/postgresql:/bin/bash\npat:x:1000:1000:Pat Smith:/home/pat:/bin/zsh\nsam:x:1001:1001::/home/sam:/bin/bash\nold:x:127:128::/x:/y\n\0root:x:0:\nsudo:x:27:pat,sam\npostgres:x:131:\ndocker:x:999:pat\n\0pat:oldhash:1:0:99999:7:::\n\0sudo:*::pat,sam\n'
  seed packages 9 'Package: vim\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2:9.1-1\nDescription: x\n more\n .\n\nPackage: z\nStatus: hold ok half-configured\nArchitecture: all\nVersion: 1\n\0Package: vim\nArchitecture: amd64\nAuto-Installed: 1\n\0deb [arch=amd64 signed-by=/etc/apt/k.gpg] http://deb.example.com s main # c\n\0Types: deb\nURIs: https://x.example.com/a/\nSuites: ./\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n\nEnabled: no\nURIs: x\nSuites: y\n\0Package: vim\nArchitecture: amd64\nVersion: 2:9.1-1\n\0{"data": {"snaps": {"f": {"type": "app", "current": "x1", "channel": "latest/stable", "sequence": [{"side-info": {"revision": "x1"}}]}}}}\0root:x:0:0::/root:/bin/sh\nu:x:1000:1000::/home/u:/bin/sh\n\0manual\n/usr/bin/editor\n\0{"installs": {"rg 14.1.0 (registry+https://x)": {}}}'
  seed package-report 9 'apt installed htop 3.3\napt newer jq 1.7 1.8\napt failed gone 2\nsnap installed firefox\npip skipped requests 2.31\nalternatives installed editor /usr/bin/vim.basic\n'
  seed pkgdb 11 '/usr/bin/x\n/usr/bin/x.distrib\nother\n/a\n/b\n:\n\0Package: hello\nStatus: install ok installed\nArchitecture: amd64\nMulti-Arch: same\nConffiles:\n /etc/hello.conf f968f33f844c98de1d3b4fe70f2e1a0f\n /etc/old.conf f968f33f844c98de1d3b4fe70f2e1a0f obsolete\n /etc/new.conf newconffile\n\nPackage: gone\nStatus: deinstall ok config-files\n\0a723176f804503c15766073170b99298  usr/bin/hello\nf968f33f844c98de1d3b4fe70f2e1a0f *bin/x\n\0/.\n/usr\n/usr/bin/hello\n/bin/x\n'
  seed pkgdb-bsd 11 '\0\0\0\0@cwd /usr/pkg\n@name hello-2.12nb1\n@comment Packaged at x\n@ignore\n+BUILD_INFO\nbin/hello\n@comment MD5:f968f33f844c98de1d3b4fe70f2e1a0f\nshare/examples/hello/hello.conf\n@comment MD5:a723176f804503c15766073170b99298\n@pkgdir share/hello\n@cwd /usr/local\n@bin bin/x\n@sha 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n@size 0\n@sample /etc/x.conf\n@sample /etc/x.d/\n\0# FILE: etc/hello.conf c share/examples/hello/hello.conf 0644\n# FILE: /etc/rc.d/hello cr share/examples/hello/hello.conf 0755\n# DIR: etc m\n'
  # pkg's sums begin "1$" and "2$": not shell, but what pkg writes.
  # shellcheck disable=SC2016
  seed pkgdb-tools 11 '\0\0\0\0\0\0bash\t/usr/local\t2$8p4etf4zhq79gi3y6xmyx5sjsgj4wp6c7gbc334jjtewmxxwp6szkxfaqsj5ibgouy6n7du6se3618n51zbpw4qk1xdn4rxkj13y7un\t/usr/local/bin/bash\nbash\t/usr/local\t1$7de906afbe3c573fa88c8d70afc886239e2d0ae91e4a1035364a5461873ca936\t/usr/local/bin/bashbug\nx\t/\t-\t/usr/local/x\tab\n\0libgcc\t8\t0\t0\tc71a62b5ef442ab8cf4470874dee6f2383d73a744f0006b6d287412f131c2e09\t/lib64/libgcc_s.so.1\nlibgcc\t8\t1\t0\t231f7edcc7352d7734a96eef0b8030f77982678c516876fcb81e25b32d68564c\t/etc/x.conf\nold\t(none)\t64\t0\tf968f33f844c98de1d3b4fe70f2e1a0f\t/var/log/old\nold\t1\t0\t2\tf968f33f844c98de1d3b4fe70f2e1a0f\t/usr/share/doc/old\n'
  seed pkgdb-apk 11 '\0\0\0\0\0\0\0\0C:Q18Pz9wvTaBYr2RzvEXE6rYpFiJbI=\nP:alpine-baselayout\nV:3.7.2-r1\nF:etc\nR:motd\nZ:Q1SLkS9hBidUbPwwrw+XR0Whv3ww8=\nF:etc/crontabs\nR:root\na:0:0:600\nZ:Q2R5o5D0dFEdOGd8+aM6Ni3JByOxF8QrfLzXAO+gEO9sA=\nZ:Q1short\n\nP:musl\nR:ld-musl-x86_64.so.1\nZ:Q1vfk1apUWI4yLJGhhNRd0kJixfvY=\n\0#mtree\n/set type=file uid=0 gid=0 mode=644\n./.PKGINFO time=1 size=410 sha256digest=3c8c26ef78fb04300ffbdff779c61d0db5a7d41cb0574e9af2d76cd0a4cefcd8\n./etc time=1 mode=755 type=dir\n./etc/with\\040space time=1 sha256digest=9932c3a3d3bdbfb7e60501afda1bd8e591a7672df9c221dcf5083b48fbf7f83a\n./usr/bin/link type=link link=x\n./bad\\000nul time=1\n'
  seed live 12 'Name:\tpostgres\nPPid:\t1\nUid:\t133\t133\t133\t133\n\0pos:\t0\nflags:\t02100002\n\0storage:\n  dbPath: "/var/lib/mongodb"\n\0/usr/lib/postgresql/18/bin/postgres\0-D\0/var/lib/postgresql/18/main\0'
  seed repo 13 'restate-pack 1\n1 a6328afc76e9db71da297ebff4b0d3e7a7eb3b01d917c05a6573fef121b6ecb6 5\n2 - 9\n\n20261011T030000Z\n20261012T030000Z-2\nodd\n'
  seed repo2 13 'restate-pack 2\n1 a6328afc76e9db71da297ebff4b0d3e7a7eb3b01d917c05a6573fef121b6ecb6 5\n= b0f66adc83641586656866813fd9dd0b8ebb63796075661ba45d1aa8089e1d44 6 a6328afc76e9db71da297ebff4b0d3e7a7eb3b01d917c05a6573fef121b6ecb6 a6328afc76e9db71da297ebff4b0d3e7a7eb3b01d917c05a6573fef121b6ecb6\n'
  seed repo3 13 'restate-repository 2\nid 0123456789abcdef0123456789abcdef\nencrypted\n'
  seed openpgp 14 '-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: x\n\nAAEC\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n[GNUPG:] GOODSIG FC9CA96ACA026560 x\n[GNUPG:] VALIDSIG D55C0D1AC78A8D8126CB631CFC9CA96ACA026560 2026-10-08 1 0 4 0 1 8 01 D55C0D1AC78A8D8126CB631CFC9CA96ACA026560\nValid-Until: Sat, 17 Oct 2026 08:12:29 UTC\n'
  # Session keys at the head of an encrypted message: the keys it is to.
  seed openpgp-pkesk 14 '\0301\0012\0003\0001\0002\0003\0004\0005\0006\0007\0010\0022\0204\0012\0003\0021\0022\0023\0024\0025\0026\0027\0030\0001\0301\0030\0006\0025\0004\0240\0241\0242\0243\0244\0245\0246\0247\0250\0251\0252\0253\0260\0261\0262\0263\0264\0265\0266\0267\0031\0301\0003\0006\0000\0031\0322\0001\0001'
  seed openpgp-signature 14 '\0302\0062\0004\0000\0026\0012\0000\0035\0005\0002\0152\0000\0000\0000\0026\0041\0004\0166\0374\0135\0135\0207\0255\0316\0160\0323\0257\0207\0057\0256\0315\0077\0077\0160\0377\0012\0110\0000\0012\0011\0020\0256\0315\0077\0077\0160\0377\0012\0110\0022\0064\0001'
  seed apt 15 '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Ubuntu\nSHA256:\n bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb       907381 main/binary-amd64/Packages.gz\n- -----x\n-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n\0Package: hello\nVersion: 2:1.0\nArchitecture: amd64\nFilename: pool/h/hello_1.0_amd64.deb\nSize: 42\nSHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\n\0https://archive.ubuntu.com/ubuntu/ resolute-updates/main\0http://deb.debian.org/debian'
  seed clones 16 '# the lab\nname,mac,serial,address,gateway,dns\nweb1,52:54:00:00:00:01,,10.0.0.11/24,10.0.0.1,10.0.0.2 10.0.0.3\nweb2,,S4EW-2,fd00::12/64,fd00::1,\n'
  seed hosts 16 '127.0.0.1 localhost\n127.0.1.1\tweb1 web1.lan # web1\n::1 ip6-localhost\n'
  seed job 17 '# nightly\ncommand = capture\nrepository = /mnt/nas/r\nquiesce = true\nquiesce_with = unifi\nencrypt_to = /etc/restate/k.asc\nresult = /var/lib/restate/n.json\nreport_group = adm\n'
  seed job-restore 17 'command = restore\nsnapshot = /r::20261020T030000Z\nrestore_root = /var/tmp/x\ninclude = /home/bob\ndry_run = yes\n'
  seed storage 18 'restate-sum 1\nsha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nsize 42\n\0restate-packs 1\n20261020T030000Z-1-0001\n20261020T030000Z-1-0002\n\0restate-record 1\npacks/a.idx 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 10\nsnapshots/x/kit 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0\n\0restate-seek 1\n1 0\n9 100\n20 230\n'
  seed sha256sums 8 '1111111111111111111111111111111111111111111111111111111111111111 *ubuntu-26.04-live-server-amd64.iso\n2222222222222222222222222222222222222222222222222222222222222222 *ubuntu-26.04.1-live-server-amd64.iso\r\n3333333333333333333333333333333333333333333333333333333333333333  ubuntu-26.04.2-desktop-amd64.iso\n'
  # A LUKS2 header: magic, version 2, an 8 KiB header size, the binary
  # header padded to 4 KiB, then the JSON area padded to the 8 KiB it claims.
  {
    printf '\007LUKS\272\276\000\002\000\000\000\000\000\000\040\000'
    head -c 4080 /dev/zero
    printf '{"keyslots": {"0": {"area": {"key_size": 64}, "kdf": {"type": "argon2id"}}}, "segments": {"0": {"encryption": "aes-xts-plain64", "sector_size": 4096}}}'
    head -c 3900 /dev/zero
  } > "$WORK/corpus/luks2"
  # A real tar with the index as its first member, as an image holds it.
  SEED_TREE="$(mktemp -d)"
  mkdir -p "$SEED_TREE/restate"
  printf '%s' "$INDEX" > "$SEED_TREE/restate/index.json"
  { printf '\003'; ( cd "$SEED_TREE" && tar -cf - restate/index.json 2>/dev/null ); } \
    > "$WORK/corpus/tar-index"
  rm -rf "$SEED_TREE"
}
if [ "$fresh" = 1 ]; then
  ok "built a seed corpus of $(find "$WORK/corpus" -type f | wc -l | tr -d ' ') inputs"
else
  ok "reusing the corpus in $WORK/corpus, with the seeds written again"
fi

# Platform feature macros in one place; see scripts/features.sh.
read -r -a RS_FEATURES <<< "$(scripts/features.sh)"
CPPFLAGS_ALL=(-Iinclude -Isrc "${RS_FEATURES[@]}" -DRESTATE_VERSION="\"$VERSION\"")
SAN=("-fsanitize=address,undefined" -fno-sanitize-recover=all
     -fno-omit-frame-pointer -O1 -g)
# Every program source except main.c, globbed so a new file in src/ means the
# same thing here as in the Makefile.
SOURCES=()
for f in src/*.c; do
  [ "$f" = src/main.c ] || SOURCES+=("$f")
done
SOURCES+=(tests/fuzz/fuzz_restate.c)

# Without llvm-symbolizer a sanitizer report is a column of hex offsets; the
# Debian packages put it in a versioned directory that is not on PATH.
if [ -z "${ASAN_SYMBOLIZER_PATH:-}" ]; then
  SYMBOLIZER="$(command -v llvm-symbolizer 2>/dev/null || true)"
  if [ -z "$SYMBOLIZER" ]; then
    SYMBOLIZER="$(find /usr/lib /usr/local/opt -maxdepth 4 -name llvm-symbolizer -type f 2>/dev/null \
                  | sort | tail -1)"
  fi
  if [ -n "$SYMBOLIZER" ]; then
    export ASAN_SYMBOLIZER_PATH="$SYMBOLIZER"
  else
    note "llvm-symbolizer is not installed; a crash report will be hex offsets"
  fi
fi

# ---------------------------------------------------------------------------
# libFuzzer, when clang can build it
# ---------------------------------------------------------------------------
if command -v clang > /dev/null 2>&1 && [ "${FUZZ_ENGINE:-auto}" != "builtin" ]; then
  if clang -std=c11 "${CPPFLAGS_ALL[@]}" "${SAN[@]}" -DRESTATE_LIBFUZZER \
        -fsanitize=fuzzer -o "$WORK/fuzz-libfuzzer" "${SOURCES[@]}" \
        2> "$WORK/build-libfuzzer.log"; then
    ok "built the libFuzzer target"
    mkdir -p "$WORK/findings"
    if "$WORK/fuzz-libfuzzer" "$WORK/corpus" \
         -max_total_time="$FUZZ_SECONDS" -artifact_prefix="$WORK/findings/" \
         -max_len=16384 -timeout=10 -print_final_stats=1 -rss_limit_mb=2048 \
         > "$WORK/libfuzzer.log" 2>&1; then
      ok "libFuzzer found nothing in ${FUZZ_SECONDS}s"
      grep -E "^stat::number_of_executed_units|^stat::peak_rss" "$WORK/libfuzzer.log" \
        | sed 's/^/    /' || true
      grep -oE 'Done [0-9]+ runs' "$WORK/libfuzzer.log" | tail -1 | sed 's/^/    /' || true
      exit 0
    fi
    bad "libFuzzer found a crash"
    note "the failing input is under $WORK/findings/"
    # The ERROR line and the frames beneath it, not the shadow-byte legend at
    # the end of the report, which is the same boilerplate every time.
    awk '/ERROR: (Address|Leak|Memory)Sanitizer|runtime error:|deadly signal/ { p = 1 }
         /Shadow bytes around/ || /^SUMMARY:/ { p = 0 }
         p' "$WORK/libfuzzer.log" | head -40 | sed 's/^/      /'
    grep -m1 'SUMMARY:' "$WORK/libfuzzer.log" | sed 's/^/      /' || true
    note "reproduce it with: $WORK/fuzz-libfuzzer <the file above>"
    exit 1
  fi
  note "clang is installed but the libFuzzer build failed; using the built-in loop"
  if grep -q 'libclang_rt' "$WORK/build-libfuzzer.log" 2>/dev/null; then
    note "clang's runtime is missing: sudo apt install libclang-rt-dev (or: make install-dev)"
  fi
  note "see $WORK/build-libfuzzer.log"
fi

# ---------------------------------------------------------------------------
# The built-in mutation loop
# ---------------------------------------------------------------------------
if ! "$CC" -std=c11 "${CPPFLAGS_ALL[@]}" "${SAN[@]}" -Wall -Wextra \
      -o "$WORK/fuzz-builtin" "${SOURCES[@]}" 2> "$WORK/build-builtin.log"; then
  bad "could not build the fuzz target"
  note "see $WORK/build-builtin.log"
  exit 1
fi
ok "built the built-in mutation target"

export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:symbolize=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

rm -f "$WORK/crash.bin"
if "$WORK/fuzz-builtin" --seconds="$FUZZ_SECONDS" --seed="$FUZZ_SEED" \
     --crash-file="$WORK/crash.bin" "$WORK"/corpus/*; then
  ok "no crashes"
  exit 0
fi

bad "the fuzzer found a crash"
if [ -f "$WORK/crash.bin" ]; then
  note "the failing input is $WORK/crash.bin"
  note "reproduce it with: $WORK/fuzz-builtin --replay=$WORK/crash.bin"
fi
exit 1
