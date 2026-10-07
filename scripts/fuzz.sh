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
{"path": "/etc/hosts", "name": "hosts", "type": "file", "class": "state", "mode": "0644", "uid": 0, "gid": 0, "size": 0, "mtime": "2024-02-29T23:59:59.999999999Z", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "stored": "restate/files/etc/hosts"},
{"path": "x", "path_base64": "L2V0Yy9h/w==", "type": "symlink", "class": "baseline", "mode": "0777", "uid": 1, "gid": 1, "size": 1, "mtime": "1970-01-01T00:00:00.000000000Z", "target": "\\u00e9\\ud83d\\ude00\\n"},
{"path": "/dev/x", "type": "char", "class": "state", "mode": "0600", "uid": 0, "gid": 0, "size": 0, "rdev": 259, "mtime": "2026-10-03T00:00:00.000000000Z", "unreadable": false}
]}'

if [ -z "$(ls -A "$WORK/corpus" 2>/dev/null)" ]; then
  printf '\000%s' "$INDEX" > "$WORK/corpus/index-full"
  seed index-min 0 '{"format": "restate-index", "version": 1, "entries": []}'
  seed rules-builtin 1 '# comment\nephemeral /proc\nstate /etc\nexpendable /var/cache   # why\nbaseline /usr/**/lib\nephemeral *.pid\nstate /a\\*b\n'
  seed rules-bad 1 'keep /x\nstate\n'
  seed glob-anydirs 2 '/var/**/x\0/var/a/b/x'
  seed glob-unanchored 2 '*.pid\0/run/sshd.pid'
  seed glob-stars 2 '/*a*a*a*b\0/aaaaaaaaaaaaaaaaaaaa'
  seed time-iso 4 '2026-10-03T14:05:09.123456789Z'
  seed time-epoch 4 '@-62167219201.000000000'
  seed base64 5 'L2V0Yy9h/w=='
  seed lvm 6 'contents = "Text Format Volume Group"\nversion = 1\nvg0 {\n\tid = "x"\n\textent_size = 8192\n\tstatus = ["READ", "WRITE"]\n\tlogical_volumes {\n\t\troot {\n\t\t\tstripes = [\n\t\t\t\t"pv0", 0\n\t\t\t]\n\t\t}\n\t}\n}\n'
  seed accounts 10 'root:x:0:0:root:/root:/bin/bash\npostgres:x:128:135::/var/lib/postgresql:/bin/bash\npat:x:1000:1000:Pat:/home/pat:/bin/sh\n\0root:x:0:\nsudo:x:27:pat\npostgres:x:135:\n\0pat:!:1:0:99999:7:::\n\0\0root:x:0:0:root:/root:/bin/zsh\npostgres:x:125:131::/var/lib/postgresql:/bin/bash\npat:x:1000:1000:Pat Smith:/home/pat:/bin/zsh\nsam:x:1001:1001::/home/sam:/bin/bash\nold:x:127:128::/x:/y\n\0root:x:0:\nsudo:x:27:pat,sam\npostgres:x:131:\ndocker:x:999:pat\n\0pat:oldhash:1:0:99999:7:::\n\0sudo:*::pat,sam\n'
  seed packages 9 'Package: vim\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2:9.1-1\nDescription: x\n more\n .\n\nPackage: z\nStatus: hold ok half-configured\nArchitecture: all\nVersion: 1\n\0Package: vim\nArchitecture: amd64\nAuto-Installed: 1\n\0deb [arch=amd64 signed-by=/etc/apt/k.gpg] http://deb.example.com s main # c\n\0Types: deb\nURIs: https://x.example.com/a/\nSuites: ./\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n\nEnabled: no\nURIs: x\nSuites: y\n\0Package: vim\nArchitecture: amd64\nVersion: 2:9.1-1\n\0{"data": {"snaps": {"f": {"type": "app", "current": "x1", "channel": "latest/stable", "sequence": [{"side-info": {"revision": "x1"}}]}}}}\0root:x:0:0::/root:/bin/sh\nu:x:1000:1000::/home/u:/bin/sh\n\0manual\n/usr/bin/editor\n\0{"installs": {"rg 14.1.0 (registry+https://x)": {}}}'
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
  ok "built a seed corpus of $(find "$WORK/corpus" -type f | wc -l | tr -d ' ') inputs"
else
  ok "reusing the corpus in $WORK/corpus"
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
