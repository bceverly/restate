#!/usr/bin/env sh
#
# Copyright (c) 2026 Bryan C. Everly
# SPDX-License-Identifier: BSD-2-Clause
#
# The feature-test macros this program is compiled with, for this platform.
#
#   scripts/features.sh
#
# One place, because the Makefile and every analysis script (lint, coverage,
# memcheck, security, fuzz) compile this program, and the answer is not the
# same everywhere. Seven callers with seven copies of it is how six of them end
# up asserting the Linux answer on a Mac.
#
#   Linux         _GNU_SOURCE: POSIX.1-2008 (openat, fstatat, fdopendir and
#                 readlinkat, which the walker is built on) plus the two Linux
#                 additions the index needs -- statx(2), the only way to read a
#                 file's birth time there, and O_NOATIME, so that hashing a file
#                 does not change the access time the index is recording.
#
#   macOS         the same request also switches off __DARWIN_C_LEVEL, and
#                 getopt_long and optreset live outside POSIX.
#                 _DARWIN_C_SOURCE puts them back.
#
#   the BSDs      __BSD_VISIBLE is on by default and _XOPEN_SOURCE turns it
#                 off, hiding getopt_long and optreset there for the same
#                 reason. They are better served by asking for nothing.
#
# _FILE_OFFSET_BITS=64 is a glibc question: without it a 32-bit Linux build
# cannot stat a file over 2 GiB, and a backup tool that cannot see a large
# file is worse than useless. The BSDs have had a 64-bit off_t all along.
#
# sh rather than bash: the Makefile runs this for every target.
case "$(uname -s)" in
Darwin)
    echo "-D_XOPEN_SOURCE=700 -D_FILE_OFFSET_BITS=64 -D_DARWIN_C_SOURCE"
    ;;
FreeBSD | NetBSD | OpenBSD | DragonFly)
    echo "-D_FILE_OFFSET_BITS=64"
    ;;
*)
    echo "-D_GNU_SOURCE -D_FILE_OFFSET_BITS=64"
    ;;
esac
