/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Processor architectures, and the names each system gives them.
 *
 * One architecture goes by several names: the kernel's (`uname -m` on Linux,
 * "x86_64"), Debian's ("amd64"), RPM's, and each BSD's. restate keeps the
 * kernel's as its own and maps the others to it, so a capture taken on one
 * system is compared with, and rebuilt for, a machine that names it another
 * way -- and an ELF program's header says which one it was built for.
 */
#ifndef RESTATE_ARCH_H
#define RESTATE_ARCH_H

#include <stdbool.h>
#include <stddef.h>

#include "json.h"

struct rs_arch {
    const char *name;      /* the kernel's: "x86_64", "aarch64", "s390x" */
    const char *debian;    /* dpkg's, and the binary-ARCH in a repository */
    const char *rpm;       /* rpm's */
    const char *freebsd;   /* FreeBSD's MACHINE_ARCH, as pkg's ABI names it */
    const char *openbsd;   /* OpenBSD's MACHINE, as its package paths name it */
    const char *netbsd;    /* NetBSD's MACHINE_ARCH, as pkgsrc names it */
    const char *what;      /* "64-bit x86", for people */
    unsigned    elf;       /* the ELF header's e_machine */
    bool        wide;      /* 64-bit */
    bool        big;       /* big-endian */
};

/* The architecture any system names `name`, or NULL if none does. */
const struct rs_arch *rs_arch_find(const char *name);

/* The architecture an ELF file's first `n` bytes say it is built for; NULL
 * if they are not an ELF header, or for one restate does not know. */
const struct rs_arch *rs_arch_of_elf(const unsigned char *head, size_t n);

/* The architecture this restate was built for. */
const struct rs_arch *rs_arch_built(void);

/* A machine description's architecture: its "arch", else its "architecture"
 * (the kernel's word, which on a BSD can be a board's: NetBSD's "evbarm"). */
const struct rs_arch *rs_arch_of_machine(const struct rs_jval *machine);

/* This machine's: the kernel's name for it where that is one of the table's,
 * else what restate was built for. */
const struct rs_arch *rs_arch_here(const char *uname_machine);

/* Whether two names, in any system's spelling, are one architecture. Names
 * no system has are the same only if they are the same name. */
bool rs_arch_same(const char *a, const char *b);

#endif
