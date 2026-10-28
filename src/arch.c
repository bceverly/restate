/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "arch.h"

#include <string.h>

/* NULL where that system has no port for it. */
static const struct rs_arch arches[] = {
    { "x86_64", "amd64", "x86_64", "amd64", "amd64", "x86_64", "64-bit x86", 62, true, false },
    { "aarch64", "arm64", "aarch64", "aarch64", "arm64", "aarch64", "64-bit ARM", 183, true,
      false },
    { "ppc64le", "ppc64el", "ppc64le", "powerpc64le", NULL, NULL, "64-bit POWER, little-endian",
      21, true, false },
    { "riscv64", "riscv64", "riscv64", "riscv64", "riscv64", "riscv64", "64-bit RISC-V", 243,
      true, false },
    { "s390x", "s390x", "s390x", NULL, NULL, NULL, "IBM Z (s390x)", 22, true, true },
    { "ppc64", "ppc64", "ppc64", "powerpc64", "powerpc64", NULL, "64-bit POWER, big-endian", 21,
      true, true },
    { "i686", "i386", "i686", "i386", "i386", "i386", "32-bit x86", 3, false, false },
    { "armv7l", "armhf", "armv7hl", "armv7", "armv7", "earmv7hf", "32-bit ARM", 40, false,
      false },
};

/* Other words for them: the kernel's for older x86, and what macOS and
 * FreeBSD's uname -m say. */
static const char *const aliases[][2] = {
    { "i386", "i686" },   { "i486", "i686" },     { "i586", "i686" },  { "arm64", "aarch64" },
    { "armv7", "armv7l" }, { "powerpc64le", "ppc64le" }, { "powerpc64", "ppc64" },
};

static bool eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

const struct rs_arch *rs_arch_find(const char *name)
{
    size_t i;

    if (!name)
    {
        return NULL;
    }
    for (i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++)
    {
        if (eq(name, aliases[i][0]))
        {
            name = aliases[i][1];
            break;
        }
    }
    for (i = 0; i < sizeof(arches) / sizeof(arches[0]); i++)
    {
        const struct rs_arch *a = &arches[i];

        if (eq(name, a->name) || eq(name, a->debian) || eq(name, a->rpm) ||
            eq(name, a->freebsd) || eq(name, a->openbsd) || eq(name, a->netbsd))
        {
            return a;
        }
    }
    return NULL;
}

const struct rs_arch *rs_arch_of_elf(const unsigned char *head, size_t n)
{
    unsigned machine;
    bool     wide;
    bool     big;
    size_t   i;

    /* The magic, the class (1, 32-bit; 2, 64-bit), the byte order (1, little;
     * 2, big); e_machine at 18, in that order. */
    if (n < 20 || head[0] != 0x7f || head[1] != 'E' || head[2] != 'L' || head[3] != 'F' ||
        (head[4] != 1 && head[4] != 2) || (head[5] != 1 && head[5] != 2))
    {
        return NULL;
    }
    wide = head[4] == 2;
    big = head[5] == 2;
    machine = big ? (unsigned)head[18] << 8 | head[19] : (unsigned)head[19] << 8 | head[18];
    for (i = 0; i < sizeof(arches) / sizeof(arches[0]); i++)
    {
        if (arches[i].elf == machine && arches[i].wide == wide && arches[i].big == big)
        {
            return &arches[i];
        }
    }
    return NULL;
}

const struct rs_arch *rs_arch_built(void)
{
#if defined(__x86_64__)
    return rs_arch_find("x86_64");
#elif defined(__aarch64__)
    return rs_arch_find("aarch64");
#elif defined(__powerpc64__) && defined(__LITTLE_ENDIAN__)
    return rs_arch_find("ppc64le");
#elif defined(__powerpc64__)
    return rs_arch_find("ppc64");
#elif defined(__riscv) && defined(__riscv_xlen) && __riscv_xlen == 64
    return rs_arch_find("riscv64");
#elif defined(__s390x__)
    return rs_arch_find("s390x");
#elif defined(__i386__)
    return rs_arch_find("i686");
#elif defined(__arm__)
    return rs_arch_find("armv7l");
#else
    return NULL;
#endif
}

const struct rs_arch *rs_arch_of_machine(const struct rs_jval *machine)
{
    const struct rs_jval *sys = rs_jobject_get(machine, "system");
    const struct rs_arch *a = rs_arch_find(rs_jobject_str(sys, "arch"));

    return a ? a : rs_arch_find(rs_jobject_str(sys, "architecture"));
}

const struct rs_arch *rs_arch_here(const char *uname_machine)
{
    const struct rs_arch *a = rs_arch_find(uname_machine);

    return a ? a : rs_arch_built();
}

bool rs_arch_same(const char *a, const char *b)
{
    const struct rs_arch *x = rs_arch_find(a);
    const struct rs_arch *y = rs_arch_find(b);

    if (x || y)
    {
        return x == y;
    }
    return eq(a, b);
}
