/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "json.h"
#include "test.h"

/* An ELF header's first 20 bytes: class, byte order and e_machine. */
static void elf(unsigned char *h, unsigned cls, unsigned data, unsigned machine)
{
    memset(h, 0, 20);
    h[0] = 0x7f;
    h[1] = 'E';
    h[2] = 'L';
    h[3] = 'F';
    h[4] = (unsigned char)cls;
    h[5] = (unsigned char)data;
    if (data == 2)
    {
        h[18] = (unsigned char)(machine >> 8);
        h[19] = (unsigned char)machine;
    } else
    {
        h[18] = (unsigned char)machine;
        h[19] = (unsigned char)(machine >> 8);
    }
}

static const char *named(const struct rs_arch *a)
{
    return a ? a->name : "";
}

void test_arch(void)
{
    unsigned char h[20];

    TEST_CASE("arch: every system's name for one processor is the one");
    CHECK_STR(named(rs_arch_find("x86_64")), "x86_64");
    CHECK_STR(named(rs_arch_find("amd64")), "x86_64");
    CHECK_STR(named(rs_arch_find("arm64")), "aarch64");
    CHECK_STR(named(rs_arch_find("aarch64")), "aarch64");
    CHECK_STR(named(rs_arch_find("ppc64el")), "ppc64le");
    CHECK_STR(named(rs_arch_find("powerpc64le")), "ppc64le");
    CHECK_STR(named(rs_arch_find("powerpc64")), "ppc64");
    CHECK_STR(named(rs_arch_find("s390x")), "s390x");
    CHECK_STR(named(rs_arch_find("riscv64")), "riscv64");
    CHECK_STR(named(rs_arch_find("i386")), "i686");
    CHECK_STR(named(rs_arch_find("i586")), "i686");
    CHECK_STR(named(rs_arch_find("armhf")), "armv7l");
    CHECK_STR(named(rs_arch_find("earmv7hf")), "armv7l");
    CHECK_STR(named(rs_arch_find("armv7")), "armv7l");
    CHECK(rs_arch_find("evbarm") == NULL);
    CHECK(rs_arch_find("") == NULL);
    CHECK(rs_arch_find(NULL) == NULL);

    TEST_CASE("arch: and each system's name for it");
    {
        const struct rs_arch *a = rs_arch_find("ppc64le");

        CHECK_STR(a ? a->debian : "", "ppc64el");
        CHECK_STR(a ? a->rpm : "", "ppc64le");
        CHECK_STR(a ? a->freebsd : "", "powerpc64le");
        CHECK(a && a->openbsd == NULL && a->netbsd == NULL);
        a = rs_arch_find("aarch64");
        CHECK_STR(a ? a->debian : "", "arm64");
        CHECK_STR(a ? a->openbsd : "", "arm64");
        CHECK_STR(a ? a->netbsd : "", "aarch64");
        CHECK(a && a->wide && !a->big);
        a = rs_arch_find("s390x");
        CHECK(a && a->big && a->wide && a->freebsd == NULL);
    }

    TEST_CASE("arch: the same processor, whatever it is called");
    CHECK(rs_arch_same("amd64", "x86_64"));
    CHECK(rs_arch_same("arm64", "aarch64"));
    CHECK(!rs_arch_same("arm64", "x86_64"));
    CHECK(!rs_arch_same("arm64", "mystery"));
    CHECK(rs_arch_same("mystery", "mystery"));
    CHECK(!rs_arch_same("mystery", "other"));
    CHECK(!rs_arch_same(NULL, NULL));

    TEST_CASE("arch: an ELF header says which processor");
    elf(h, 2, 1, 62);
    CHECK_STR(named(rs_arch_of_elf(h, sizeof(h))), "x86_64");
    elf(h, 2, 1, 183);
    CHECK_STR(named(rs_arch_of_elf(h, sizeof(h))), "aarch64");
    elf(h, 2, 2, 22);
    CHECK_STR(named(rs_arch_of_elf(h, sizeof(h))), "s390x");
    elf(h, 2, 1, 21);
    CHECK_STR(named(rs_arch_of_elf(h, sizeof(h))), "ppc64le");
    elf(h, 2, 2, 21);
    CHECK_STR(named(rs_arch_of_elf(h, sizeof(h))), "ppc64");
    elf(h, 2, 1, 243);
    CHECK_STR(named(rs_arch_of_elf(h, sizeof(h))), "riscv64");
    elf(h, 1, 1, 3);
    CHECK_STR(named(rs_arch_of_elf(h, sizeof(h))), "i686");
    elf(h, 1, 1, 40);
    CHECK_STR(named(rs_arch_of_elf(h, sizeof(h))), "armv7l");
    /* 32-bit s390, MIPS: not one of restate's. */
    elf(h, 1, 2, 22);
    CHECK(rs_arch_of_elf(h, sizeof(h)) == NULL);
    elf(h, 2, 1, 8);
    CHECK(rs_arch_of_elf(h, sizeof(h)) == NULL);
    /* Short, not ELF, a bad class or byte order. */
    elf(h, 2, 1, 62);
    CHECK(rs_arch_of_elf(h, 19) == NULL);
    h[4] = 3;
    CHECK(rs_arch_of_elf(h, sizeof(h)) == NULL);
    elf(h, 2, 3, 62);
    CHECK(rs_arch_of_elf(h, sizeof(h)) == NULL);
    elf(h, 2, 1, 62);
    h[1] = 'X';
    CHECK(rs_arch_of_elf(h, sizeof(h)) == NULL);
    CHECK(rs_arch_of_elf((const unsigned char *)"#!/bin/sh\nexit 0\n\n\n\n", 20) == NULL);

    TEST_CASE("arch: what this restate is built for, and this machine");
    CHECK(rs_arch_built() != NULL);
    CHECK(rs_arch_here("amd64") == rs_arch_find("x86_64"));
    CHECK(rs_arch_here("evbarm") == rs_arch_built());
    CHECK(rs_arch_here(NULL) == rs_arch_built());

    TEST_CASE("arch: a machine description's, by arch or by the kernel's word");
    {
        struct rs_jval  m;
        struct rs_jval *sys;

        memset(&m, 0, sizeof(m));
        rs_jval_set_object(&m);
        CHECK(rs_arch_of_machine(&m) == NULL);
        sys = rs_jobj_add(&m, "system");
        rs_jval_set_object(sys);
        rs_jobj_str(sys, "architecture", "amd64");
        CHECK_STR(named(rs_arch_of_machine(&m)), "x86_64");
        rs_jobj_str(sys, "arch", "aarch64");
        CHECK_STR(named(rs_arch_of_machine(&m)), "aarch64");
        rs_jval_free(&m);
    }
}
