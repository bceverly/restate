/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>

#include "bsd.h"
#include "buildsheet.h"
#include "json.h"
#include "layout.h"
#include "test.h"

/* What FreeBSD 14 prints for a UEFI install with a GELI-encrypted swap, an
 * MBR USB stick, and an optical drive. */
static const char conftxt[] =
    "0 DISK ada0 500107862016 512 hd 16 sc 63\n"
    "1 PART ada0p3 495812886528 512 i 3 o 4295004160 ty freebsd-zfs xs GPT xt "
    "516e7cba-6ecf-11d6-8ff8-00022d09712b\n"
    "1 PART ada0p2 4294967296 512 i 2 o 36864 ty freebsd-swap xs GPT xt "
    "516e7cb5-6ecf-11d6-8ff8-00022d09712b\n"
    "1 PART ada0p1 272629760 512 i 1 o 20480 ty efi xs GPT xt c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n"
    "2 LABEL gpt/efiboot0 272629760 512 i 0 o 0\n"
    "2 ELI ada0p2.eli 4294967296 4096\n"
    "0 DISK da0 16008609792 512 hd 255 sc 63\n"
    "1 PART da0s1 16007561216 512 i 1 o 1048576 ty fat32lba xs MBR xt 12\n"
    "1 PART nosuch1 1 512 i 1 o 0 ty efi xs GPT xt x\n"
    "0 DISK cd0 0 2048\n"
    "short line\n"
    "\n";

void test_bsd(void)
{
    struct rs_jval        m;
    const struct rs_jval *disks;
    const struct rs_jval *parts;
    const struct rs_jval *p;
    const struct rs_jval *mapped;

    TEST_CASE("bsd: FreeBSD's GEOM configuration");
    memset(&m, 0, sizeof(m));
    rs_jval_set_object(&m);
    rs_geom_parse(conftxt, &m);
    disks = rs_jobject_get(&m, "disks");
    CHECK(disks && disks->n == 2);
    CHECK_STR(rs_jobject_str(&disks->items[0], "name"), "ada0");
    CHECK_STR(rs_jobject_str(rs_jobject_get(&disks->items[0], "table"), "type"), "gpt");
    parts = rs_jobject_get(&disks->items[0], "partitions");
    CHECK(parts && parts->n == 3);
    p = &parts->items[2];
    CHECK_STR(rs_jobject_str(p, "name"), "ada0p1");
    CHECK_STR(rs_jobject_str(p, "type"), "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    CHECK_STR(rs_jobject_str(p, "type_name"), "efi");
    CHECK_STR(rs_jobject_str(rs_jobject_get(p, "content"), "type"), "vfat");
    CHECK_STR(rs_jobject_str(rs_jobject_get(&parts->items[0], "content"), "type"), "zfs_member");
    CHECK_STR(rs_jobject_str(rs_jobject_get(&parts->items[1], "content"), "type"), "swap");
    CHECK_STR(rs_jobject_str(rs_jobject_get(&disks->items[1], "table"), "type"), "dos");
    p = &rs_jobject_get(&disks->items[1], "partitions")->items[0];
    CHECK_STR(rs_jobject_str(p, "type"), "0x0c");
    CHECK(rs_jobject_get(p, "content") == NULL);
    mapped = rs_jobject_get(&m, "mapped");
    CHECK(mapped && mapped->n == 1);
    CHECK_STR(rs_jobject_str(&mapped->items[0], "kind"), "geli");
    CHECK_STR(rs_jobject_get(&mapped->items[0], "devices")->items[0].s, "ada0p2");
    rs_geom_parse(NULL, &m);

    TEST_CASE("bsd: a disklabel, wedges and mounts");
    {
        static const struct rs_bsd_part label[] = {
            { "sd0a", 1, 64 * 512, 1073741824, "4.2BSD", NULL },
            { "sd0b", 2, 1073741824 + 64 * 512, 536870912, "swap", NULL },
            { "sd0i", 9, 0, 1048576, "MSDOS", NULL },
        };
        static const struct rs_bsd_part wedges[] = {
            { "dk0", 1, 1048576, 134217728, "msdos", "EFI system" },
            { "dk1", 2, 135266304, 8589934592, "ffs", "netbsd-root" },
        };

        rs_bsd_add_disk(&m, "sd0", 21474836480, 512, "disklabel", label, 3);
        rs_bsd_add_disk(&m, "wd0", 0, 0, "gpt", wedges, 2);
        rs_bsd_add_disk(&m, "sd9", 1, 512, NULL, NULL, 0);
        disks = rs_jobject_get(&m, "disks");
        CHECK(disks && disks->n == 5);
        parts = rs_jobject_get(&disks->items[2], "partitions");
        CHECK_STR(rs_jobject_str(rs_jobject_get(&parts->items[0], "content"), "type"), "ffs");
        CHECK_STR(rs_jobject_str(rs_jobject_get(&parts->items[1], "content"), "type"), "swap");
        CHECK_STR(rs_jobject_str(rs_jobject_get(&parts->items[2], "content"), "type"), "vfat");
        parts = rs_jobject_get(&disks->items[3], "partitions");
        CHECK_STR(rs_jobject_str(&parts->items[1], "label"), "netbsd-root");
        CHECK(rs_jobject_get(&disks->items[4], "table") == NULL);

        rs_bsd_add_mount(&m, "/", "/dev/sd0a", "ffs", 1000, 400);
        rs_bsd_add_mount(&m, "/mnt/nas", "nas:/export", "nfs", 1000, 400);
        rs_bsd_add_mount(&m, "/dev", "devfs", "devfs", 0, 0);
        rs_bsd_add_mount(&m, NULL, "x", "ufs", 0, 0);
        rs_bsd_add_mount(&m, "/x", "x", NULL, 0, 0);
        CHECK(rs_jobject_get(&m, "mounts")->n == 2);
        CHECK(rs_jobject_get(&rs_jobject_get(&m, "mounts")->items[0], "used")->u == 400);
        CHECK(rs_jobject_get(&rs_jobject_get(&m, "mounts")->items[1], "size") == NULL);
    }

    TEST_CASE("bsd: a BSD layout is a layout, and a build sheet says what it is for");
    {
        struct rs_layout     l;
        struct rs_sheet_opts o = { RS_TARGET_SAME, NULL, NULL, NULL, false };
        struct rs_buf        out;
        struct rs_buf        err;
        struct rs_jval      *sys = rs_jobj_add(&m, "system");

        CHECK(rs_layout_build(&m, &l));
        CHECK(rs_layout_find(&l, "ada0p2.eli") != SIZE_MAX);
        rs_layout_free(&l);
        rs_jval_set_object(sys);
        rs_jobj_str(sys, "kernel_name", "FreeBSD");
        rs_buf_init(&out);
        rs_buf_init(&err);
        CHECK(!rs_buildsheet(&m, &o, &out, &err));
        CHECK_CONTAINS(err.data, "written for Linux in this version, and this is FreeBSD");
        rs_buf_free(&out);
        rs_buf_free(&err);
    }

    TEST_CASE("bsd: asking the kernel, where there is one to ask");
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
    {
        struct rs_jval live;

        memset(&live, 0, sizeof(live));
        rs_jval_set_object(&live);
        CHECK(rs_bsd_describe(&live));
        CHECK(rs_jobject_get(&live, "hardware") != NULL);
        CHECK(rs_jobject_get(&live, "mounts") != NULL);
        rs_jval_free(&live);
    }
#else
    CHECK(!rs_bsd_describe(&m));
#endif
    rs_jval_free(&m);
}
