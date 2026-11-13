/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <string.h>

#include "autoinstall.h"
#include "bsdsheet.h"
#include "buildsheet.h"
#include "json.h"
#include "test.h"

/* bsdinstall's UEFI layout on ZFS, encrypted: an ESP, the BIOS boot code, a
 * GELI swap and a GELI pool -- and a USB stick, nothing of the system's. */
static const char freebsd_zfs[] =
    "{\"system\": {\"kernel_name\": \"FreeBSD\", \"id\": \"freebsd\", \"version_id\": \"14.2\","
    " \"pretty_name\": \"FreeBSD 14.2-RELEASE\", \"architecture\": \"amd64\","
    " \"hostname\": \"fbsd1\"},"
    " \"hardware\": {\"sys_vendor\": \"QEMU\", \"product_name\": \"Standard PC\","
    " \"cpu\": \"AMD EPYC\", \"cpus\": 4, \"memory\": 8589934592},"
    " \"firmware\": {\"mode\": \"uefi\"},"
    " \"disks\": [{\"name\": \"ada0\", \"size\": 107374182400, \"logical_block_size\": 512,"
    " \"table\": {\"type\": \"gpt\"}, \"partitions\": ["
    "{\"name\": \"ada0p1\", \"number\": 1, \"start\": 20480, \"size\": 272629760,"
    " \"type\": \"c12a7328-f81f-11d2-ba4b-00a0c93ec93b\", \"type_name\": \"efi\","
    " \"label\": \"efiboot0\", \"content\": {\"type\": \"vfat\"}},"
    "{\"name\": \"ada0p2\", \"number\": 2, \"start\": 272650240, \"size\": 524288,"
    " \"type_name\": \"freebsd-boot\", \"label\": \"gptboot0\"},"
    "{\"name\": \"ada0p3\", \"number\": 3, \"start\": 273678336, \"size\": 4294967296,"
    " \"type_name\": \"freebsd-swap\", \"label\": \"swap0\", \"content\": {\"type\": \"swap\"}},"
    "{\"name\": \"ada0p4\", \"number\": 4, \"start\": 4568645632, \"size\": 102805536768,"
    " \"type_name\": \"freebsd-zfs\", \"label\": \"zfs0\","
    " \"content\": {\"type\": \"zfs_member\"}}]},"
    " {\"name\": \"da0\", \"size\": 16008609792, \"table\": {\"type\": \"dos\"},"
    " \"partitions\": [{\"name\": \"da0s1\", \"number\": 1, \"start\": 1048576,"
    " \"size\": 16007561216, \"type\": \"0x0c\", \"type_name\": \"fat32lba\"}]},"
    " {\"name\": \"cd0\", \"size\": 0}],"
    " \"mapped\": [{\"name\": \"ada0p3.eli\", \"kind\": \"geli\", \"devices\": [\"ada0p3\"]},"
    " {\"name\": \"ada0p4.eli\", \"kind\": \"geli\", \"devices\": [\"ada0p4\"]},"
    " {\"name\": \"x\", \"kind\": \"geli\", \"devices\": []}],"
    " \"fstab\": [{\"spec\": \"/dev/gpt/efiboot0\", \"file\": \"/boot/efi\","
    " \"type\": \"msdosfs\", \"options\": \"rw\", \"freq\": \"2\", \"passno\": \"2\"},"
    " {\"spec\": \"/dev/ada0p3.eli\", \"file\": \"none\", \"type\": \"swap\","
    " \"options\": \"sw\", \"freq\": \"0\", \"passno\": \"0\"},"
    " {\"spec\": \"nas:/export\", \"file\": \"/nas\", \"type\": \"nfs\"}],"
    " \"mounts\": [{\"mountpoint\": \"/\", \"type\": \"zfs\", \"source\": \"zroot/ROOT/default\","
    " \"size\": 100000000000, \"used\": 3000000000},"
    " {\"mountpoint\": \"/home\", \"type\": \"zfs\", \"source\": \"zroot/home\","
    " \"used\": 1000000000},"
    " {\"mountpoint\": \"/zroot\", \"type\": \"zfs\", \"source\": \"zroot\", \"used\": 100000},"
    " {\"mountpoint\": \"/usr/ports\", \"type\": \"zfs\", \"source\": \"zroot/usr/ports\","
    " \"used\": 100},"
    " {\"mountpoint\": \"/boot/efi\", \"type\": \"msdosfs\", \"source\": \"/dev/gpt/efiboot0\","
    " \"size\": 270000000, \"used\": 1000000}]}";

/* A BIOS machine on UFS, its root labeled. */
static const char freebsd_ufs[] =
    "{\"system\": {\"kernel_name\": \"FreeBSD\", \"version_id\": \"14.2\","
    " \"architecture\": \"arm64\"},"
    " \"firmware\": {\"mode\": \"bios\"},"
    " \"disks\": [{\"name\": \"nda0\", \"size\": 53687091200, \"table\": {\"type\": \"gpt\"},"
    " \"partitions\": ["
    "{\"name\": \"nda0p1\", \"number\": 1, \"start\": 20480, \"size\": 524288,"
    " \"type_name\": \"freebsd-boot\"},"
    "{\"name\": \"nda0p2\", \"number\": 2, \"start\": 544768, \"size\": 49392123904,"
    " \"type_name\": \"freebsd-ufs\", \"content\": {\"type\": \"ufs\", \"label\": \"rootfs\"}},"
    "{\"name\": \"nda0p3\", \"number\": 3, \"start\": 49392668672, \"size\": 4294967296,"
    " \"type_name\": \"freebsd-swap\", \"content\": {\"type\": \"swap\"}},"
    "{\"name\": \"nda0p4\", \"number\": 4, \"start\": 53687635968, \"size\": 1048576,"
    " \"type\": \"516e7cb4-6ecf-11d6-8ff8-00022d09712b\", \"content\": {\"type\": \"ufs\"}}]}],"
    " \"fstab\": [{\"spec\": \"/dev/ufs/rootfs\", \"file\": \"/\", \"type\": \"ufs\","
    " \"options\": \"rw\", \"freq\": \"1\", \"passno\": \"1\"},"
    " {\"spec\": \"/dev/nda0p3\", \"file\": \"none\", \"type\": \"swap\", \"options\": \"sw\"},"
    " {\"spec\": \"/dev/nda0p4\", \"file\": \"/data\", \"type\": \"ufs\"}],"
    " \"mounts\": [{\"mountpoint\": \"/\", \"type\": \"ufs\", \"source\": \"/dev/ufs/rootfs\","
    " \"size\": 48000000000, \"used\": 6000000000}]}";

/* The OpenBSD installer's own layout, on UEFI, named by its DUID. */
static const char openbsd[] =
    "{\"system\": {\"kernel_name\": \"OpenBSD\", \"id\": \"openbsd\", \"version_id\": \"7.6\","
    " \"architecture\": \"amd64\", \"hostname\": \"puffy\"},"
    " \"disks\": [{\"name\": \"sd0\", \"size\": 21474836480, \"logical_block_size\": 512,"
    " \"table\": {\"type\": \"disklabel\"}, \"duid\": \"3eb7f9d8cd4f05ee\", \"partitions\": ["
    "{\"name\": \"sd0a\", \"number\": 1, \"start\": 33554432, \"size\": 1073741824,"
    " \"type\": \"4.2BSD\", \"content\": {\"type\": \"ffs\"}},"
    "{\"name\": \"sd0b\", \"number\": 2, \"start\": 1107296256, \"size\": 536870912,"
    " \"type\": \"swap\", \"content\": {\"type\": \"swap\"}},"
    "{\"name\": \"sd0d\", \"number\": 4, \"start\": 1644167168, \"size\": 2147483648,"
    " \"type\": \"4.2BSD\", \"content\": {\"type\": \"ffs\"}},"
    "{\"name\": \"sd0e\", \"number\": 5, \"start\": 3791650816, \"size\": 4294967296,"
    " \"type\": \"4.2BSD\", \"content\": {\"type\": \"ffs\"}},"
    "{\"name\": \"sd0i\", \"number\": 9, \"start\": 32768, \"size\": 272662528,"
    " \"type\": \"MSDOS\", \"content\": {\"type\": \"vfat\"}}]},"
    " {\"name\": \"sd1\", \"size\": 1, \"table\": {\"type\": \"disklabel\"}, \"partitions\": ["
    "{\"name\": \"sd1a\", \"number\": 1, \"start\": 0, \"size\": 1, \"type\": \"4.2BSD\"}]},"
    " {\"name\": \"sd2\", \"size\": 8589934592, \"table\": {\"type\": \"disklabel\"},"
    " \"partitions\": [{\"name\": \"sd2a\", \"number\": 1, \"start\": 0,"
    " \"size\": 8589934592, \"type\": \"4.2BSD\", \"content\": {\"type\": \"ffs\"}}]}],"
    " \"fstab\": [{\"spec\": \"3eb7f9d8cd4f05ee.a\", \"file\": \"/\", \"type\": \"ffs\"},"
    " {\"spec\": \"3eb7f9d8cd4f05ee.b\", \"file\": \"none\", \"type\": \"swap\"},"
    " {\"spec\": \"3eb7f9d8cd4f05ee.d\", \"file\": \"/tmp\", \"type\": \"ffs\"},"
    " {\"spec\": \"3eb7f9d8cd4f05ee.e\", \"file\": \"/var\", \"type\": \"ffs\"},"
    " {\"spec\": \"/dev/sd2a\", \"file\": \"/srv\", \"type\": \"ffs\"}]}";

/* NetBSD on GPT wedges, by their names; and a disk with a disklabel. */
static const char netbsd[] =
    "{\"system\": {\"kernel_name\": \"NetBSD\", \"version_id\": \"10.1\","
    " \"architecture\": \"amd64\", \"hostname\": \"nb1\"},"
    " \"firmware\": {\"mode\": \"uefi\"},"
    " \"disks\": [{\"name\": \"wd0\", \"size\": 0, \"logical_block_size\": 512,"
    " \"table\": {\"type\": \"gpt\"}, \"partitions\": ["
    "{\"name\": \"dk0\", \"number\": 1, \"start\": 1048576, \"size\": 268435456,"
    " \"type\": \"msdos\", \"label\": \"EFI system\", \"content\": {\"type\": \"vfat\"}},"
    "{\"name\": \"dk1\", \"number\": 2, \"start\": 269484032, \"size\": 8589934592,"
    " \"type\": \"ffs\", \"label\": \"netbsd-root\", \"content\": {\"type\": \"ffs\"}},"
    "{\"name\": \"dk2\", \"number\": 3, \"start\": 8859418624, \"size\": 1073741824,"
    " \"type\": \"swap\", \"label\": \"netbsd-swap\", \"content\": {\"type\": \"swap\"}},"
    "{\"name\": \"dk3\", \"number\": 4, \"start\": 9933160448, \"size\": 1073741824,"
    " \"type\": \"ext2fs\", \"content\": {\"type\": \"ext2\"}}]},"
    " {\"name\": \"wd1\", \"size\": 1073741824, \"table\": {\"type\": \"disklabel\"},"
    " \"partitions\": [{\"name\": \"wd1a\", \"number\": 1, \"start\": 0,"
    " \"size\": 1073741824, \"type\": \"4.2BSD\", \"content\": {\"type\": \"ffs\"}}]}],"
    " \"fstab\": [{\"spec\": \"NAME=netbsd-root\", \"file\": \"/\", \"type\": \"ffs\","
    " \"options\": \"rw,log\", \"freq\": \"1\", \"passno\": \"1\"},"
    " {\"spec\": \"NAME=netbsd-swap\", \"file\": \"none\", \"type\": \"swap\","
    " \"options\": \"sw,dp\"},"
    " {\"spec\": \"/dev/dk3\", \"file\": \"/linux\", \"type\": \"ext2fs\"},"
    " {\"spec\": \"/dev/wd1a\", \"file\": \"/old\", \"type\": \"ffs\"}]}";

static void parse(const char *text, struct rs_jval *out)
{
    struct rs_json_parser jp;
    struct rs_buf         err;

    rs_buf_init(&err);
    memset(out, 0, sizeof(*out));
    rs_json_init(&jp, text, strlen(text), &err);
    if (!rs_json_value(&jp, out))
    {
        rs_test_fail(__FILE__, __LINE__, "fixture does not parse: %s", err.data ? err.data : "");
    }
    rs_buf_free(&err);
}

static char *sheet(const char *fixture, enum rs_target target, const char *packages,
                   const char *export_from)
{
    struct rs_jval       m;
    struct rs_jval       pk;
    struct rs_sheet_opts o;
    struct rs_buf        out;
    struct rs_buf        err;

    parse(fixture, &m);
    memset(&pk, 0, sizeof(pk));
    if (packages)
    {
        parse(packages, &pk);
    }
    memset(&o, 0, sizeof(o));
    o.target = target;
    o.image = "web.tar";
    o.version = "9.9";
    o.packages = packages ? &pk : NULL;
    o.trust = "--allow-unverified";
    o.export_from = export_from;
    rs_buf_init(&out);
    rs_buf_init(&err);
    CHECK(rs_buildsheet(&m, &o, &out, &err));
    if (err.len)
    {
        rs_test_fail(__FILE__, __LINE__, "%s", err.data);
    }
    rs_buf_free(&err);
    rs_jval_free(&m);
    rs_jval_free(&pk);
    return rs_buf_detach(&out);
}

static void freebsd_cases(void)
{
    char *s;

    TEST_CASE("bsdsheet: FreeBSD on encrypted ZFS, booted by UEFI");
    s = sheet(freebsd_zfs, RS_TARGET_SAME, "{\"freebsd-pkg\": [{\"name\": \"nginx\"}]}", NULL);
    CHECK_CONTAINS(s, "restate build sheet: fbsd1");
    CHECK_CONTAINS(s, "System     FreeBSD 14.2-RELEASE");
    CHECK_CONTAINS(s, "Firmware   UEFI");
    CHECK_CONTAINS(s, "FreeBSD-14.2-RELEASE-amd64-memstick.img");
    CHECK_CONTAINS(s, "https://download.freebsd.org/releases/ISO-IMAGES/14.2/");
    CHECK_CONTAINS(s, "The image to restore: web.tar");
    CHECK_CONTAINS(s, "da0 14 GiB  MBR -- nothing of the system's: left alone");
    CHECK_CONTAINS(s, "zroot/ROOT/default");
    CHECK_CONTAINS(s, "    kldload -n zfs\n    kldload -n geom_eli\n");
    CHECK_CONTAINS(s, "    DISK1=ada0 ");
    CHECK_CONTAINS(s, "# da0: nothing of the system's on it -- left alone");
    CHECK_CONTAINS(s, "gpart create -s gpt \"$DISK1\"");
    CHECK_CONTAINS(s, "gpart add -t efi -b 40 -s 532480 -i 1 -l efiboot0 \"$DISK1\"");
    CHECK_CONTAINS(s, "gpart add -t freebsd-zfs -b 8923136 -s 200792064 -i 4 -l zfs0");
    CHECK_CONTAINS(s, "gpart bootcode -b /boot/pmbr -p /boot/gptzfsboot -i 2 \"$DISK1\"");
    CHECK_CONTAINS(s, "geli init -b -g -s 4096 -l 256 /dev/${DISK1}p4\n");
    CHECK_CONTAINS(s, "geli attach /dev/${DISK1}p4\n");
    CHECK(strstr(s, "geli init -b -g -s 4096 -l 256 /dev/${DISK1}p3") == NULL);
    CHECK_CONTAINS(s, "newfs_msdos -F 32 -c 1 /dev/${DISK1}p1\n");
    CHECK_CONTAINS(s, "zpool create -f -o altroot=/mnt -O compress=lz4 -O atime=off -m /zroot "
                      "zroot /dev/${DISK1}p4.eli\n");
    CHECK_CONTAINS(s, "    zfs create -o mountpoint=none zroot/ROOT\n"
                      "    zfs create -o canmount=noauto -o mountpoint=/ zroot/ROOT/default\n"
                      "    zfs mount zroot/ROOT/default\n"
                      "    zfs create -o mountpoint=/home zroot/home\n"
                      "    zfs create -o mountpoint=none zroot/usr\n"
                      "    zfs create -o mountpoint=/usr/ports zroot/usr/ports\n"
                      "    zpool set bootfs=zroot/ROOT/default zroot\n");
    CHECK_CONTAINS(s, "zpool set cachefile=/mnt/boot/zfs/zpool.cache zroot");
    CHECK_CONTAINS(s, "    mkdir -p /mnt/boot/efi\n    mount -t msdosfs /dev/${DISK1}p1 "
                      "/mnt/boot/efi\n");
    CHECK_CONTAINS(s, "for set in base kernel lib32; do");
    CHECK_CONTAINS(s, "cp /mnt/boot/loader.efi /mnt/boot/efi/EFI/BOOT/BOOTX64.efi");
    CHECK_CONTAINS(s, "efibootmgr -a -c -l /mnt/boot/efi/EFI/freebsd/loader.efi -L FreeBSD");
    CHECK_CONTAINS(s, "    /dev/${DISK1}p1          /boot/efi    msdosfs  rw       2 2\n");
    CHECK_CONTAINS(s, "    /dev/${DISK1}p3.eli      none         swap     sw       0 0\n");
    CHECK_CONTAINS(s, "sysrc -f /mnt/etc/rc.conf hostname=fbsd1 ifconfig_DEFAULT=SYNCDHCP "
                      "sshd_enable=YES zfs_enable=YES");
    CHECK_CONTAINS(s, "sysrc -f /mnt/boot/loader.conf zfs_load=YES geom_eli_load=YES");
    CHECK_CONTAINS(s, "pkg add ./restate-9.9-freebsd-*.pkg");
    CHECK_CONTAINS(s, "pkg install -y nginx");
    CHECK_CONTAINS(s, "restate restore");
    CHECK(strstr(s, "It keeps the new system's /etc/fstab") == NULL);
    CHECK(strstr(s, "update-initramfs") == NULL);
    CHECK_CONTAINS(s, "Then reboot:\n\n    reboot\n");
    CHECK(strstr(s, "VDEVS") == NULL);
    CHECK_CONTAINS(s, "a key file the old ones had");
    free(s);

    TEST_CASE("bsdsheet: FreeBSD as a virtual machine, sized to what it holds");
    s = sheet(freebsd_zfs, RS_TARGET_VM, NULL, "repo::web");
    CHECK_CONTAINS(s, "Rebuilt as a virtual machine");
    CHECK_CONTAINS(s, "Start the virtual machine");
    CHECK_CONTAINS(s, "    DISK1=vtbd0 ");
    CHECK_CONTAINS(s, "gpart add -t efi -a 1m -s 260M -i 1 -l efiboot0");
    CHECK_CONTAINS(s, "gpart add -t freebsd-zfs -a 1m -s 9216M -i 4 -l zfs0");
    CHECK_CONTAINS(s, "gpart add -t freebsd-swap -a 1m -s 4096M -i 3 -l swap0");
    CHECK_CONTAINS(s, "gpart add -t freebsd-boot -a 1m -s 512K -i 2 -l gptboot0");
    CHECK(strstr(s, "efibootmgr") == NULL);
    CHECK_CONTAINS(s, "restate export repo::web -o web.tar");
    CHECK_CONTAINS(s, "It keeps the new system's /etc/fstab");
    free(s);

    TEST_CASE("bsdsheet: FreeBSD on UFS, booted by BIOS, on other hardware");
    s = sheet(freebsd_ufs, RS_TARGET_METAL, NULL, NULL);
    CHECK_CONTAINS(s, "restate build sheet: (no host name recorded)");
    CHECK_CONTAINS(s, "System     FreeBSD 14.2");
    CHECK_CONTAINS(s, "Firmware   legacy BIOS");
    CHECK_CONTAINS(s, "FreeBSD-14.2-RELEASE-arm64-aarch64-memstick.img");
    CHECK_CONTAINS(s, "    DISK1=CHANGE-ME ");
    CHECK_CONTAINS(s, "CHANGE-ME fails safely");
    CHECK_CONTAINS(s, "gpart bootcode -b /boot/pmbr -p /boot/gptboot -i 1 \"$DISK1\"");
    CHECK_CONTAINS(s, "gpart add -t '!516e7cb4-6ecf-11d6-8ff8-00022d09712b' -a 1m -s 1M -i 4");
    CHECK_CONTAINS(s, "newfs -U -L rootfs /dev/${DISK1}p2\n");
    CHECK_CONTAINS(s, "newfs -U /dev/${DISK1}p4\n");
    CHECK_CONTAINS(s, "    mount /dev/${DISK1}p2 /mnt\n");
    CHECK_CONTAINS(s, "    mkdir -p /mnt/data\n    mount /dev/${DISK1}p4 /mnt/data\n");
    CHECK_CONTAINS(s, "for set in base kernel; do");
    CHECK_CONTAINS(s, "    /dev/${DISK1}p2          /            ufs      rw       1 1\n");
    CHECK_CONTAINS(s, "    /dev/${DISK1}p4          /data        ufs      rw       1 2\n");
    CHECK(strstr(s, "zfs_enable") == NULL);
    CHECK(strstr(s, "loader.conf") == NULL);
    CHECK(strstr(s, "kldload") == NULL);
    CHECK(strstr(s, "EFI loader") == NULL);
    CHECK_CONTAINS(s, "It keeps the new system's /etc/fstab");
    CHECK_CONTAINS(s, "The network interfaces are new: what the restore puts back names the old "
                      "ones (ifconfig_NAME in /etc/rc.conf)");
    free(s);
}

static void openbsd_cases(void)
{
    char *s;

    TEST_CASE("bsdsheet: OpenBSD, its label from a template, the rest the installer's");
    s = sheet(openbsd, RS_TARGET_SAME, "{\"pkg\": [{\"name\": \"vim\"}]}", NULL);
    CHECK_CONTAINS(s, "System     OpenBSD 7.6");
    CHECK_CONTAINS(s, "Firmware   not recorded");
    CHECK_CONTAINS(s, "install76.img");
    CHECK_CONTAINS(s, "https://cdn.openbsd.org/pub/OpenBSD/7.6/amd64/");
    CHECK_CONTAINS(s, "against `sysctl hw.disknames`");
    CHECK_CONTAINS(s, "answer s.");
    CHECK_CONTAINS(s, "(cd /dev && sh ./MAKEDEV \"$DISK1\")");
    CHECK_CONTAINS(s, "    DISK2=sd2 ");
    CHECK_CONTAINS(s, "# sd1: nothing of the system's on it -- left alone");
    CHECK_CONTAINS(s, "fdisk -gy -b 532544 \"$DISK1\"");
    CHECK_CONTAINS(s, "fdisk -iy \"$DISK2\"");
    CHECK_CONTAINS(s, "    /                        1024M\n    swap                     512M\n"
                      "    /tmp                     2048M\n    /var                     4096M\n");
    CHECK_CONTAINS(s, "disklabel -w -A -T \"/tmp/$DISK1.layout\" \"$DISK1\"");
    CHECK_CONTAINS(s, "      a  /                        (was sd0a)\n"
                      "      b  swap                     (was sd0b)\n"
                      "      d  /tmp                     (was sd0d)\n"
                      "      e  /var                     (was sd0e)\n");
    CHECK_CONTAINS(s, "System hostname: puffy.");
    CHECK_CONTAINS(s, "        n a       mount point: /\n        n d       mount point: /tmp\n");
    CHECK(strstr(s, "mount point: swap") == NULL);
    CHECK_CONTAINS(s, "at \"Which disk do you wish to initialize?\", $DISK2, and the same:");
    CHECK_CONTAINS(s, "        n a       mount point: /srv\n");
    CHECK(strstr(s, "newfs") == NULL);
    CHECK(strstr(s, "Take the USB stick out") == NULL);
    CHECK_CONTAINS(s, "    cp ./restate-9.9-openbsd-*.tgz ./restate-9.9.tgz\n"
                      "    pkg_add -D unsigned ./restate-9.9.tgz\n");
    CHECK_CONTAINS(s, "pkg_add vim");
    CHECK_CONTAINS(s, "It keeps the new system's /etc/fstab");
    free(s);
}

static void netbsd_cases(void)
{
    char *s;

    TEST_CASE("bsdsheet: NetBSD on wedges, found by their names");
    s = sheet(netbsd, RS_TARGET_SAME, NULL, NULL);
    CHECK_CONTAINS(s, "NetBSD-10.1-amd64-install.img.gz");
    CHECK_CONTAINS(s, "\"Run /bin/sh\"");
    CHECK_CONTAINS(s, "wedge() { dkctl \"$1\" listwedges |");
    CHECK_CONTAINS(s, "gpt create \"$DISK1\"");
    CHECK_CONTAINS(s, "gpt add -i 1 -b 2048 -s 524288 -t efi -l 'EFI system' \"$DISK1\"");
    CHECK_CONTAINS(s, "gpt add -i 2 -b 526336 -s 16777216 -t ffs -l netbsd-root \"$DISK1\"");
    CHECK_CONTAINS(s, "-t linux-data -l wd0-4 \"$DISK1\"");
    CHECK_CONTAINS(s, "dk3 had no GPT label, and the commands here find its wedge by one: it is "
                      "given wd0-4, and /etc/fstab names it NAME=wd0-4.");
    CHECK(strstr(s, "/mnt/linux") == NULL);
    CHECK(strstr(s, "/mnt/old") == NULL);
    CHECK(strstr(s, "$DISK2\" '") == NULL);
    CHECK_CONTAINS(s, "    DISK1=wd0          # was wd0\n");
    CHECK_CONTAINS(s, "(it was wd0).");
    CHECK_CONTAINS(s, "dkctl \"$DISK1\" makewedges");
    CHECK_CONTAINS(s, "a disklabel -- see the notes");
    CHECK_CONTAINS(s, "has a disklabel and no GPT");
    CHECK_CONTAINS(s, "newfs_msdos -F 32 /dev/r$(wedge \"$DISK1\" 'EFI system')\n");
    CHECK_CONTAINS(s, "newfs -O 2 /dev/r$(wedge \"$DISK1\" 'netbsd-root')\n");
    CHECK_CONTAINS(s, "dk3 holds ext2");
    CHECK_CONTAINS(s, "    mount /dev/$(wedge \"$DISK1\" 'netbsd-root') /mnt\n");
    CHECK_CONTAINS(s, "SETS=/amd64/binary/sets");
    CHECK_CONTAINS(s, "cp /mnt/usr/mdec/*.efi /tmp/esp/EFI/boot/");
    CHECK(strstr(s, "biosboot") == NULL);
    CHECK_CONTAINS(s, "    NAME=netbsd-root         /            ffs      rw,log   1 1\n");
    CHECK_CONTAINS(s, "    NAME=netbsd-swap         none         swap     sw,dp    0 0\n");
    CHECK_CONTAINS(s, "rc_configured=YES hostname=nb1 dhcpcd=YES sshd=YES");
    CHECK_CONTAINS(s, "pkg_add ./restate-9.9-netbsd-*.tgz");
    free(s);
}

static void refusal_cases(void)
{
    struct rs_jval       m;
    struct rs_sheet_opts o;
    struct rs_buf        out;
    struct rs_buf        err;

    TEST_CASE("bsdsheet: what it will not write");
    CHECK(rs_bsdsheet_for("FreeBSD") && rs_bsdsheet_for("NetBSD") &&
          rs_bsdsheet_for("OpenBSD"));
    CHECK(!rs_bsdsheet_for("Darwin") && !rs_bsdsheet_for(NULL));
    memset(&o, 0, sizeof(o));
    rs_buf_init(&out);
    rs_buf_init(&err);
    parse(freebsd_zfs, &m);
    o.firmware = "bios";
    CHECK(!rs_buildsheet(&m, &o, &out, &err));
    CHECK_CONTAINS(err.data, "--firmware is for Linux's build sheets in this version; "
                             "FreeBSD's");
    rs_jval_free(&m);
    rs_buf_reset(&err);
    o.firmware = NULL;
    parse("{\"system\": {\"kernel_name\": \"NetBSD\"}, \"disks\": [{\"name\": \"wd0\","
          " \"partitions\": [{\"name\": \"dk0\"}]}]}", &m);
    CHECK(!rs_buildsheet(&m, &o, &out, &err));
    CHECK_CONTAINS(err.data, "no disk with NetBSD's filesystems on it");
    rs_jval_free(&m);
    rs_buf_reset(&err);
    parse("{\"system\": {\"kernel_name\": \"Darwin\"}, \"disks\": []}", &m);
    CHECK(!rs_buildsheet(&m, &o, &out, &err));
    CHECK_CONTAINS(err.data, "written for Linux, FreeBSD, OpenBSD and NetBSD, and this is "
                             "Darwin");
    rs_jval_free(&m);
    rs_buf_free(&out);
    rs_buf_free(&err);
}

static bool autoinst(const char *fixture, enum rs_target target, const char *firmware,
                     char **text, char **why)
{
    struct rs_jval      m;
    struct rs_auto_opts o;
    struct rs_buf       out;
    struct rs_buf       err;
    bool                ok;

    parse(fixture, &m);
    memset(&o, 0, sizeof(o));
    o.target = target;
    o.image = "web.tar";
    o.version = "9.9";
    o.firmware = firmware;
    rs_buf_init(&out);
    rs_buf_init(&err);
    ok = rs_autoinstall(&m, &o, &out, &err);
    *text = rs_buf_detach(&out);
    *why = rs_buf_detach(&err);
    rs_jval_free(&m);
    return ok;
}

/* `fixture` with `from` replaced by `to`, for the variations. */
static char *with(const char *fixture, const char *from, const char *to)
{
    const char   *at = strstr(fixture, from);
    struct rs_buf b;

    rs_buf_init(&b);
    if (!at)
    {
        rs_test_fail(__FILE__, __LINE__, "the fixture has no \"%s\"", from);
        rs_buf_addstr(&b, fixture);
        return rs_buf_detach(&b);
    }
    rs_buf_add(&b, fixture, (size_t)(at - fixture));
    rs_buf_addstr(&b, to);
    rs_buf_addstr(&b, at + strlen(from));
    return rs_buf_detach(&b);
}

static void autoinstall_cases(void)
{
    char *s;
    char *why;
    char *fx;

    TEST_CASE("bsdsheet: FreeBSD's bsdinstall script, on ZFS");
    CHECK(autoinst(freebsd_zfs, RS_TARGET_SAME, NULL, &s, &why));
    CHECK_CONTAINS(s, "# restate autoinstall: fbsd1 -- a bsdinstall script, rebuilt as this "
                      "machine");
    CHECK_CONTAINS(s, "put it at /etc/installerconfig");
    CHECK_CONTAINS(s, "# The pool was GELI-encrypted.");
    CHECK_CONTAINS(s, "export ZFSBOOT_DISKS=\"ada0\"\n"
                      "export ZFSBOOT_VDEV_TYPE=stripe\n"
                      "export ZFSBOOT_POOL_NAME=zroot\n"
                      "export ZFSBOOT_BEROOT_NAME=ROOT\n"
                      "export ZFSBOOT_BOOTFS_NAME=default\n"
                      "export ZFSBOOT_PARTITION_SCHEME=GPT\n"
                      "export ZFSBOOT_BOOT_TYPE=BIOS+UEFI\n"
                      "export ZFSBOOT_SWAP_SIZE=4096m\n"
                      "export ZFSBOOT_SWAP_ENCRYPTION=YES\n");
    CHECK_CONTAINS(s, "\t/ROOT                            mountpoint=none\n"
                      "\t/ROOT/default                    mountpoint=/\n"
                      "\t/home                            mountpoint=/home\n"
                      "\t/usr                             mountpoint=none\n"
                      "\t/usr/ports                       mountpoint=/usr/ports\n\"\n");
    CHECK(strstr(s, "PARTITIONS") == NULL);
    CHECK_CONTAINS(s, "DISTRIBUTIONS=\"kernel.txz base.txz lib32.txz\"\n\n#!/bin/sh\n");
    CHECK_CONTAINS(s, "sysrc hostname=fbsd1\nsysrc ifconfig_DEFAULT=SYNCDHCP sshd_enable=YES\n");
    CHECK_CONTAINS(s, "echo 'CHANGE-ME' | pw usermod root -h 0");
    free(s);
    free(why);

    TEST_CASE("bsdsheet: FreeBSD's bsdinstall script, on UFS, in a virtual machine");
    fx = with(freebsd_ufs, "\"architecture\": \"arm64\"}",
              "\"architecture\": \"arm64\", \"keymap\": \"uk.kbd\", \"timezone\": "
              "\"Europe/London\"}");
    CHECK(autoinst(fx, RS_TARGET_VM, NULL, &s, &why));
    CHECK_CONTAINS(s, "(no host name) -- a bsdinstall script, rebuilt as a virtual machine");
    CHECK_CONTAINS(s, "PARTITIONS=\"vtbd0 gpt { 512K freebsd-boot, 9216M freebsd-ufs /, 4096M "
                      "freebsd-swap, 1M freebsd-ufs /data }\"\n");
    CHECK_CONTAINS(s, "DISTRIBUTIONS=\"kernel.txz base.txz\"\n");
    CHECK(strstr(s, "sysrc hostname") == NULL);
    CHECK_CONTAINS(s, "sysrc keymap=uk.kbd\ntzsetup Europe/London\n");
    free(s);
    free(why);
    free(fx);

    TEST_CASE("bsdsheet: OpenBSD's install.conf, with its disklabel template");
    fx = with(openbsd, "\"hostname\": \"puffy\"}",
              "\"hostname\": \"puffy\", \"timezone\": \"Europe/Oslo\"}");
    CHECK(autoinst(fx, RS_TARGET_SAME, NULL, &s, &why));
    CHECK_CONTAINS(s, "# restate autoinstall: puffy -- an install.conf");
    CHECK_CONTAINS(s, "# The installer partitions the root disk only: the other, as the");
    CHECK_CONTAINS(s, "# ---- puffy.disklabel ----\n"
                      "# /                        1024M\n"
                      "# swap                     512M\n"
                      "# /tmp                     2048M\n"
                      "# /var                     4096M\n"
                      "# ----\n");
    CHECK_CONTAINS(s, "System hostname = puffy\n");
    CHECK_CONTAINS(s, "What timezone are you in = Europe/Oslo\n");
    CHECK_CONTAINS(s, "Which disk is the root disk = sd0\n");
    CHECK_CONTAINS(s, "(O)penBSD area or (E)dit = G\n");
    CHECK_CONTAINS(s, "URL to autopartitioning template for disklabel = "
                      "http://CHANGE-ME/puffy.disklabel\n");
    free(s);
    free(why);
    free(fx);
    fx = with(openbsd, "\"type\": \"MSDOS\", \"content\": {\"type\": \"vfat\"}",
              "\"type\": \"unused\"");
    CHECK(autoinst(fx, RS_TARGET_VM, NULL, &s, &why));
    CHECK_CONTAINS(s, "(O)penBSD area or (E)dit = W\n");
    CHECK_CONTAINS(s, "System hostname = puffy\n");
    CHECK(strstr(s, "What timezone") == NULL);
    free(s);
    free(why);
    free(fx);

    TEST_CASE("bsdsheet: what autoinstall will not write for a BSD");
    CHECK(!autoinst(netbsd, RS_TARGET_SAME, NULL, &s, &why));
    CHECK_CONTAINS(why, "sysinst, reads no answers");
    free(s);
    free(why);
    CHECK(!autoinst(freebsd_zfs, RS_TARGET_SAME, "uefi", &s, &why));
    CHECK_CONTAINS(why, "--firmware is for Ubuntu's autoinstall files; FreeBSD's installs");
    free(s);
    free(why);
    fx = with(freebsd_zfs, "zroot/home", "tank/home");
    CHECK(!autoinst(fx, RS_TARGET_SAME, NULL, &s, &why));
    CHECK_CONTAINS(why, "there are 2 ZFS pools, and bsdinstall makes one");
    free(s);
    free(why);
    free(fx);
    fx = with(freebsd_zfs, "zroot/ROOT/default", "zroot/root");
    CHECK(!autoinst(fx, RS_TARGET_SAME, NULL, &s, &why));
    CHECK_CONTAINS(why, "not a boot environment");
    free(s);
    free(why);
    free(fx);
    fx = with(freebsd_ufs, "\"type\": \"gpt\"", "\"type\": \"dos\"");
    CHECK(!autoinst(fx, RS_TARGET_SAME, NULL, &s, &why));
    CHECK_CONTAINS(why, "nda0 has MBR slices");
    free(s);
    free(why);
    free(fx);
    fx = with(freebsd_ufs, "{\"type\": \"ufs\"}", "{\"type\": \"ext2\"}");
    CHECK(!autoinst(fx, RS_TARGET_SAME, NULL, &s, &why));
    CHECK_CONTAINS(why, "nda0p4 holds ext2, which bsdinstall does not make");
    free(s);
    free(why);
    free(fx);
    fx = with(openbsd, "\"file\": \"/\"", "\"file\": \"/root\"");
    CHECK(!autoinst(fx, RS_TARGET_SAME, NULL, &s, &why));
    CHECK_CONTAINS(why, "no disk holds /");
    free(s);
    free(why);
    free(fx);
    CHECK(!autoinst("{\"system\": {\"kernel_name\": \"OpenBSD\"}}", RS_TARGET_SAME, NULL,
                    &s, &why));
    CHECK_CONTAINS(why, "no disk with OpenBSD's filesystems");
    free(s);
    free(why);
}

void test_bsdsheet(void)
{
    freebsd_cases();
    openbsd_cases();
    netbsd_cases();
    refusal_cases();
    autoinstall_cases();
}
