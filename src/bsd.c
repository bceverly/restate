/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "bsd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#define RS_BSD 1
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(__OpenBSD__) || defined(__NetBSD__)
#define DKTYPENAMES
#define FSTYPENAMES
#include <sys/disklabel.h>
#include <sys/dkio.h>
#endif

#if defined(__NetBSD__)
#include <sys/disk.h>
#include <sys/statvfs.h>
#endif

#include "util.h"

static bool eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static struct rs_jval *array_member(struct rs_jval *obj, const char *key)
{
    size_t          i;
    struct rs_jval *v;

    for (i = 0; i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return &obj->items[i];
        }
    }
    v = rs_jobj_add(obj, key);
    rs_jval_set_array(v);
    return v;
}

/* What a partition type says is on it, where it says anything definite. */
static void content_from_type(struct rs_jval *part, const char *type)
{
    static const struct {
        const char *type;
        const char *fs;
        const char *usage;
    } kinds[] = {
        { "freebsd-ufs", "ufs", "filesystem" },  { "freebsd-swap", "swap", "other" },
        { "freebsd-zfs", "zfs_member", "filesystem" }, { "efi", "vfat", "filesystem" },
        { "4.2BSD", "ffs", "filesystem" },       { "ffs", "ffs", "filesystem" },
        { "swap", "swap", "other" },             { "MSDOS", "vfat", "filesystem" },
        { "msdos", "vfat", "filesystem" },       { "ext2fs", "ext2", "filesystem" },
        { "linux-data", NULL, NULL },
    };
    size_t i;

    for (i = 0; type && i < sizeof(kinds) / sizeof(kinds[0]); i++)
    {
        if (eq(kinds[i].type, type) && kinds[i].fs)
        {
            struct rs_jval *c = rs_jobj_add(part, "content");

            rs_jval_set_object(c);
            rs_jobj_str(c, "type", kinds[i].fs);
            rs_jobj_str(c, "usage", kinds[i].usage);
            rs_jobj_str(c, "source", "the partition type");
            return;
        }
    }
}

/* ------------------------------------------------------------------------- */
/* FreeBSD: GEOM                                                             */
/* ------------------------------------------------------------------------- */

/* The value after `key` among a conftxt line's "key value" pairs. */
static const char *kv(char **tok, size_t n, const char *key)
{
    size_t i;

    for (i = 5; i + 1 < n; i += 2)
    {
        if (strcmp(tok[i], key) == 0)
        {
            return tok[i + 1];
        }
    }
    return NULL;
}

static struct rs_jval *find_disk(struct rs_jval *disks, const char *name)
{
    size_t i;

    for (i = 0; i < disks->n; i++)
    {
        if (eq(rs_jobject_str(&disks->items[i], "name"), name))
        {
            return &disks->items[i];
        }
    }
    return NULL;
}

void rs_geom_parse(const char *conftxt, struct rs_jval *machine)
{
    struct rs_jval *disks;
    struct rs_jval *mapped;
    char           *copy = rs_xstrdup(conftxt ? conftxt : "");
    char           *line;
    char           *save = NULL;
    int             pass;

    /* Both made before either is held: adding a member to the description
     * can move its others, and a pointer taken earlier would then dangle. */
    (void)array_member(machine, "disks");
    (void)array_member(machine, "mapped");
    disks = array_member(machine, "disks");
    mapped = array_member(machine, "mapped");
    /* Two passes: the disks first, since a partition can be listed before
     * the disk it is on. */
    for (pass = 0; pass < 2; pass++)
    {
        free(copy);
        copy = rs_xstrdup(conftxt ? conftxt : "");
        for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
        {
            char  *tok[64];
            size_t n = 0;
            char  *s2 = NULL;
            char  *t;

            for (t = strtok_r(line, " ", &s2); t && n < 64; t = strtok_r(NULL, " ", &s2))
            {
                tok[n++] = t;
            }
            if (n < 5)
            {
                continue;
            }
            if (pass == 0 && strcmp(tok[1], "DISK") == 0 && !rs_starts_with(tok[2], "cd"))
            {
                struct rs_jval *d = rs_jarr_add(disks);

                rs_jval_set_object(d);
                rs_jobj_str(d, "name", tok[2]);
                rs_jobj_u64(d, "size", strtoull(tok[3], NULL, 10));
                rs_jobj_u64(d, "logical_block_size", strtoull(tok[4], NULL, 10));
            } else if (pass == 1 && strcmp(tok[1], "PART") == 0)
            {
                const char     *scheme = kv(tok, n, "xs");
                const char     *ty = kv(tok, n, "ty");
                const char     *xt = kv(tok, n, "xt");
                const char     *index = kv(tok, n, "i");
                const char     *off = kv(tok, n, "o");
                struct rs_jval *disk = NULL;
                struct rs_jval *parts;
                struct rs_jval *p;
                size_t          k;
                char           *parent = rs_xstrdup(tok[2]);

                /* ada0p3 is on ada0; ada0s1a on ada0s1, itself on ada0. */
                for (k = strlen(parent); k > 0 && !disk; k--)
                {
                    parent[k] = '\0';
                    disk = find_disk(disks, parent);
                }
                free(parent);
                if (!disk)
                {
                    continue;
                }
                if (!rs_jobject_get(disk, "table"))
                {
                    struct rs_jval *table = rs_jobj_add(disk, "table");

                    rs_jval_set_object(table);
                    rs_jobj_str(table, "type", eq(scheme, "GPT") ? "gpt" : eq(scheme, "MBR") ? "dos"
                                                                                             : scheme);
                }
                parts = array_member(disk, "partitions");
                p = rs_jarr_add(parts);
                rs_jval_set_object(p);
                rs_jobj_str(p, "name", tok[2]);
                rs_jobj_u64(p, "number", index ? strtoull(index, NULL, 10) : 0);
                rs_jobj_u64(p, "start", off ? strtoull(off, NULL, 10) : 0);
                rs_jobj_u64(p, "size", strtoull(tok[3], NULL, 10));
                if (eq(scheme, "GPT") && xt)
                {
                    rs_jobj_str(p, "type", xt);
                } else if (xt)
                {
                    char hex[16];

                    (void)snprintf(hex, sizeof(hex), "0x%02lx", strtoul(xt, NULL, 10) & 0xffUL);
                    rs_jobj_str(p, "type", eq(scheme, "MBR") ? hex : xt);
                }
                rs_jobj_str(p, "type_name", ty);
                content_from_type(p, ty);
            } else if (pass == 1 && strcmp(tok[1], "ELI") == 0)
            {
                struct rs_jval *m = rs_jarr_add(mapped);
                struct rs_jval *devs;
                size_t          len = strlen(tok[2]);

                rs_jval_set_object(m);
                rs_jobj_str(m, "device", tok[2]);
                rs_jobj_str(m, "name", tok[2]);
                rs_jobj_str(m, "kind", "geli");
                devs = rs_jobj_add(m, "devices");
                rs_jval_set_array(devs);
                if (len > 4 && strcmp(tok[2] + len - 4, ".eli") == 0)
                {
                    char *under = rs_xstrndup(tok[2], len - 4);

                    rs_jval_set_string(rs_jarr_add(devs), under);
                    free(under);
                }
            }
        }
    }
    free(copy);
}

/* ------------------------------------------------------------------------- */
/* Disks from a disklabel or wedges, and mounts                              */
/* ------------------------------------------------------------------------- */

void rs_bsd_add_disk(struct rs_jval *machine, const char *name, uint64_t size, uint64_t sector,
                     const char *table, const struct rs_bsd_part *parts, size_t n)
{
    struct rs_jval *disks = array_member(machine, "disks");
    struct rs_jval *d = rs_jarr_add(disks);

    rs_jval_set_object(d);
    rs_jobj_str(d, "name", name);
    rs_jobj_u64(d, "size", size);
    rs_jobj_u64(d, "logical_block_size", sector ? sector : 512);
    if (table)
    {
        struct rs_jval *t = rs_jobj_add(d, "table");

        rs_jval_set_object(t);
        rs_jobj_str(t, "type", table);
    }
    if (n > 0)
    {
        struct rs_jval *arr = rs_jobj_add(d, "partitions");
        size_t          i;

        rs_jval_set_array(arr);
        for (i = 0; i < n; i++)
        {
            struct rs_jval *p = rs_jarr_add(arr);

            rs_jval_set_object(p);
            rs_jobj_str(p, "name", parts[i].name);
            rs_jobj_u64(p, "number", parts[i].number);
            rs_jobj_u64(p, "start", parts[i].offset);
            rs_jobj_u64(p, "size", parts[i].size);
            rs_jobj_str(p, "type", parts[i].type);
            rs_jobj_str(p, "label", parts[i].label);
            content_from_type(p, parts[i].type);
        }
    }
}

void rs_bsd_add_mount(struct rs_jval *machine, const char *on, const char *from,
                      const char *type, uint64_t size, uint64_t used)
{
    static const char *const keep[] = { "ufs", "ffs", "zfs", "msdosfs", "ext2fs", "apfs", "hfs",
                                        "nfs", "smbfs", "exfat", "ntfs", "fusefs", "lfs", "cd9660" };
    struct rs_jval          *mounts;
    struct rs_jval          *m;
    size_t                   i;
    bool                     data = false;

    for (i = 0; type && i < sizeof(keep) / sizeof(keep[0]); i++)
    {
        data = data || strcmp(type, keep[i]) == 0;
    }
    if (!data || !on)
    {
        return;
    }
    mounts = array_member(machine, "mounts");
    m = rs_jarr_add(mounts);
    rs_jval_set_object(m);
    rs_jobj_str(m, "mountpoint", on);
    rs_jobj_str(m, "type", type);
    rs_jobj_str(m, "source", from);
    if (size > 0 && !eq(type, "nfs") && !eq(type, "smbfs"))
    {
        rs_jobj_u64(m, "size", size);
        rs_jobj_u64(m, "used", used);
    }
}

/* ------------------------------------------------------------------------- */
/* Asking the kernel                                                         */
/* ------------------------------------------------------------------------- */

#ifdef RS_BSD

static struct rs_jval *object_member(struct rs_jval *obj, const char *key)
{
    size_t          i;
    struct rs_jval *v;

    for (i = 0; i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return &obj->items[i];
        }
    }
    v = rs_jobj_add(obj, key);
    rs_jval_set_object(v);
    return v;
}

static void note(struct rs_jval *machine, const char *text)
{
    rs_jval_set_string(rs_jarr_add(array_member(machine, "notes")), text);
}

/* Set only what Linux's readers did not: NetBSD's /proc can answer them too,
 * and a key twice would make the index unreadable. */
static void put_str(struct rs_jval *obj, const char *key, const char *value)
{
    if (value && !rs_jobject_get(obj, key))
    {
        rs_jobj_str(obj, key, value);
    }
}

static void put_u64(struct rs_jval *obj, const char *key, uint64_t value)
{
    if (value > 0 && !rs_jobject_get(obj, key))
    {
        rs_jobj_u64(obj, key, value);
    }
}

#if defined(__OpenBSD__)
static char *sysctl_str(int top, int second)
{
    int    mib[2] = { top, second };
    size_t len = 0;
    char  *s;

    if (sysctl(mib, 2, NULL, &len, NULL, 0) != 0 || len == 0)
    {
        return NULL;
    }
    s = rs_xcalloc(len + 1, 1);
    if (sysctl(mib, 2, s, &len, NULL, 0) != 0)
    {
        free(s);
        return NULL;
    }
    return s;
}
#else
static char *sysctl_str(const char *name)
{
    size_t len = 0;
    char  *s;

    if (sysctlbyname(name, NULL, &len, NULL, 0) != 0 || len == 0)
    {
        return NULL;
    }
    s = rs_xcalloc(len + 1, 1);
    if (sysctlbyname(name, s, &len, NULL, 0) != 0)
    {
        free(s);
        return NULL;
    }
    return s;
}

static uint64_t sysctl_u64(const char *name)
{
    uint64_t v64 = 0;
    uint32_t v32 = 0;
    size_t   len = sizeof(v64);

    if (sysctlbyname(name, &v64, &len, NULL, 0) == 0 && len == sizeof(v64))
    {
        return v64;
    }
    len = sizeof(v32);
    if (sysctlbyname(name, &v32, &len, NULL, 0) == 0 && len == sizeof(v32))
    {
        return v32;
    }
    return 0;
}
#endif

static void hardware(struct rs_jval *machine)
{
    struct rs_jval *hw = object_member(machine, "hardware");
    char           *s;

#if defined(__OpenBSD__)
    {
        int      mib[2] = { CTL_HW, HW_PHYSMEM64 };
        int64_t  mem = 0;
        int      ncpu = 0;
        size_t   len = sizeof(mem);

        s = sysctl_str(CTL_HW, HW_VENDOR);
        put_str(hw, "sys_vendor", s);
        free(s);
        s = sysctl_str(CTL_HW, HW_PRODUCT);
        put_str(hw, "product_name", s);
        free(s);
        s = sysctl_str(CTL_HW, HW_MODEL);
        put_str(hw, "cpu", s);
        free(s);
        if (sysctl(mib, 2, &mem, &len, NULL, 0) == 0 && mem > 0)
        {
            put_u64(hw, "memory", (uint64_t)mem);
        }
        mib[1] = HW_NCPU;
        len = sizeof(ncpu);
        if (sysctl(mib, 2, &ncpu, &len, NULL, 0) == 0 && ncpu > 0)
        {
            put_u64(hw, "cpus", (uint64_t)ncpu);
        }
    }
#else
#if defined(__APPLE__)
    s = sysctl_str("hw.model");
    put_str(hw, "product_name", s);
    free(s);
    put_str(hw, "sys_vendor", "Apple");
    s = sysctl_str("machdep.cpu.brand_string");
    put_str(hw, "cpu", s);
    free(s);
    put_u64(hw, "memory", sysctl_u64("hw.memsize"));
#elif defined(__NetBSD__)
    s = sysctl_str("machdep.dmi.system-vendor");
    put_str(hw, "sys_vendor", s);
    free(s);
    s = sysctl_str("machdep.dmi.system-product");
    put_str(hw, "product_name", s);
    free(s);
    s = sysctl_str("machdep.cpu_brand");
    put_str(hw, "cpu", s);
    free(s);
    put_u64(hw, "memory", sysctl_u64("hw.physmem64"));
#else
    s = sysctl_str("hw.model");
    put_str(hw, "cpu", s);
    free(s);
    put_u64(hw, "memory", sysctl_u64("hw.physmem"));
#endif
    put_u64(hw, "cpus", sysctl_u64("hw.ncpu"));
#endif
}

/* The interfaces with a hardware address, from getifaddrs. */
static void network(struct rs_jval *machine)
{
    struct rs_jval       *hw = object_member(machine, "hardware");
    struct rs_jval       *net = array_member(hw, "network");
    struct ifaddrs       *ifs = NULL;
    const struct ifaddrs *a;

    if (getifaddrs(&ifs) != 0)
    {
        return;
    }
    for (a = ifs; a; a = a->ifa_next)
    {
        const struct sockaddr_dl *dl;
        const unsigned char      *mac;
        char                      text[18];
        struct rs_jval           *n;

        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_LINK || (a->ifa_flags & IFF_LOOPBACK))
        {
            continue;
        }
        dl = (const struct sockaddr_dl *)(const void *)a->ifa_addr;
        if (dl->sdl_alen != 6)
        {
            continue;
        }
        /* LLADDR without its cast, which drops const on some systems. */
        mac = (const unsigned char *)dl->sdl_data + dl->sdl_nlen;
        (void)snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2],
                       mac[3], mac[4], mac[5]);
        n = rs_jarr_add(net);
        rs_jval_set_object(n);
        rs_jobj_str(n, "name", a->ifa_name);
        rs_jobj_str(n, "mac", text);
    }
    freeifaddrs(ifs);
}

static void mount_table(struct rs_jval *machine)
{
#if defined(__NetBSD__)
    struct statvfs *mnt = NULL;
#else
    struct statfs *mnt = NULL;
#endif
    int i;
    int n = getmntinfo(&mnt, MNT_NOWAIT);

    (void)array_member(machine, "mounts");
    for (i = 0; i < n; i++)
    {
#if defined(__NetBSD__)
        uint64_t unit = (uint64_t)mnt[i].f_frsize;
#else
        uint64_t unit = (uint64_t)mnt[i].f_bsize;
#endif
        uint64_t size = (uint64_t)mnt[i].f_blocks * unit;
        uint64_t used = ((uint64_t)mnt[i].f_blocks - (uint64_t)mnt[i].f_bfree) * unit;

        rs_bsd_add_mount(machine, mnt[i].f_mntonname, mnt[i].f_mntfromname, mnt[i].f_fstypename,
                         size, used);
    }
}

#if defined(__OpenBSD__) || defined(__NetBSD__)
/* The names in hw.disknames, which OpenBSD writes "sd0:duid,cd0:" and NetBSD
 * "wd0 dk0 cd0". Optical drives, RAM disks and vnodes are not disks to rebuild. */
static char **disk_names(size_t *count)
{
#if defined(__OpenBSD__)
    char *s = sysctl_str(CTL_HW, HW_DISKNAMES);
#else
    char *s = sysctl_str("hw.disknames");
#endif
    char **names = NULL;
    char  *save = NULL;
    char  *t;

    *count = 0;
    for (t = s ? strtok_r(s, ", ", &save) : NULL; t; t = strtok_r(NULL, ", ", &save))
    {
        char *colon = strchr(t, ':');

        if (colon)
        {
            *colon = '\0';
        }
        if (rs_starts_with(t, "cd") || rs_starts_with(t, "rd") || rs_starts_with(t, "vnd") ||
            rs_starts_with(t, "md") || t[0] == '\0')
        {
            continue;
        }
        names = rs_xreallocarray(names, *count + 1, sizeof(*names));
        names[(*count)++] = rs_xstrdup(t);
    }
    free(s);
    return names;
}

/* A disk's disklabel, as partitions. */
static void disklabel_disk(struct rs_jval *machine, const char *name)
{
    struct disklabel   dl;
    struct rs_bsd_part parts[MAXPARTITIONS];
    char               names[MAXPARTITIONS][32];
    size_t             n = 0;
    int                i;
    char               raw = (char)('a' + RAW_PART);
    char              *path = rs_xasprintf("/dev/r%s%c", name, raw);
    int                fd = open(path, O_RDONLY | O_CLOEXEC);
    uint64_t           sector;
    uint64_t           size;

    free(path);
    if (fd < 0 || ioctl(fd, DIOCGDINFO, &dl) != 0)
    {
        char *msg = rs_xasprintf("%s: its disklabel could not be read (%s); reading it needs root",
                                 name, strerror(errno));

        note(machine, msg);
        free(msg);
        if (fd >= 0)
        {
            (void)close(fd);
        }
        return;
    }
    (void)close(fd);
    sector = dl.d_secsize;
#if defined(__OpenBSD__)
    size = (uint64_t)DL_GETDSIZE(&dl) * sector;
#else
    size = (uint64_t)dl.d_secperunit * sector;
#endif
    for (i = 0; i < dl.d_npartitions && i < MAXPARTITIONS; i++)
    {
        const struct partition *p = &dl.d_partitions[i];
#if defined(__OpenBSD__)
        uint64_t                psize = DL_GETPSIZE(p);
        uint64_t                poff = DL_GETPOFFSET(p);
#else
        uint64_t                psize = p->p_size;
        uint64_t                poff = p->p_offset;
#endif

        if (psize == 0 || i == RAW_PART || p->p_fstype == FS_UNUSED)
        {
            continue;
        }
        (void)snprintf(names[n], sizeof(names[n]), "%s%c", name, 'a' + i);
        parts[n].name = names[n];
        parts[n].number = (unsigned)i + 1;
        parts[n].offset = poff * sector;
        parts[n].size = psize * sector;
        parts[n].type = p->p_fstype < FSMAXTYPES ? fstypenames[p->p_fstype] : "unknown";
        parts[n].label = NULL;
        n++;
    }
    rs_bsd_add_disk(machine, name, size, sector, "disklabel", parts, n);
}
#endif

#if defined(__NetBSD__)
/* NetBSD's GPT disks are wedges -- dk0, dk1 -- each naming its parent. */
static void netbsd_disks(struct rs_jval *machine)
{
    size_t               nn;
    char               **names = disk_names(&nn);
    struct dkwedge_info *w = NULL;
    size_t               nw = 0;
    size_t               i;
    size_t               j;

    for (i = 0; i < nn; i++)
    {
        char *path;
        int   fd;

        if (!rs_starts_with(names[i], "dk"))
        {
            continue;
        }
        path = rs_xasprintf("/dev/r%s", names[i]);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        free(path);
        w = rs_xreallocarray(w, nw + 1, sizeof(*w));
        if (fd >= 0 && ioctl(fd, DIOCGWEDGEINFO, &w[nw]) == 0)
        {
            nw++;
        }
        if (fd >= 0)
        {
            (void)close(fd);
        }
    }
    for (i = 0; i < nn; i++)
    {
        struct rs_bsd_part *parts;
        size_t              np = 0;

        if (rs_starts_with(names[i], "dk"))
        {
            continue;
        }
        parts = rs_xcalloc(nw + 1, sizeof(*parts));
        for (j = 0; j < nw; j++)
        {
            if (strcmp(w[j].dkw_parent, names[i]) == 0)
            {
                parts[np].name = w[j].dkw_devname;
                parts[np].number = (unsigned)np + 1;
                parts[np].offset = (uint64_t)w[j].dkw_offset * 512;
                parts[np].size = (uint64_t)w[j].dkw_size * 512;
                parts[np].type = w[j].dkw_ptype;
                parts[np].label = (const char *)w[j].dkw_wname;
                np++;
            }
        }
        if (np > 0)
        {
            rs_bsd_add_disk(machine, names[i], 0, 512, "gpt", parts, np);
        } else
        {
            disklabel_disk(machine, names[i]);
        }
        free(parts);
    }
    for (i = 0; i < nn; i++)
    {
        free(names[i]);
    }
    free(names);
    free(w);
}
#endif

bool rs_bsd_describe(struct rs_jval *machine)
{
    hardware(machine);
    network(machine);
#if defined(__FreeBSD__)
    {
        char           *conf = sysctl_str("kern.geom.conftxt");
        char           *boot = sysctl_str("machdep.bootmethod");
        struct rs_jval *fw = object_member(machine, "firmware");

        put_str(fw, "mode", eq(boot, "UEFI") ? "uefi" : eq(boot, "BIOS") ? "bios" : NULL);
        if (conf)
        {
            rs_geom_parse(conf, machine);
        } else
        {
            note(machine, "kern.geom.conftxt could not be read, so the disks are not described");
        }
        free(conf);
        free(boot);
    }
#elif defined(__OpenBSD__)
    {
        size_t n;
        char **names = disk_names(&n);
        size_t i;

        for (i = 0; i < n; i++)
        {
            disklabel_disk(machine, names[i]);
            free(names[i]);
        }
        free(names);
    }
#elif defined(__NetBSD__)
    netbsd_disks(machine);
#elif defined(__APPLE__)
    note(machine, "on macOS the disks are described through Disk Arbitration, not libc, so "
                  "only the hardware, interfaces and mounts are recorded in this version");
#endif
    mount_table(machine);
    return true;
}

#else

bool rs_bsd_describe(struct rs_jval *machine)
{
    (void)machine;
    return false;
}

#endif
