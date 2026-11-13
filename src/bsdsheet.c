/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "bsdsheet.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "layout.h"

#define MIB ((uint64_t)1024 * 1024)
#define GIB (MIB * 1024)

enum os {
    OS_FREEBSD,
    OS_OPENBSD,
    OS_NETBSD
};

/* A partition, as the machine description has it, and what it was for. */
struct bpart {
    const char           *name;        /* ada0p2, sd0a, dk1 */
    unsigned              number;
    uint64_t              start;       /* bytes */
    uint64_t              size;
    const char           *type;        /* a GPT GUID, an MBR type, a disklabel fstype */
    const char           *type_name;   /* FreeBSD's name for it: freebsd-ufs */
    const char           *label;       /* the GPT label, a wedge's name */
    const char           *fs;          /* ufs, ffs, swap, vfat, zfs_member */
    const char           *fslabel;     /* the filesystem's own */
    const char           *mountpoint;  /* "/", "/usr", "[swap]", or NULL */
    const struct rs_jval *fstab;       /* its /etc/fstab line, if it has one */
    uint64_t              used;        /* bytes its filesystem held */
    bool                  used_known;
    bool                  eli;         /* a GELI provider is on it */
    bool                  pool;        /* a ZFS pool's */
    size_t                disk;
    char                 *made_label;  /* the label given it here, where it had none */
};

struct bdisk {
    const char *name;
    uint64_t    size;
    uint64_t    sector;
    const char *table;       /* "gpt", "dos", "disklabel" */
    const char *duid;        /* OpenBSD's */
    bool        used;        /* something of the system's is on it */
    bool        supported;   /* a partition table this writes commands for */
    unsigned    var;         /* $DISKn, numbered among the used */
};

/* A ZFS dataset that was mounted. */
struct dataset {
    const char *name;        /* zroot/ROOT/default */
    const char *mountpoint;
    uint64_t    used;
};

struct bs {
    const struct rs_jval       *machine;
    const struct rs_jval       *sys;
    const struct rs_sheet_opts *o;
    enum os                     os;
    struct rs_buf              *out;
    struct rs_buf              *notes;
    unsigned                   *step;
    struct bdisk               *disks;
    size_t                      ndisks;
    struct bpart               *parts;
    size_t                      nparts;
    struct dataset             *ds;
    size_t                      nds;
    char                      **pools;
    size_t                      npools;
    const char                 *firmware;  /* "uefi", "bios", or NULL */
};

static void say(struct bs *b, const char *fmt, ...) RESTATE_PRINTF(2, 3);

static void say(struct bs *b, const char *fmt, ...)
{
    va_list ap;
    char   *text;

    va_start(ap, fmt);
    text = rs_xvasprintf(fmt, ap);
    va_end(ap);
    rs_buf_addstr(b->out, text);
    rs_buf_add(b->out, "\n", 1);
    free(text);
}

static void note(struct bs *b, const char *fmt, ...) RESTATE_PRINTF(2, 3);

static void note(struct bs *b, const char *fmt, ...)
{
    va_list ap;
    char   *text;

    va_start(ap, fmt);
    text = rs_xvasprintf(fmt, ap);
    va_end(ap);
    rs_buf_addf(b->notes, "  - %s\n", text);
    free(text);
}

static void heading(struct bs *b, const char *title)
{
    size_t i;
    size_t n;

    (*b->step)++;
    rs_buf_addf(b->out, "\n%u. %s\n", *b->step, title);
    n = strlen(title) + (*b->step >= 10 ? 4 : 3);
    for (i = 0; i < n; i++)
    {
        rs_buf_add(b->out, "-", 1);
    }
    rs_buf_add(b->out, "\n", 1);
}

static bool eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static const char *size_text(uint64_t bytes, char *buf, size_t len)
{
    rs_human_size(bytes, buf, len);
    return buf;
}

static uint64_t round_up(uint64_t n, uint64_t unit)
{
    return (n + unit - 1) / unit * unit;
}

static const char *const os_names[] = { "FreeBSD", "OpenBSD", "NetBSD" };

bool rs_bsdsheet_for(const char *kernel)
{
    size_t i;

    for (i = 0; i < sizeof(os_names) / sizeof(os_names[0]); i++)
    {
        if (eq(kernel, os_names[i]))
        {
            return true;
        }
    }
    return false;
}

static enum os os_of(const struct rs_jval *machine)
{
    const char *k = rs_jobject_str(rs_jobject_get(machine, "system"), "kernel_name");

    return eq(k, "OpenBSD") ? OS_OPENBSD : eq(k, "NetBSD") ? OS_NETBSD : OS_FREEBSD;
}

/* ------------------------------------------------------------------------- */
/* What was there                                                            */
/* ------------------------------------------------------------------------- */

/* The letter OpenBSD's autoallocation gives after `c`: never c, the whole
 * disk, nor i, the EFI system partition fdisk made, where there is one. */
static char next_letter(char c, bool esp)
{
    while (c == 'c' || (esp && c == 'i'))
    {
        c++;
    }
    return c;
}

/* A partition's letter in its disklabel: sd0a's a. */
static char letter(const struct bpart *p)
{
    size_t n = strlen(p->name);

    if (n == 0)
    {
        return '?';
    }
    return p->name[n - 1];
}

static bool is_esp(const struct bpart *p)
{
    return eq(p->type_name, "efi") || eq(p->fs, "vfat") ||
           rs_ptype_is(p->type, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
}

static bool is_boot(const struct bpart *p)
{
    return eq(p->type_name, "freebsd-boot");
}

static bool is_swap(const struct bpart *p)
{
    return eq(p->fs, "swap");
}

/* Whether the /etc/fstab or mount table's `spec` names partition `p`. */
static bool names_part(const struct bs *b, const char *spec, const struct bpart *p)
{
    const char *s = spec;
    char       *want;
    bool        hit;

    if (!s)
    {
        return false;
    }
    if (rs_starts_with(s, "NAME="))
    {
        return eq(s + 5, p->label);
    }
    if (rs_starts_with(s, "/dev/"))
    {
        s += 5;
    }
    if (eq(s, p->name))
    {
        return true;
    }
    hit = false;
    if (p->name)
    {
        want = rs_xasprintf("%s.eli", p->name);
        hit = eq(s, want);
        free(want);
    }
    if (hit || (rs_starts_with(s, "gpt/") && eq(s + 4, p->label)) ||
        (rs_starts_with(s, "ufs/") && eq(s + 4, p->fslabel)) ||
        (rs_starts_with(s, "msdosfs/") && eq(s + 8, p->fslabel)))
    {
        return true;
    }
    if (b->disks[p->disk].duid)
    {
        want = rs_xasprintf("%s.%c", b->disks[p->disk].duid, letter(p));
        hit = eq(s, want);
        free(want);
    }
    return hit;
}

static void add_dataset(struct bs *b, const char *name, const char *mountpoint, uint64_t used)
{
    struct dataset *d;
    const char     *slash = strchr(name, '/');
    size_t          plen = slash ? (size_t)(slash - name) : strlen(name);
    size_t          i;
    bool            known = false;

    b->ds = rs_xreallocarray(b->ds, b->nds + 1, sizeof(*b->ds));
    d = &b->ds[b->nds++];
    d->name = name;
    d->mountpoint = mountpoint;
    d->used = used;
    for (i = 0; i < b->npools; i++)
    {
        known = known || (strlen(b->pools[i]) == plen && strncmp(b->pools[i], name, plen) == 0);
    }
    if (!known)
    {
        b->pools = rs_xreallocarray(b->pools, b->npools + 1, sizeof(*b->pools));
        b->pools[b->npools++] = rs_xstrndup(name, plen);
    }
}

static void collect(struct bs *b)
{
    const struct rs_jval *disks = rs_jobject_get(b->machine, "disks");
    const struct rs_jval *mapped = rs_jobject_get(b->machine, "mapped");
    const struct rs_jval *fstab = rs_jobject_get(b->machine, "fstab");
    const struct rs_jval *mounts = rs_jobject_get(b->machine, "mounts");
    size_t                i;
    size_t                j;
    unsigned              var = 0;

    for (i = 0; disks && disks->type == RS_JARRAY && i < disks->n; i++)
    {
        const struct rs_jval *d = &disks->items[i];
        const struct rs_jval *parts = rs_jobject_get(d, "partitions");
        const struct rs_jval *v;
        struct bdisk         *disk;

        if (!parts || parts->type != RS_JARRAY || parts->n == 0)
        {
            continue;
        }
        b->disks = rs_xreallocarray(b->disks, b->ndisks + 1, sizeof(*b->disks));
        disk = &b->disks[b->ndisks];
        memset(disk, 0, sizeof(*disk));
        disk->name = rs_jobject_str(d, "name");
        v = rs_jobject_get(d, "size");
        disk->size = v && v->type == RS_JINT ? v->u : 0;
        v = rs_jobject_get(d, "logical_block_size");
        disk->sector = v && v->type == RS_JINT && v->u ? v->u : 512;
        disk->table = rs_jobject_str(rs_jobject_get(d, "table"), "type");
        disk->duid = rs_jobject_str(d, "duid");
        for (j = 0; j < parts->n; j++)
        {
            const struct rs_jval *pj = &parts->items[j];
            const struct rs_jval *c = rs_jobject_get(pj, "content");
            struct bpart         *p;

            b->parts = rs_xreallocarray(b->parts, b->nparts + 1, sizeof(*b->parts));
            p = &b->parts[b->nparts++];
            memset(p, 0, sizeof(*p));
            p->name = rs_jobject_str(pj, "name");
            v = rs_jobject_get(pj, "number");
            p->number = v && v->type == RS_JINT ? (unsigned)v->u : 0;
            v = rs_jobject_get(pj, "start");
            p->start = v && v->type == RS_JINT ? v->u : 0;
            v = rs_jobject_get(pj, "size");
            p->size = v && v->type == RS_JINT ? v->u : 0;
            p->type = rs_jobject_str(pj, "type");
            p->type_name = rs_jobject_str(pj, "type_name");
            p->label = rs_jobject_str(pj, "label");
            p->fs = rs_jobject_str(c, "type");
            p->fslabel = rs_jobject_str(c, "label");
            p->disk = b->ndisks;
            if (!p->name)
            {
                b->nparts--;
            }
        }
        b->ndisks++;
    }
    for (i = 0; mapped && mapped->type == RS_JARRAY && i < mapped->n; i++)
    {
        const struct rs_jval *under = rs_jobject_get(&mapped->items[i], "devices");

        if (!eq(rs_jobject_str(&mapped->items[i], "kind"), "geli") || !under ||
            under->type != RS_JARRAY || under->n == 0)
        {
            continue;
        }
        for (j = 0; j < b->nparts; j++)
        {
            b->parts[j].eli = b->parts[j].eli || eq(under->items[0].s, b->parts[j].name);
        }
    }
    for (i = 0; fstab && fstab->type == RS_JARRAY && i < fstab->n; i++)
    {
        const struct rs_jval *e = &fstab->items[i];

        for (j = 0; j < b->nparts; j++)
        {
            if (!b->parts[j].mountpoint && names_part(b, rs_jobject_str(e, "spec"), &b->parts[j]))
            {
                b->parts[j].mountpoint = eq(rs_jobject_str(e, "type"), "swap")
                                             ? "[swap]"
                                             : rs_jobject_str(e, "file");
                b->parts[j].fstab = e;
                break;
            }
        }
    }
    for (i = 0; mounts && mounts->type == RS_JARRAY && i < mounts->n; i++)
    {
        const struct rs_jval *e = &mounts->items[i];
        const struct rs_jval *used = rs_jobject_get(e, "used");
        const char           *source = rs_jobject_str(e, "source");
        const char           *mp = rs_jobject_str(e, "mountpoint");

        if (eq(rs_jobject_str(e, "type"), "zfs") && source && mp)
        {
            add_dataset(b, source, mp, used && used->type == RS_JINT ? used->u : 0);
            continue;
        }
        for (j = 0; j < b->nparts; j++)
        {
            if (names_part(b, source, &b->parts[j]))
            {
                if (!b->parts[j].mountpoint)
                {
                    b->parts[j].mountpoint = mp;
                }
                if (used && used->type == RS_JINT)
                {
                    b->parts[j].used = used->u;
                    b->parts[j].used_known = true;
                }
                break;
            }
        }
    }
    for (j = 0; j < b->nparts; j++)
    {
        struct bpart *p = &b->parts[j];

        p->pool = b->npools > 0 && eq(p->fs, "zfs_member");
        if (p->mountpoint || p->pool)
        {
            b->disks[p->disk].used = true;
        }
    }
    for (i = 0; i < b->ndisks; i++)
    {
        struct bdisk *d = &b->disks[i];

        d->supported = b->os == OS_OPENBSD ? eq(d->table, "disklabel") : eq(d->table, "gpt");
        if (d->used)
        {
            d->var = ++var;
        }
    }
    /* NetBSD's commands find a wedge by its name: one without is given one. */
    for (j = 0; b->os == OS_NETBSD && j < b->nparts; j++)
    {
        struct bpart *p = &b->parts[j];

        if (!p->label && b->disks[p->disk].supported && b->disks[p->disk].used)
        {
            p->made_label = rs_xasprintf("%s-%u", b->disks[p->disk].name, p->number);
            p->label = p->made_label;
        }
    }
    b->firmware = rs_jobject_str(rs_jobject_get(b->machine, "firmware"), "mode");
}

/* Whether partition `p` is rebuilt: one of the system's, or the boot
 * partition of a disk that is. */
static bool rebuilt(const struct bs *b, const struct bpart *p)
{
    if (!b->disks[p->disk].used || !b->disks[p->disk].supported)
    {
        return false;
    }
    return p->mountpoint || p->pool || is_esp(p) || is_boot(p);
}

/* Whether this sheet makes, mounts and lists in /etc/fstab the filesystem
 * on `p`: one of the system's own kinds, or swap. */
static bool known_fs(const struct bpart *p)
{
    return eq(p->fs, "ufs") || eq(p->fs, "ffs") || is_esp(p) || is_swap(p);
}

/* What `p` holds, in bytes: a pool's partition, the pool's datasets. */
static uint64_t holds(const struct bs *b, const struct bpart *p, bool *known)
{
    if (p->pool)
    {
        uint64_t sum = 0;
        size_t   i;

        for (i = 0; i < b->nds; i++)
        {
            sum += b->ds[i].used;
        }
        *known = b->nds > 0;
        return sum;
    }
    *known = p->used_known;
    return p->used;
}

/* Its size, rebuilt for the target: in a virtual machine, what its
 * filesystem used and room to grow, as on Linux (layout.h). */
static uint64_t fit(const struct bs *b, const struct bpart *p)
{
    uint64_t want;
    uint64_t h;
    bool     known;

    if (b->o->target != RS_TARGET_VM || is_esp(p) || is_boot(p))
    {
        return p->size;
    }
    if (is_swap(p))
    {
        return p->size < 8 * GIB ? p->size : 8 * GIB;
    }
    h = holds(b, p, &known);
    if (!known)
    {
        return p->size;
    }
    want = round_up(h + h / 4 + (p->pool ? 4 : 2) * GIB, GIB);
    if (p->size > 0 && want > p->size)
    {
        want = p->size;
    }
    return want < GIB && p->size >= GIB ? GIB : want;
}

/* $DISKn's partition, as a device path for the shell: "/dev/${DISK1}p2". */
static char *dev(const struct bs *b, const struct bpart *p)
{
    unsigned var = b->disks[p->disk].var;

    if (b->os == OS_OPENBSD)
    {
        return rs_xasprintf("/dev/${DISK%u}%c", var, letter(p));
    }
    if (b->os == OS_NETBSD)
    {
        return rs_xasprintf("/dev/$(wedge \"$DISK%u\" '%s')", var, p->label ? p->label : "");
    }
    return rs_xasprintf("/dev/${DISK%u}p%u", var, p->number);
}

/* The raw one, for newfs on OpenBSD and NetBSD. */
static char *raw_dev(const struct bs *b, const struct bpart *p)
{
    unsigned var = b->disks[p->disk].var;

    if (b->os == OS_OPENBSD)
    {
        return rs_xasprintf("/dev/r${DISK%u}%c", var, letter(p));
    }
    if (b->os == OS_NETBSD)
    {
        return rs_xasprintf("/dev/r$(wedge \"$DISK%u\" '%s')", var, p->label ? p->label : "");
    }
    return dev(b, p);
}

/* Where the new machine's disk `d` is expected to be. */
static char *disk_default(const struct bs *b, const struct bdisk *d)
{
    static const char *const vm[] = { "vtbd", "sd", "ld" };

    if (b->o->target == RS_TARGET_SAME)
    {
        return rs_xstrdup(d->name ? d->name : "CHANGE-ME");
    }
    if (b->o->target == RS_TARGET_VM)
    {
        return rs_xasprintf("%s%u", vm[b->os], d->var - 1);
    }
    return rs_xstrdup("CHANGE-ME");
}

static bool any_pool_root(const struct bs *b)
{
    size_t i;

    for (i = 0; i < b->nds; i++)
    {
        if (eq(b->ds[i].mountpoint, "/"))
        {
            return true;
        }
    }
    return false;
}

static bool any_eli(const struct bs *b)
{
    size_t i;

    for (i = 0; i < b->nparts; i++)
    {
        if (rebuilt(b, &b->parts[i]) && b->parts[i].eli && !is_swap(&b->parts[i]))
        {
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------------- */
/* The installer                                                             */
/* ------------------------------------------------------------------------- */

/* The installer's image and where it is published, or NULLs. */
static void installer(const struct bs *b, char **file, char **url, const char **check)
{
    const char *ver = rs_jobject_str(b->sys, "version_id");
    const char *arch = rs_jobject_str(b->sys, "architecture");

    *file = NULL;
    *url = NULL;
    *check = NULL;
    if (!ver || !arch)
    {
        return;
    }
    if (b->os == OS_FREEBSD)
    {
        const char *a = eq(arch, "amd64")   ? "amd64"
                        : eq(arch, "arm64") ? "arm64-aarch64"
                        : eq(arch, "i386")  ? "i386"
                                            : NULL;

        if (a)
        {
            *file = rs_xasprintf("FreeBSD-%s-RELEASE-%s-memstick.img", ver, a);
            *url = rs_xasprintf("https://download.freebsd.org/releases/ISO-IMAGES/%s/", ver);
            *check = "Check it against the CHECKSUM.SHA256 file there, which the release\n"
                     "    announcement signs";
        }
    } else if (b->os == OS_OPENBSD)
    {
        char  *short_ver = rs_xstrdup(ver);
        char  *dot = strchr(short_ver, '.');

        if (dot)
        {
            memmove(dot, dot + 1, strlen(dot));
        }
        *file = rs_xasprintf("install%s.img", short_ver);
        *url = rs_xasprintf("https://cdn.openbsd.org/pub/OpenBSD/%s/%s/", ver, arch);
        *check = "Check it with signify against SHA256.sig there, and an OpenBSD\n"
                 "    machine's /etc/signify/openbsd-NN-base.pub";
        free(short_ver);
    } else if (eq(arch, "amd64") || eq(arch, "i386"))
    {
        *file = rs_xasprintf("NetBSD-%s-%s-install.img.gz", ver, arch);
        *url = rs_xasprintf("https://cdn.netbsd.org/pub/NetBSD/NetBSD-%s/images/", ver);
        *check = "Check it against the SHA512 file there";
    }
}

/* ------------------------------------------------------------------------- */
/* The steps                                                                 */
/* ------------------------------------------------------------------------- */

static void intro(struct bs *b)
{
    const struct rs_jval *hw = rs_jobject_get(b->machine, "hardware");
    const char           *host = rs_jobject_str(b->sys, "hostname");
    const char           *pretty = rs_jobject_str(b->sys, "pretty_name");
    const char           *ver = rs_jobject_str(b->sys, "version_id");
    const char           *vendor = rs_jobject_str(hw, "sys_vendor");
    const char           *model = rs_jobject_str(hw, "product_name");
    const char           *cpu = rs_jobject_str(hw, "cpu");
    const struct rs_jval *mem = rs_jobject_get(hw, "memory");
    const struct rs_jval *cpus = rs_jobject_get(hw, "cpus");
    const char           *from = b->o->export_from ? b->o->export_from : b->o->image;
    char                  buf[32];
    static const char    *const targets[] = {
        "this machine, or one like it -- the original sizes, exactly",
        "a virtual machine -- each volume sized to what it uses",
        "other hardware -- the original sizes"
    };

    say(b, "restate build sheet: %s", host ? host : "(no host name recorded)");
    say(b, "%s", "==========================================================================");
    say(b, "%s", "");
    if (pretty)
    {
        say(b, "  System     %s", pretty);
    } else
    {
        say(b, "  System     %s%s%s", os_names[b->os], ver ? " " : "", ver ? ver : "");
    }
    if (vendor || model)
    {
        say(b, "  Hardware   %s%s%s", vendor ? vendor : "", vendor && model ? " " : "",
            model ? model : "");
    }
    if (cpu || cpus || mem)
    {
        say(b, "             %s%s%" PRIu64 " CPUs, %s memory", cpu ? cpu : "", cpu ? ", " : "",
            cpus && cpus->type == RS_JINT ? cpus->u : 0,
            size_text(mem && mem->type == RS_JINT ? mem->u : 0, buf, sizeof(buf)));
    }
    if (eq(b->firmware, "uefi") || eq(b->firmware, "bios"))
    {
        say(b, "  Firmware   %s", eq(b->firmware, "uefi") ? "UEFI" : "legacy BIOS");
    } else
    {
        say(b, "%s", "  Firmware   not recorded");
    }
    say(b, "  Rebuilt as %s", targets[b->o->target]);
    say(b, "  Made by    restate %s%s%s", b->o->version ? b->o->version : "",
        from ? " from " : " from the running system", from ? from : "");
    say(b, "%s", "");
    say(b, "%s", "Read it all before starting. The commands below are printed, not run: each");
    say(b, "%s", "one destroys whatever is on the device it names, so check every device name");
    say(b, "against `%s` before running anything.",
        b->os == OS_FREEBSD ? "geom disk list" : "sysctl hw.disknames");
}

static void needs(struct bs *b)
{
    char        buf[32];
    char        buf2[32];
    char       *file;
    char       *url;
    const char *check;
    size_t      d;
    size_t      i;

    heading(b, "What you need");
    for (d = 0; d < b->ndisks; d++)
    {
        const struct bdisk *disk = &b->disks[d];
        uint64_t            need = 0;

        if (!disk->used)
        {
            continue;
        }
        for (i = 0; i < b->nparts; i++)
        {
            const struct bpart *p = &b->parts[i];

            if (p->disk != d || !rebuilt(b, p))
            {
                continue;
            }
            if (b->o->target == RS_TARGET_SAME)
            {
                need = p->start + p->size > need ? p->start + p->size : need;
            } else
            {
                need += fit(b, p);
            }
        }
        if (b->o->target != RS_TARGET_SAME)
        {
            need = round_up(need + 2 * MIB, GIB);
        }
        say(b, "  - Disk %u: at least %s (it was %s%s%s).", disk->var,
            size_text(need, buf, sizeof(buf)), disk->name ? disk->name : "?",
            disk->size ? ", " : "", disk->size ? size_text(disk->size, buf2, sizeof(buf2)) : "");
    }
    if (eq(b->firmware, "uefi"))
    {
        say(b, "%s", "  - Firmware set to boot UEFI, not legacy BIOS.");
    } else if (eq(b->firmware, "bios"))
    {
        say(b, "%s", "  - Firmware set to boot legacy BIOS (CSM), as the original did.");
    }
    installer(b, &file, &url, &check);
    if (file)
    {
        say(b, "  - The installer, %s, on a USB stick, from", file);
        say(b, "      %s", url);
        say(b, "    %s.", check);
    } else
    {
        say(b, "  - The installer for %s, on a USB stick.", os_names[b->os]);
    }
    free(file);
    free(url);
    rs_sheet_image_needs(b->o, b->out);
    say(b, "  - restate's %s package, from its release, to restore with.", os_names[b->os]);
}

/* What a partition was for, in the layout's table. */
static const char *use_of(const struct bpart *p)
{
    if (p->pool)
    {
        return "ZFS pool";
    }
    if (is_swap(p))
    {
        return p->mountpoint ? "swap" : "";
    }
    return p->mountpoint ? p->mountpoint : "";
}

static const char *table_name(const char *table)
{
    if (eq(table, "gpt"))
    {
        return "GPT";
    }
    if (eq(table, "dos"))
    {
        return "MBR";
    }
    return table ? table : "no partition table";
}

static void layout_table(struct bs *b)
{
    size_t d;
    size_t i;
    char   buf[32];

    heading(b, "The disk layout, as it was");
    for (d = 0; d < b->ndisks; d++)
    {
        const struct bdisk *disk = &b->disks[d];

        say(b, "%s%s %s  %s%s", d ? "\n" : "", disk->name ? disk->name : "?",
            size_text(disk->size, buf, sizeof(buf)), table_name(disk->table),
            disk->used ? "" : " -- nothing of the system's: left alone");
        for (i = 0; i < b->nparts; i++)
        {
            const struct bpart *p = &b->parts[i];
            char                what[64];

            if (p->disk != d)
            {
                continue;
            }
            (void)snprintf(what, sizeof(what), "%s%s",
                           p->type_name ? p->type_name : (p->type ? p->type : ""),
                           p->eli ? " (GELI)" : "");
            say(b, "  %-12s %9s  %-22s %s%s%s", p->name, size_text(p->size, buf, sizeof(buf)),
                what, use_of(p), p->label ? "  label " : "", p->label ? p->label : "");
        }
    }
    for (i = 0; i < b->nds; i++)
    {
        if (i == 0)
        {
            say(b, "%s", "");
            say(b, "%s", "ZFS datasets that were mounted:");
        }
        say(b, "  %-32s %s", b->ds[i].name, b->ds[i].mountpoint);
    }
}

static void shell(struct bs *b)
{
    size_t d;

    heading(b, "Boot the installer and open a root shell");
    if (b->o->target == RS_TARGET_VM)
    {
        say(b, "%s", "Start the virtual machine; it boots the installer.");
    } else
    {
        say(b, "%s", "Boot the new machine from the USB stick.");
    }
    if (b->os == OS_FREEBSD)
    {
        say(b, "%s", "At the installer's Welcome screen choose Shell. Then name the disks:");
        say(b, "%s", "");
        if (b->npools > 0)
        {
            say(b, "%s", "    kldload -n zfs");
        }
        if (any_eli(b))
        {
            say(b, "%s", "    kldload -n geom_eli");
        }
        say(b, "%s", "    geom disk list");
    } else if (b->os == OS_OPENBSD)
    {
        say(b, "%s", "At \"(I)nstall, (U)pgrade, (A)utoinstall or (S)hell?\" answer s. Then name");
        say(b, "%s", "the disks, and make their device nodes:");
        say(b, "%s", "");
        say(b, "%s", "    sysctl hw.disknames");
    } else
    {
        say(b, "%s", "In sysinst choose \"Utility menu\", then \"Run /bin/sh\". Then name the");
        say(b, "%s", "disks, and define a helper that finds a wedge by its name:");
        say(b, "%s", "");
        say(b, "%s", "    sysctl hw.disknames");
    }
    for (d = 0; d < b->ndisks; d++)
    {
        char *def;
        char  buf[32];

        if (!b->disks[d].used)
        {
            continue;
        }
        def = disk_default(b, &b->disks[d]);
        say(b, "    DISK%u=%-12s # was %s%s%s", b->disks[d].var, def,
            b->disks[d].name ? b->disks[d].name : "?", b->disks[d].size ? ": " : "",
            b->disks[d].size ? size_text(b->disks[d].size, buf, sizeof(buf)) : "");
        if (b->os == OS_OPENBSD)
        {
            say(b, "    (cd /dev && sh ./MAKEDEV \"$DISK%u\")", b->disks[d].var);
        }
        free(def);
    }
    if (b->os == OS_NETBSD)
    {
        say(b, "%s", "    wedge() { dkctl \"$1\" listwedges |");
        say(b, "%s", "        sed -n \"s/^\\(dk[0-9]*\\): $2, .*/\\1/p\"; }");
    }
    if (b->o->target == RS_TARGET_METAL)
    {
        say(b, "%s", "");
        say(b, "%s", "Set each DISK to the new machine's disk from that listing: the names on");
        say(b, "%s", "other hardware are not knowable in advance, and CHANGE-ME fails safely.");
    }
}

/* " -a 1m -s SIZE", in mebibytes, or in kibibytes for a size that is not a
 * whole number of them: a freebsd-boot partition, which pmbr loads whole,
 * stays the 512 KiB it was. */
static void size_arg(struct rs_buf *line, uint64_t bytes, const char *kib, const char *mib)
{
    if (bytes % MIB != 0)
    {
        rs_buf_addf(line, " -a 1m -s %" PRIu64 "%s", (bytes + 1023) / 1024, kib);
    } else
    {
        rs_buf_addf(line, " -a 1m -s %" PRIu64 "%s", bytes / MIB, mib);
    }
}

/* FreeBSD's gpart, a disk at a time. */
static void gpart(struct bs *b, size_t d)
{
    const struct bdisk *disk = &b->disks[d];
    size_t              i;
    bool                zfs_root = any_pool_root(b);

    say(b, "    gpart destroy -F \"$DISK%u\"    # says so, harmlessly, on a blank disk",
        disk->var);
    say(b, "    gpart create -s gpt \"$DISK%u\"", disk->var);
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];
        struct rs_buf       line;

        if (p->disk != d || !rebuilt(b, p))
        {
            continue;
        }
        rs_buf_init(&line);
        rs_buf_addstr(&line, "    gpart add -t ");
        if (p->type_name && !eq(p->type_name, "!"))
        {
            rs_shell_word(&line, p->type_name);
        } else
        {
            rs_buf_addf(&line, "'!%s'", p->type ? p->type : "");
        }
        if (b->o->target == RS_TARGET_SAME)
        {
            rs_buf_addf(&line, " -b %" PRIu64 " -s %" PRIu64, p->start / disk->sector,
                        p->size / disk->sector);
        } else
        {
            size_arg(&line, fit(b, p), "K", "M");
        }
        rs_buf_addf(&line, " -i %u", p->number);
        if (p->label)
        {
            rs_buf_addstr(&line, " -l ");
            rs_shell_word(&line, p->label);
        }
        rs_buf_addf(&line, " \"$DISK%u\"", disk->var);
        say(b, "%s", line.data);
        rs_buf_free(&line);
    }
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];

        if (p->disk == d && rebuilt(b, p) && is_boot(p))
        {
            say(b, "    gpart bootcode -b /boot/pmbr -p /boot/%s -i %u \"$DISK%u\"",
                zfs_root ? "gptzfsboot" : "gptboot", p->number, disk->var);
        }
    }
    say(b, "    gpart show -l \"$DISK%u\"", disk->var);
}

/* OpenBSD's: fdisk, then the disklabel from a template of the sizes. */
static void openbsd_label(struct bs *b, size_t d)
{
    const struct bdisk *disk = &b->disks[d];
    const struct bpart *esp = NULL;
    size_t              i;
    char                next = 'a';

    for (i = 0; i < b->nparts; i++)
    {
        if (b->parts[i].disk == d && is_esp(&b->parts[i]) && !esp)
        {
            esp = &b->parts[i];
        }
    }
    if (esp)
    {
        say(b, "    fdisk -gy -b %" PRIu64 " \"$DISK%u\"    # GPT, and an EFI system partition "
            "as it had (%s)", esp->size / 512, disk->var, esp->name);
    } else
    {
        say(b, "    fdisk -iy \"$DISK%u\"    # MBR: it had no EFI system partition", disk->var);
    }
    say(b, "    cat > \"/tmp/$DISK%u.layout\" <<'RESTATE_END'", disk->var);
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];

        if (p->disk != d || !p->mountpoint || is_esp(p))
        {
            continue;
        }
        say(b, "    %-24s %" PRIu64 "M", is_swap(p) ? "swap" : p->mountpoint,
            (fit(b, p) + MIB - 1) / MIB);
    }
    say(b, "%s", "    RESTATE_END");
    say(b, "    disklabel -w -A -T \"/tmp/$DISK%u.layout\" \"$DISK%u\"", disk->var, disk->var);
    say(b, "    disklabel \"$DISK%u\"", disk->var);
    say(b, "%s", "");
    say(b, "%s", "The listing should give them these letters (the installer's editor names");
    say(b, "%s", "them by letter below):");
    say(b, "%s", "");
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];

        if (p->disk != d || !p->mountpoint || is_esp(p))
        {
            continue;
        }
        next = next_letter(next, esp != NULL);
        say(b, "      %c  %-24s (was %s)", next, is_swap(p) ? "swap" : p->mountpoint, p->name);
        next++;
    }
}

/* NetBSD's gpt, with the wedges made from it. */
static void netbsd_gpt(struct bs *b, size_t d)
{
    const struct bdisk *disk = &b->disks[d];
    size_t              i;

    say(b, "    gpt destroy \"$DISK%u\"    # says so, harmlessly, on a blank disk", disk->var);
    say(b, "    gpt create \"$DISK%u\"", disk->var);
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];
        const char         *t = p->type;
        struct rs_buf       line;

        if (p->disk != d || !rebuilt(b, p))
        {
            continue;
        }
        if (is_esp(p))
        {
            t = "efi";
        } else if (eq(t, "raidframe"))
        {
            t = "raid";
        } else if (eq(t, "ext2fs"))
        {
            t = "linux-data";
        }
        rs_buf_init(&line);
        rs_buf_addf(&line, "    gpt add -i %u", p->number);
        if (b->o->target == RS_TARGET_SAME)
        {
            rs_buf_addf(&line, " -b %" PRIu64 " -s %" PRIu64, p->start / disk->sector,
                        p->size / disk->sector);
        } else
        {
            size_arg(&line, fit(b, p), "k", "m");
        }
        rs_buf_addstr(&line, " -t ");
        rs_shell_word(&line, t ? t : "ffs");
        rs_buf_addstr(&line, " -l ");
        rs_shell_word(&line, p->label ? p->label : "");
        rs_buf_addf(&line, " \"$DISK%u\"", disk->var);
        say(b, "%s", line.data);
        rs_buf_free(&line);
    }
    say(b, "    dkctl \"$DISK%u\" makewedges", disk->var);
    say(b, "    dkctl \"$DISK%u\" listwedges", disk->var);
}

static void partition(struct bs *b)
{
    size_t d;
    size_t i;

    heading(b, "Partition the disks");
    for (d = 0; d < b->ndisks; d++)
    {
        const struct bdisk *disk = &b->disks[d];

        if (!disk->used)
        {
            say(b, "    # %s: nothing of the system's on it -- left alone", disk->name);
            continue;
        }
        if (!disk->supported)
        {
            say(b, "    # $DISK%u (was %s): %s -- see the notes", disk->var, disk->name,
                eq(disk->table, "dos") ? "MBR slices" : "a disklabel");
            note(b, "$DISK%u (was %s) has %s, which this version writes no commands for: "
                 "partition it and make its filesystems by hand, at the sizes in \"The disk "
                 "layout, as it was\", and mount them under /mnt before the system is "
                 "installed; /etc/fstab needs their lines added.", disk->var, disk->name,
                 eq(disk->table, "dos") ? "MBR slices" : "a disklabel and no GPT");
            continue;
        }
        if (b->os == OS_FREEBSD)
        {
            gpart(b, d);
        } else if (b->os == OS_OPENBSD)
        {
            openbsd_label(b, d);
        } else
        {
            netbsd_gpt(b, d);
        }
        say(b, "%s", "");
    }
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];

        if (rebuilt(b, p) && p->made_label)
        {
            note(b, "%s had no GPT label, and the commands here find its wedge by one: it is "
                 "given %s, and /etc/fstab names it NAME=%s.", p->name, p->label, p->label);
        }
    }
}

/* FreeBSD's GELI, under everything but swap (which /etc/fstab's .eli makes
 * encrypt itself with a new key at each boot). */
static void geli(struct bs *b)
{
    size_t i;

    if (!any_eli(b))
    {
        return;
    }
    heading(b, "Encrypt");
    say(b, "%s", "Each asks for a passphrase, a new one: the old one's key was the old disk's.");
    say(b, "%s", "");
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];
        char               *dv;

        if (!rebuilt(b, p) || !p->eli || is_swap(p))
        {
            continue;
        }
        dv = dev(b, p);
        say(b, "    geli init -b -g -s 4096 -l 256 %s", dv);
        say(b, "    geli attach %s", dv);
        free(dv);
    }
    note(b, "The GELI providers are made with bsdinstall's settings (AES-XTS, 256-bit keys, "
         "4 KiB sectors, a passphrase, booted from); a key file the old ones had is not in "
         "this description, and has to be added again with geli setkey.");
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct dataset *)a)->name, ((const struct dataset *)b)->name);
}

static bool printed_has(char **printed, size_t n, const char *name)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        if (strcmp(printed[i], name) == 0)
        {
            return true;
        }
    }
    return false;
}

/* `name`, and the datasets above it that were not mounted, unless printed. */
static void zfs_create(struct bs *b, const char *name, char ***printed, size_t *n)
{
    const char *slash = strchr(name, '/');
    size_t      i;

    if (!slash || printed_has(*printed, *n, name))
    {
        return;
    }
    while (slash)
    {
        char *above = rs_xstrndup(name, (size_t)(slash - name));

        if (strchr(above, '/') && !printed_has(*printed, *n, above))
        {
            bool was_mounted = false;

            for (i = 0; i < b->nds; i++)
            {
                was_mounted = was_mounted || strcmp(b->ds[i].name, above) == 0;
            }
            if (!was_mounted)
            {
                say(b, "    zfs create -o mountpoint=none %s", above);
                *printed = rs_xreallocarray(*printed, *n + 1, sizeof(**printed));
                (*printed)[(*n)++] = rs_xstrdup(above);
            }
        }
        free(above);
        slash = strchr(slash + 1, '/');
    }
    for (i = 0; i < b->nds; i++)
    {
        if (strcmp(b->ds[i].name, name) == 0)
        {
            bool root = eq(b->ds[i].mountpoint, "/");

            say(b, "    zfs create%s -o mountpoint=%s %s", root ? " -o canmount=noauto" : "",
                b->ds[i].mountpoint, name);
            if (root)
            {
                say(b, "    zfs mount %s", name);
            }
        }
    }
    *printed = rs_xreallocarray(*printed, *n + 1, sizeof(**printed));
    (*printed)[(*n)++] = rs_xstrdup(name);
}

static void zfs_pools(struct bs *b)
{
    size_t  i;
    size_t  k;
    char  **printed = NULL;
    size_t  nprinted = 0;
    size_t  members = 0;

    qsort(b->ds, b->nds, sizeof(*b->ds), by_name);
    for (i = 0; i < b->nparts; i++)
    {
        members += b->parts[i].pool && rebuilt(b, &b->parts[i]);
    }
    for (k = 0; k < b->npools; k++)
    {
        const char   *pool = b->pools[k];
        const char   *top = NULL;
        const char   *bootfs = NULL;
        struct rs_buf vdevs;

        rs_buf_init(&vdevs);
        if (b->npools == 1 && members == 1)
        {
            for (i = 0; i < b->nparts; i++)
            {
                if (b->parts[i].pool && rebuilt(b, &b->parts[i]))
                {
                    char *dv = dev(b, &b->parts[i]);

                    rs_buf_addf(&vdevs, "%s%s", dv, b->parts[i].eli ? ".eli" : "");
                    free(dv);
                }
            }
        } else
        {
            rs_buf_addstr(&vdevs, "VDEVS");
            note(b, "The pool %s's layout -- which partitions, mirrored or raidz -- is not in "
                 "this description: VDEVS is it, as `zpool status %s` showed it on the old "
                 "machine, with the new partitions' names.", pool, pool);
        }
        for (i = 0; i < b->nds; i++)
        {
            if (strcmp(b->ds[i].name, pool) == 0)
            {
                top = b->ds[i].mountpoint;
            }
            if (eq(b->ds[i].mountpoint, "/") && rs_starts_with(b->ds[i].name, pool) &&
                b->ds[i].name[strlen(pool)] == '/')
            {
                bootfs = b->ds[i].name;
            }
        }
        say(b, "    zpool create -f -o altroot=/mnt -O compress=lz4 -O atime=off -m %s %s %s",
            top ? top : "none", pool, vdevs.data);
        rs_buf_free(&vdevs);
        if (bootfs)
        {
            zfs_create(b, bootfs, &printed, &nprinted);
        }
        for (i = 0; i < b->nds; i++)
        {
            if (rs_starts_with(b->ds[i].name, pool) && b->ds[i].name[strlen(pool)] == '/')
            {
                zfs_create(b, b->ds[i].name, &printed, &nprinted);
            }
        }
        if (bootfs)
        {
            say(b, "    zpool set bootfs=%s %s", bootfs, pool);
        }
        say(b, "    mkdir -p /mnt/boot/zfs && zpool set cachefile=/mnt/boot/zfs/zpool.cache %s",
            pool);
    }
    for (i = 0; i < nprinted; i++)
    {
        free(printed[i]);
    }
    free(printed);
    note(b, "Only the ZFS datasets that were mounted are in this description, and none of "
         "their properties: the pools are made with bsdinstall's defaults (lz4, atime off). "
         "Others, and other boot environments, are made by hand, as `zfs list` showed them.");
}

static void filesystems(struct bs *b)
{
    size_t i;

    if (b->os == OS_OPENBSD)
    {
        return;
    }
    heading(b, b->npools > 0 ? "Make the filesystems and pools" : "Make the filesystems");
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];
        char               *dv;
        struct rs_buf       c;

        if (!rebuilt(b, p) || is_swap(p) || p->pool || is_boot(p))
        {
            continue;
        }
        dv = b->os == OS_NETBSD ? raw_dev(b, p) : dev(b, p);
        rs_buf_init(&c);
        if (is_esp(p))
        {
            rs_buf_addstr(&c, "newfs_msdos -F 32");
            if (b->os == OS_FREEBSD)
            {
                rs_buf_addstr(&c, " -c 1");
            }
            if (p->fslabel)
            {
                rs_buf_addstr(&c, " -L ");
                rs_shell_word(&c, p->fslabel);
            }
        } else if (eq(p->fs, "ufs") || eq(p->fs, "ffs"))
        {
            rs_buf_addstr(&c, b->os == OS_FREEBSD ? "newfs -U" : "newfs -O 2");
            if (b->os == OS_FREEBSD && p->fslabel)
            {
                rs_buf_addstr(&c, " -L ");
                rs_shell_word(&c, p->fslabel);
            }
        } else
        {
            note(b, "%s holds %s, which this sheet does not know how to make: make it by hand.",
                 p->name, p->fs ? p->fs : (p->type_name ? p->type_name : "a filesystem"));
        }
        if (c.len)
        {
            say(b, "    %s %s%s", c.data, dv, p->eli ? ".eli" : "");
        }
        rs_buf_free(&c);
        free(dv);
    }
    if (b->npools > 0)
    {
        zfs_pools(b);
    }
}

static int by_mountpoint(const void *a, const void *b)
{
    const struct bpart *const *x = a;
    const struct bpart *const *y = b;

    return strcmp((*x)->mountpoint, (*y)->mountpoint);
}

/* The partitions with a filesystem mounted, parents first. */
static const struct bpart **mounted(const struct bs *b, size_t *n)
{
    const struct bpart **list = rs_xcalloc(b->nparts + 1, sizeof(*list));
    size_t               i;

    *n = 0;
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];

        if (rebuilt(b, p) && p->mountpoint && p->mountpoint[0] == '/' && !is_swap(p) &&
            known_fs(p))
        {
            list[(*n)++] = p;
        }
    }
    qsort(list, *n, sizeof(*list), by_mountpoint);
    return list;
}

static const struct bpart *esp_of(const struct bs *b)
{
    size_t i;

    for (i = 0; i < b->nparts; i++)
    {
        if (rebuilt(b, &b->parts[i]) && is_esp(&b->parts[i]))
        {
            return &b->parts[i];
        }
    }
    return NULL;
}

/* The /etc/fstab the new system boots with, until the restore puts back the
 * old one -- or, rebuilt elsewhere, stays. */
static void fstab(struct bs *b)
{
    size_t i;

    say(b, "%s", "    cat > /mnt/etc/fstab <<RESTATE_END");
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];
        const char         *opts = rs_jobject_str(p->fstab, "options");
        const char         *freq = rs_jobject_str(p->fstab, "freq");
        const char         *pass = rs_jobject_str(p->fstab, "passno");
        const char         *type;
        char               *spec;

        if (!rebuilt(b, p) || !p->mountpoint || p->pool || !known_fs(p))
        {
            continue;
        }
        if (b->os == OS_NETBSD)
        {
            spec = rs_xasprintf("NAME=%s", p->label ? p->label : "");
        } else
        {
            char *dv = dev(b, p);

            spec = rs_xasprintf("%s%s", dv, p->eli ? ".eli" : "");
            free(dv);
        }
        type = is_swap(p) ? "swap" : is_esp(p) ? (b->os == OS_NETBSD ? "msdos" : "msdosfs")
                                   : (b->os == OS_NETBSD ? "ffs" : "ufs");
        say(b, "    %-24s %-12s %-8s %-8s %s %s", spec, is_swap(p) ? "none" : p->mountpoint,
            type, opts ? opts : (is_swap(p) ? "sw" : "rw"),
            freq ? freq : (is_swap(p) || is_esp(p) ? "0" : "1"),
            pass ? pass : (is_swap(p) ? "0" : eq(p->mountpoint, "/") ? "1" : "2"));
        free(spec);
    }
    say(b, "%s", "    RESTATE_END");
}

static void freebsd_install(struct bs *b)
{
    const struct bpart  *esp = esp_of(b);
    const char          *arch = rs_jobject_str(b->sys, "architecture");
    const char          *host = rs_jobject_str(b->sys, "hostname");
    const struct bpart **list;
    size_t               n;
    size_t               i;
    bool                 esp_mounted = false;

    heading(b, "Install the base system");
    say(b, "%s", "Mount the new filesystems under /mnt, then unpack the memstick's distribution");
    say(b, "sets into them%s:", b->npools > 0 ? " (the pool's datasets are mounted there already)"
                                              : "");
    say(b, "%s", "");
    list = mounted(b, &n);
    for (i = 0; i < n; i++)
    {
        char *dv = dev(b, list[i]);

        if (strcmp(list[i]->mountpoint, "/") != 0)
        {
            say(b, "    mkdir -p /mnt%s", list[i]->mountpoint);
        }
        say(b, "    mount%s %s%s /mnt%s", is_esp(list[i]) ? " -t msdosfs" : "", dv,
            list[i]->eli ? ".eli" : "", strcmp(list[i]->mountpoint, "/") == 0
                                            ? ""
                                            : list[i]->mountpoint);
        esp_mounted = esp_mounted || list[i] == esp;
        free(dv);
    }
    free(list);
    say(b, "    for set in base kernel%s; do tar -xpf /usr/freebsd-dist/$set.txz -C /mnt; done",
        eq(arch, "amd64") ? " lib32" : "");
    if (esp)
    {
        const char *where = esp_mounted ? esp->mountpoint : "/tmp/esp";
        const char *file = eq(arch, "arm64") ? "BOOTAA64.efi" : eq(arch, "i386") ? "BOOTIA32.efi"
                                                                                 : "BOOTX64.efi";
        char       *dv = dev(b, esp);
        const char *root = esp_mounted ? "/mnt" : "";

        say(b, "%s", "");
        say(b, "%s", "The EFI loader, onto the EFI system partition:");
        say(b, "%s", "");
        if (!esp_mounted)
        {
            say(b, "    mkdir -p /tmp/esp && mount -t msdosfs %s /tmp/esp", dv);
        }
        say(b, "    mkdir -p %s%s/EFI/BOOT %s%s/EFI/freebsd", root, where, root, where);
        say(b, "    cp /mnt/boot/loader.efi %s%s/EFI/BOOT/%s", root, where, file);
        say(b, "    cp /mnt/boot/loader.efi %s%s/EFI/freebsd/loader.efi", root, where);
        if (b->o->target != RS_TARGET_VM)
        {
            say(b, "    efibootmgr -a -c -l %s%s/EFI/freebsd/loader.efi -L FreeBSD    # booted "
                "by UEFI only", root, where);
        }
        if (!esp_mounted)
        {
            say(b, "%s", "    umount /tmp/esp");
        }
        free(dv);
    }
    say(b, "%s", "");
    say(b, "%s", "Then enough of /etc to boot it and reach the network; the restore puts the");
    say(b, "%s", "rest back over it:");
    say(b, "%s", "");
    fstab(b);
    {
        struct rs_buf line;

        rs_buf_init(&line);
        rs_buf_addstr(&line, "    sysrc -f /mnt/etc/rc.conf");
        if (host)
        {
            rs_buf_addstr(&line, " hostname=");
            rs_shell_word(&line, host);
        }
        rs_buf_addstr(&line, " ifconfig_DEFAULT=SYNCDHCP sshd_enable=YES");
        if (b->npools > 0)
        {
            rs_buf_addstr(&line, " zfs_enable=YES");
        }
        say(b, "%s", line.data);
        rs_buf_free(&line);
    }
    if (b->npools > 0 || any_eli(b))
    {
        say(b, "    sysrc -f /mnt/boot/loader.conf%s%s", b->npools > 0 ? " zfs_load=YES" : "",
            any_eli(b) ? " geom_eli_load=YES" : "");
    }
    say(b, "%s", "    chroot /mnt passwd root    # until the restore brings back the old one");
}

static void openbsd_install(struct bs *b)
{
    const char *host = rs_jobject_str(b->sys, "hostname");
    size_t      d;
    size_t      i;

    heading(b, "Install onto that layout");
    say(b, "%s", "Go back to the installer -- `exit`, then answer i -- and answer its questions");
    say(b, "%s", "as for any install, with these:");
    say(b, "%s", "");
    say(b, "  - System hostname: %s.", host ? host : "the old one");
    say(b, "%s", "  - \"Which disk is the root disk?\": $DISK1's name.");
    say(b, "%s", "  - \"Use (W)hole disk MBR, whole disk (G)PT, (O)penBSD area or (E)dit?\": o,");
    say(b, "%s", "    which keeps the partition table just written.");
    say(b, "%s", "  - \"Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout?\": c.");
    say(b, "%s", "    The editor opens on the label just written; give each partition its mount");
    say(b, "%s", "    point, then write it and quit:");
    say(b, "%s", "");
    for (d = 0; d < b->ndisks; d++)
    {
        char next = 'a';
        bool esp = false;

        if (!b->disks[d].used)
        {
            continue;
        }
        for (i = 0; i < b->nparts; i++)
        {
            esp = esp || (b->parts[i].disk == d && is_esp(&b->parts[i]));
        }
        if (b->disks[d].var > 1)
        {
            say(b, "%s", "");
            say(b, "    then, at \"Which disk do you wish to initialize?\", $DISK%u, and the same:",
                b->disks[d].var);
        }
        for (i = 0; i < b->nparts; i++)
        {
            const struct bpart *p = &b->parts[i];

            if (p->disk != d || !p->mountpoint || is_esp(p))
            {
                continue;
            }
            next = next_letter(next, esp);
            if (!is_swap(p))
            {
                say(b, "        n %c       mount point: %s", next, p->mountpoint);
            }
            next++;
        }
        say(b, "%s", "        w");
        say(b, "%s", "        q");
    }
    say(b, "%s", "");
    say(b, "%s", "    It makes the filesystems, unpacks the sets and installs the boot code.");
    say(b, "%s", "  - The sets: the ones it offers. A user, if asked: the restore brings back the");
    say(b, "%s", "    real accounts.");
    say(b, "%s", "");
    say(b, "%s", "When it is done, reboot into the new system.");
}

static void netbsd_install(struct bs *b)
{
    const struct bpart  *esp = esp_of(b);
    const char          *arch = rs_jobject_str(b->sys, "architecture");
    const char          *host = rs_jobject_str(b->sys, "hostname");
    const struct bpart **list;
    const struct bpart  *root = NULL;
    size_t               n;
    size_t               i;

    heading(b, "Install the base system");
    say(b, "%s", "Mount the new filesystems under /mnt, then unpack the sets into them:");
    say(b, "%s", "");
    list = mounted(b, &n);
    for (i = 0; i < n; i++)
    {
        char *dv;

        if (is_esp(list[i]))
        {
            continue;
        }
        dv = dev(b, list[i]);
        if (strcmp(list[i]->mountpoint, "/") == 0)
        {
            root = list[i];
        } else
        {
            say(b, "    mkdir -p /mnt%s", list[i]->mountpoint);
        }
        say(b, "    mount %s /mnt%s", dv,
            strcmp(list[i]->mountpoint, "/") == 0 ? "" : list[i]->mountpoint);
        free(dv);
    }
    free(list);
    say(b, "    SETS=/%s/binary/sets    # where the install image keeps them: check with ls",
        arch ? arch : "amd64");
    say(b, "%s", "    for s in base etc comp man misc modules rescue text kern-GENERIC; do");
    say(b, "%s", "        f=$(ls \"$SETS/$s\".t*) && case $f in");
    say(b, "%s", "        *.xz) tar -xJpf \"$f\" -C /mnt ;; *) tar -xzpf \"$f\" -C /mnt ;; esac");
    say(b, "%s", "    done");
    say(b, "%s", "    (cd /mnt/dev && sh ./MAKEDEV all)");
    say(b, "%s", "");
    say(b, "%s", "The boot code:");
    say(b, "%s", "");
    if (esp)
    {
        char *dv = dev(b, esp);

        say(b, "    mkdir -p /tmp/esp && mount -t msdos %s /tmp/esp", dv);
        say(b, "%s", "    mkdir -p /tmp/esp/EFI/boot && cp /mnt/usr/mdec/*.efi /tmp/esp/EFI/boot/");
        say(b, "%s", "    umount /tmp/esp");
        free(dv);
    }
    if (root && !eq(b->firmware, "uefi"))
    {
        char *rv = raw_dev(b, root);

        say(b, "    gpt biosboot -L %s \"$DISK%u\"", root->label ? root->label : "?",
            b->disks[root->disk].var);
        say(b, "    installboot -v %s /mnt/usr/mdec/bootxx_ffsv2", rv);
        say(b, "%s", "    cp /mnt/usr/mdec/boot /mnt/boot");
        free(rv);
    }
    say(b, "%s", "");
    say(b, "%s", "Then enough of /etc to boot it and reach the network; the restore puts the");
    say(b, "%s", "rest back over it:");
    say(b, "%s", "");
    fstab(b);
    say(b, "    printf '%%s\\n' rc_configured=YES hostname=%s dhcpcd=YES sshd=YES >> "
        "/mnt/etc/rc.conf", host ? host : "CHANGE-ME");
    say(b, "%s", "    chroot /mnt passwd root    # until the restore brings back the old one");
}

static void first_boot(struct bs *b)
{
    const char *v = b->o->version ? b->o->version : "VERSION";

    if (b->os != OS_OPENBSD)
    {
        say(b, "%s", "");
        say(b, "%s", "Take the USB stick out and reboot into the new system:");
        say(b, "%s", "");
        say(b, "%s", "    reboot");
    }
    heading(b, "Put restate on the new system");
    say(b, "%s", "As root on the new system, from restate's release package for it, copied");
    say(b, "%s", "there with the image:");
    say(b, "%s", "");
    if (b->os == OS_FREEBSD)
    {
        say(b, "%s", "    env ASSUME_ALWAYS_YES=yes pkg bootstrap");
        say(b, "    pkg add ./restate-%s-freebsd-*.pkg", v);
    } else if (b->os == OS_OPENBSD)
    {
        /* pkg_add refuses a file not named as the package is. */
        say(b, "    cp ./restate-%s-openbsd-*.tgz ./restate-%s.tgz", v, v);
        say(b, "    pkg_add -D unsigned ./restate-%s.tgz", v);
    } else
    {
        say(b, "    pkg_add ./restate-%s-netbsd-*.tgz", v);
    }
}

/* On other hardware, the network interfaces it had, which /etc names. */
static void interfaces(struct bs *b)
{
    const struct rs_jval *net = rs_jobject_get(rs_jobject_get(b->machine, "hardware"),
                                               "network");
    struct rs_buf         was;
    size_t                i;

    if (b->o->target == RS_TARGET_SAME)
    {
        return;
    }
    rs_buf_init(&was);
    for (i = 0; net && net->type == RS_JARRAY && i < net->n; i++)
    {
        const char *name = rs_jobject_str(&net->items[i], "name");
        const char *mac = rs_jobject_str(&net->items[i], "mac");

        rs_buf_addf(&was, "%s%s (%s)", was.len ? ", " : "", name ? name : "?",
                    mac ? mac : "no MAC recorded");
    }
    note(b, "The network interfaces are new: what the restore puts back names the old ones (%s), "
         "and needs them renamed to what `ifconfig -l` lists here.%s%s",
         b->os == OS_OPENBSD ? "/etc/hostname.NAME" : "ifconfig_NAME in /etc/rc.conf",
         was.len ? " They were: " : "", was.len ? was.data : "");
    rs_buf_free(&was);
}

bool rs_bsdsheet_build(const struct rs_jval *machine, const struct rs_sheet_opts *o,
                       struct rs_buf *out, unsigned *step, struct rs_buf *notes,
                       struct rs_buf *err)
{
    struct bs b;
    size_t    i;
    bool      any = false;

    memset(&b, 0, sizeof(b));
    b.machine = machine;
    b.sys = rs_jobject_get(machine, "system");
    b.o = o;
    b.os = os_of(machine);
    b.out = out;
    b.notes = notes;
    b.step = step;
    if (o->firmware)
    {
        rs_buf_addf(err, "--firmware is for Linux's build sheets in this version; %s's is "
                    "rebuilt to boot as it did", os_names[b.os]);
        return false;
    }
    collect(&b);
    for (i = 0; i < b.ndisks; i++)
    {
        any = any || b.disks[i].used;
    }
    if (!any)
    {
        rs_buf_addf(err, "the machine description has no disk with %s's filesystems on it to "
                    "rebuild", os_names[b.os]);
    } else
    {
        intro(&b);
        needs(&b);
        layout_table(&b);
        shell(&b);
        partition(&b);
        if (b.os == OS_FREEBSD)
        {
            geli(&b);
        }
        filesystems(&b);
        if (b.os == OS_FREEBSD)
        {
            freebsd_install(&b);
        } else if (b.os == OS_OPENBSD)
        {
            openbsd_install(&b);
        } else
        {
            netbsd_install(&b);
        }
        first_boot(&b);
        interfaces(&b);
    }
    for (i = 0; i < b.npools; i++)
    {
        free(b.pools[i]);
    }
    for (i = 0; i < b.nparts; i++)
    {
        free(b.parts[i].made_label);
    }
    free(b.pools);
    free(b.ds);
    free(b.parts);
    free(b.disks);
    return any;
}

bool rs_bsdsheet_keeps_fstab(const struct rs_jval *machine, const struct rs_sheet_opts *o)
{
    return os_of(machine) == OS_OPENBSD || o->target != RS_TARGET_SAME;
}

/* ------------------------------------------------------------------------- */
/* Unattended                                                                */
/* ------------------------------------------------------------------------- */

static void line(struct rs_buf *out, const char *text)
{
    rs_buf_addstr(out, text);
    rs_buf_add(out, "\n", 1);
}

/* A size as bsdinstall's PARTITIONS takes it: 512K, 260M. */
static void size_word(struct rs_buf *b, uint64_t bytes)
{
    if (bytes % MIB != 0)
    {
        rs_buf_addf(b, "%" PRIu64 "K", (bytes + 1023) / 1024);
    } else
    {
        rs_buf_addf(b, "%" PRIu64 "M", bytes / MIB);
    }
}

static void auto_header(struct bs *b, const char *what)
{
    const char        *host = rs_jobject_str(b->sys, "hostname");
    static const char *const targets[] = {
        "this machine, or one like it",
        "a virtual machine, each volume sized to what it uses",
        "other hardware, at the original sizes"
    };

    rs_buf_addf(b->out, "# restate autoinstall: %s -- %s, rebuilt as %s.\n",
                host ? host : "(no host name)", what, targets[b->o->target]);
    rs_buf_addf(b->out, "# Made by restate %s from %s.\n", b->o->version ? b->o->version : "",
                b->o->image ? b->o->image : "the running system");
    line(b->out, "#");
    line(b->out, "# Before using it, replace every CHANGE-ME below. It ERASES the disks it names:");
    line(b->out, "# try it in a VM first (restate autoinstall --target vm). It installs the");
    line(b->out, "# system and stops; then follow `restate buildsheet` from \"Put restate on the");
    line(b->out, "# new system\": the packages, and the restore, which keeps this install's");
    line(b->out, "# /etc/fstab.");
}

/* ZFS as bsdinstall's zfsboot makes it: one pool, its root dataset at
 * POOL/BEROOT/BOOTFS. NULL where that is not what was there. */
static const char *zfs_bootfs(const struct bs *b, struct rs_buf *why)
{
    size_t i;

    if (b->npools != 1)
    {
        rs_buf_addf(why, "there are %zu ZFS pools, and bsdinstall makes one", b->npools);
        return NULL;
    }
    for (i = 0; i < b->nds; i++)
    {
        const char *name = b->ds[i].name;
        const char *a = strchr(name, '/');
        const char *c = a ? strchr(a + 1, '/') : NULL;

        if (eq(b->ds[i].mountpoint, "/") && a && c && !strchr(c + 1, '/') && c > a + 1 &&
            c[1] != '\0')
        {
            return name;
        }
    }
    rs_buf_addstr(why, "the pool's root is not a boot environment, POOL/ROOT/NAME, as "
                       "bsdinstall makes one");
    return NULL;
}

static void freebsd_zfs_auto(struct bs *b, const char *bootfs)
{
    const char   *pool = b->pools[0];
    const char   *be = strchr(bootfs, '/') + 1;
    const char   *bootname = strchr(be, '/') + 1;
    struct rs_buf disks;
    size_t        i;
    size_t        members = 0;
    uint64_t      swap = 0;
    bool          swap_eli = false;
    bool          pool_eli = false;
    bool          efi = false;
    bool          bios = false;

    rs_buf_init(&disks);
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];

        if (!rebuilt(b, p))
        {
            continue;
        }
        if (p->pool)
        {
            char *def = disk_default(b, &b->disks[p->disk]);

            rs_buf_addf(&disks, "%s%s", disks.len ? " " : "", def);
            free(def);
            members++;
            pool_eli = pool_eli || p->eli;
        } else if (is_swap(p) && swap == 0)
        {
            swap = fit(b, p);
            swap_eli = p->eli;
        }
        efi = efi || is_esp(p);
        bios = bios || is_boot(p);
    }
    line(b->out, "#");
    rs_buf_addf(b->out, "# The pool, %s, and its datasets, as bsdinstall's zfsboot makes "
                "them; only\n# the datasets that were mounted are known, and none of their "
                "properties.\n", pool);
    if (pool_eli)
    {
        line(b->out, "# The pool was GELI-encrypted. Nobody is there to give a passphrase, so");
        line(b->out, "# this one is not: the build sheet makes it encrypted.");
    }
    rs_buf_addf(b->out, "export ZFSBOOT_DISKS=\"%s\"\n", disks.data);
    rs_buf_free(&disks);
    rs_buf_addf(b->out, "export ZFSBOOT_VDEV_TYPE=%s\n",
                members == 1 ? "stripe"
                             : "CHANGE-ME    # mirror, raid10 or raidz1-3, as zpool status said");
    rs_buf_addf(b->out, "export ZFSBOOT_POOL_NAME=%s\n", pool);
    rs_buf_addf(b->out, "export ZFSBOOT_BEROOT_NAME=%.*s\n", (int)(bootname - be - 1), be);
    rs_buf_addf(b->out, "export ZFSBOOT_BOOTFS_NAME=%s\n", bootname);
    rs_buf_addf(b->out, "export ZFSBOOT_PARTITION_SCHEME=GPT\n");
    rs_buf_addf(b->out, "export ZFSBOOT_BOOT_TYPE=%s\n",
                efi && bios ? "BIOS+UEFI" : efi ? "UEFI" : "BIOS");
    if (swap > 0)
    {
        rs_buf_addf(b->out, "export ZFSBOOT_SWAP_SIZE=%" PRIu64 "m\n", (swap + MIB - 1) / MIB);
        rs_buf_addf(b->out, "export ZFSBOOT_SWAP_ENCRYPTION=%s\n", swap_eli ? "YES" : "");
    } else
    {
        line(b->out, "export ZFSBOOT_SWAP_SIZE=0");
    }
    line(b->out, "export ZFSBOOT_DATASETS=\"");
    {
        char  **printed = NULL;
        size_t  n = 0;
        size_t  k;
        size_t  plen = strlen(pool);

        qsort(b->ds, b->nds, sizeof(*b->ds), by_name);
        for (i = 0; i < b->nds; i++)
        {
            const char *name = b->ds[i].name;
            const char *slash;

            if (strncmp(name, pool, plen) != 0 || name[plen] != '/')
            {
                continue;
            }
            /* Those above it that were not mounted, first. */
            for (slash = strchr(name + plen + 1, '/'); slash; slash = strchr(slash + 1, '/'))
            {
                char *above = rs_xstrndup(name, (size_t)(slash - name));
                bool  was_mounted = false;

                for (k = 0; k < b->nds; k++)
                {
                    was_mounted = was_mounted || strcmp(b->ds[k].name, above) == 0;
                }
                if (!was_mounted && !printed_has(printed, n, above))
                {
                    rs_buf_addf(b->out, "\t%-32s mountpoint=none\n", above + plen);
                    printed = rs_xreallocarray(printed, n + 1, sizeof(*printed));
                    printed[n++] = rs_xstrdup(above);
                }
                free(above);
            }
            rs_buf_addf(b->out, "\t%-32s mountpoint=%s\n", name + plen, b->ds[i].mountpoint);
        }
        for (k = 0; k < n; k++)
        {
            free(printed[k]);
        }
        free(printed);
    }
    line(b->out, "\"");
}

static bool freebsd_ufs_auto(struct bs *b, struct rs_buf *err)
{
    struct rs_buf parts;
    size_t        d;
    size_t        i;

    rs_buf_init(&parts);
    for (d = 0; d < b->ndisks; d++)
    {
        char *def;

        if (!b->disks[d].used || !b->disks[d].supported)
        {
            continue;
        }
        def = disk_default(b, &b->disks[d]);
        rs_buf_addf(&parts, "%s%s gpt {", parts.len ? " " : "", def);
        free(def);
        for (i = 0; i < b->nparts; i++)
        {
            const struct bpart *p = &b->parts[i];
            bool                first = parts.data[parts.len - 1] == '{';

            if (p->disk != d || !rebuilt(b, p))
            {
                continue;
            }
            if (!is_esp(p) && !is_boot(p) && !is_swap(p) && !known_fs(p))
            {
                rs_buf_addf(err, "%s holds %s, which bsdinstall does not make", p->name,
                            p->fs ? p->fs : (p->type_name ? p->type_name : "something"));
                rs_buf_free(&parts);
                return false;
            }
            rs_buf_addstr(&parts, first ? " " : ", ");
            size_word(&parts, fit(b, p));
            rs_buf_addf(&parts, " %s",
                        is_esp(p) ? "efi" : is_boot(p) ? "freebsd-boot"
                                          : is_swap(p) ? "freebsd-swap" : "freebsd-ufs");
            if (p->mountpoint && p->mountpoint[0] == '/' && !is_esp(p))
            {
                rs_buf_addf(&parts, " %s", p->mountpoint);
            }
        }
        rs_buf_addstr(&parts, " }");
    }
    line(b->out, "#");
    line(b->out, "# The partitions, at their sizes; bsdinstall gives them no labels.");
    rs_buf_addf(b->out, "PARTITIONS=\"%s\"\n", parts.data);
    rs_buf_free(&parts);
    return true;
}

static bool freebsd_auto(struct bs *b, struct rs_buf *err)
{
    const char    *host = rs_jobject_str(b->sys, "hostname");
    const char    *zone = rs_jobject_str(b->sys, "timezone");
    const char    *keymap = rs_jobject_str(b->sys, "keymap");
    const char    *arch = rs_jobject_str(b->sys, "architecture");
    const char    *bootfs = NULL;
    struct rs_buf  why;
    struct rs_buf  body;
    struct rs_buf *real = b->out;
    struct rs_buf  cmd;
    size_t         i;

    rs_buf_init(&why);
    if (b->npools > 0)
    {
        bootfs = zfs_bootfs(b, &why);
    }
    if (b->npools > 0 && !bootfs)
    {
        rs_buf_addf(err, "%s: write the build sheet instead (restate buildsheet)", why.data);
        rs_buf_free(&why);
        return false;
    }
    rs_buf_free(&why);
    for (i = 0; i < b->ndisks; i++)
    {
        if (b->disks[i].used && !b->disks[i].supported)
        {
            rs_buf_addf(err, "%s has MBR slices, which this version writes nothing for: write "
                        "the build sheet instead (restate buildsheet)", b->disks[i].name);
            return false;
        }
    }
    rs_buf_init(&body);
    b->out = &body;
    if (bootfs)
    {
        freebsd_zfs_auto(b, bootfs);
    } else if (!freebsd_ufs_auto(b, err))
    {
        rs_buf_free(&body);
        b->out = real;
        return false;
    }
    b->out = real;
    auto_header(b, "a bsdinstall script");
    line(b->out, "#");
    line(b->out, "# To use it: put it at /etc/installerconfig on the installer's media, which");
    line(b->out, "# then installs without asking; or, from the installer's shell, run");
    line(b->out, "# `bsdinstall script FILE`.");
    rs_buf_addstr(b->out, body.data);
    rs_buf_free(&body);
    rs_buf_addf(b->out, "DISTRIBUTIONS=\"kernel.txz base.txz%s\"\n",
                eq(arch, "amd64") ? " lib32.txz" : "");
    line(b->out, "");
    line(b->out, "#!/bin/sh");
    line(b->out, "# After the install, in the new system.");
    rs_buf_init(&cmd);
    if (host)
    {
        rs_buf_addstr(&cmd, "sysrc hostname=");
        rs_shell_word(&cmd, host);
        line(b->out, cmd.data);
        rs_buf_reset(&cmd);
    }
    line(b->out, "sysrc ifconfig_DEFAULT=SYNCDHCP sshd_enable=YES");
    if (keymap)
    {
        rs_buf_addstr(&cmd, "sysrc keymap=");
        rs_shell_word(&cmd, keymap);
        line(b->out, cmd.data);
        rs_buf_reset(&cmd);
    }
    if (zone)
    {
        rs_buf_addstr(&cmd, "tzsetup ");
        rs_shell_word(&cmd, zone);
        line(b->out, cmd.data);
    }
    rs_buf_free(&cmd);
    line(b->out, "echo 'CHANGE-ME' | pw usermod root -h 0    # until the restore puts back the "
                 "old one");
    return true;
}

static bool openbsd_auto(struct bs *b, struct rs_buf *err)
{
    const char         *host = rs_jobject_str(b->sys, "hostname");
    const char         *zone = rs_jobject_str(b->sys, "timezone");
    const struct bdisk *root = NULL;
    const struct bpart *esp = NULL;
    char               *def;
    size_t              i;
    size_t              others = 0;

    for (i = 0; i < b->nparts; i++)
    {
        if (rebuilt(b, &b->parts[i]) && eq(b->parts[i].mountpoint, "/"))
        {
            root = &b->disks[b->parts[i].disk];
        }
    }
    if (!root)
    {
        rs_buf_addstr(err, "no disk holds / in this description, and autoinstall(8) has to be "
                           "told the root disk");
        return false;
    }
    for (i = 0; i < b->nparts; i++)
    {
        if (&b->disks[b->parts[i].disk] == root && is_esp(&b->parts[i]))
        {
            esp = &b->parts[i];
        }
    }
    for (i = 0; i < b->ndisks; i++)
    {
        others += b->disks[i].used && &b->disks[i] != root;
    }
    auto_header(b, "an install.conf");
    line(b->out, "#");
    line(b->out, "# To use it: serve it over HTTP and, at the installer's first question, answer");
    line(b->out, "# a and give its URL -- or serve it as install.conf from the server DHCP");
    line(b->out, "# names. The disklabel template it fetches is below: serve those lines,");
    line(b->out, "# without the \"# \", at the URL the template's answer gives.");
    if (others > 0)
    {
        rs_buf_addf(b->out, "# The installer partitions the root disk only: the other%s, as the\n"
                    "# build sheet says.\n", others == 1 ? "" : "s");
    }
    line(b->out, "#");
    rs_buf_addf(b->out, "# ---- %s.disklabel ----\n", host ? host : "the");
    for (i = 0; i < b->nparts; i++)
    {
        const struct bpart *p = &b->parts[i];

        if (&b->disks[p->disk] != root || !p->mountpoint || is_esp(p) || !rebuilt(b, p))
        {
            continue;
        }
        rs_buf_addf(b->out, "# %-24s %" PRIu64 "M\n", is_swap(p) ? "swap" : p->mountpoint,
                    (fit(b, p) + MIB - 1) / MIB);
    }
    line(b->out, "# ----");
    line(b->out, "");
    rs_buf_addf(b->out, "System hostname = %s\n", host ? host : "CHANGE-ME");
    line(b->out, "Password for root account = CHANGE-ME");
    line(b->out, "Start sshd(8) by default = yes");
    line(b->out, "Setup a user = no");
    if (zone)
    {
        rs_buf_addf(b->out, "What timezone are you in = %s\n", zone);
    }
    def = disk_default(b, root);
    rs_buf_addf(b->out, "Which disk is the root disk = %s\n", def);
    free(def);
    rs_buf_addf(b->out, "Use (W)hole disk MBR, whole disk (G)PT, (O)penBSD area or (E)dit = %s\n",
                esp ? "G" : "W");
    line(b->out, "Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a");
    rs_buf_addf(b->out, "URL to autopartitioning template for disklabel = "
                "http://CHANGE-ME/%s.disklabel\n", host ? host : "the");
    line(b->out, "Location of sets = http");
    line(b->out, "HTTP Server = cdn.openbsd.org");
    return true;
}

bool rs_bsdsheet_autoinstall(const struct rs_jval *machine, const struct rs_auto_opts *ao,
                             struct rs_buf *out, struct rs_buf *err)
{
    struct bs            b;
    struct rs_sheet_opts so;
    struct rs_buf        notes;
    size_t               i;
    bool                 any = false;
    bool                 ok = false;

    memset(&b, 0, sizeof(b));
    memset(&so, 0, sizeof(so));
    so.target = ao->target;
    so.image = ao->image;
    so.version = ao->version;
    b.machine = machine;
    b.sys = rs_jobject_get(machine, "system");
    b.o = &so;
    b.os = os_of(machine);
    b.out = out;
    b.notes = &notes;
    if (b.os == OS_NETBSD)
    {
        rs_buf_addstr(err, "NetBSD's installer, sysinst, reads no answers: write the build sheet "
                           "instead (restate buildsheet)");
        return false;
    }
    if (ao->clones || ao->firmware || ao->image_at)
    {
        rs_buf_addf(err, "%s is for Ubuntu's autoinstall files; %s's installs the system, and "
                    "the restore follows by hand", ao->clones ? "--clones"
                                                    : ao->firmware ? "--firmware" : "--image-at",
                    os_names[b.os]);
        return false;
    }
    rs_buf_init(&notes);
    collect(&b);
    for (i = 0; i < b.ndisks; i++)
    {
        any = any || b.disks[i].used;
    }
    if (!any)
    {
        rs_buf_addf(err, "the machine description has no disk with %s's filesystems on it to "
                    "rebuild", os_names[b.os]);
    } else
    {
        ok = b.os == OS_FREEBSD ? freebsd_auto(&b, err) : openbsd_auto(&b, err);
    }
    rs_buf_free(&notes);
    for (i = 0; i < b.npools; i++)
    {
        free(b.pools[i]);
    }
    for (i = 0; i < b.nparts; i++)
    {
        free(b.parts[i].made_label);
    }
    free(b.pools);
    free(b.ds);
    free(b.parts);
    free(b.disks);
    return ok;
}
