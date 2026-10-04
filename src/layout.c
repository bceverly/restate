/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "layout.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "machine.h"
#include "util.h"

#define KIB ((uint64_t)1024)
#define MIB (KIB * 1024)
#define GIB (MIB * 1024)

static const struct {
    const char *type;
    const char *name;
    const char *foreign;    /* whose it is, if not Linux's */
} ptypes[] = {
    { "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "EFI system", NULL },
    { "21686148-6449-6e6f-744e-656564454649", "BIOS boot", NULL },
    { "0fc63daf-8483-4772-8e79-3d69d8477de4", "Linux filesystem", NULL },
    { "4f68bce3-e8cd-4db1-96e7-fbcaf984b709", "Linux root (x86-64)", NULL },
    { "b921b045-1df0-41c3-af44-4c6f280d3fae", "Linux root (ARM64)", NULL },
    { "933ac7e1-2eb4-4f13-b844-0e14e2aef915", "Linux home", NULL },
    { "3b8f8425-20e0-4f3b-907f-1a25a76f98e8", "Linux server data", NULL },
    { "bc13c2ff-59e6-4262-a352-b275fd6f7172", "Linux extended boot", NULL },
    { "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "Linux swap", NULL },
    { "e6d6d379-f507-44c2-a23c-238f2a3df928", "Linux LVM", NULL },
    { "a19d880f-05fc-4d3b-a006-743f0f84911e", "Linux RAID", NULL },
    { "ca7d7ccb-63ed-4c53-861c-1742536059cc", "Linux LUKS", NULL },
    { "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "Microsoft basic data", NULL },
    { "e3c9e316-0b5c-4db8-817d-f92df00215ae", "Microsoft reserved", "Windows" },
    { "de94bba4-06d1-4d40-a16a-bfd50179d6ac", "Windows recovery", "Windows" },
    { "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3", "Windows LDM metadata", "Windows" },
    { "af9b60a0-1431-4f62-bc68-3311714a69ad", "Windows LDM data", "Windows" },
    { "48465300-0000-11aa-aa11-00306543ecac", "Apple HFS+", "macOS" },
    { "7c3457ef-0000-11aa-aa11-00306543ecac", "Apple APFS", "macOS" },
    { "426f6f74-0000-11aa-aa11-00306543ecac", "Apple boot", "macOS" },
    { "516e7cb4-6ecf-11d6-8ff8-00022d09712b", "FreeBSD data", "FreeBSD" },
    { "516e7cba-6ecf-11d6-8ff8-00022d09712b", "FreeBSD ZFS", "FreeBSD" },
    { "824cc7a0-36a8-11e3-890a-952519ad3f61", "OpenBSD data", "OpenBSD" },
    { "49f48d5a-b10e-11dc-b99b-0019d1879648", "NetBSD FFS", "NetBSD" },
    { "6a898cc3-1dd2-11b2-99a6-080020736631", "ZFS", NULL },
    { "0x83", "Linux", NULL },
    { "0x82", "Linux swap", NULL },
    { "0x8e", "Linux LVM", NULL },
    { "0xfd", "Linux RAID", NULL },
    { "0xef", "EFI system", NULL },
    { "0x05", "Extended", NULL },
    { "0x0f", "Extended (LBA)", NULL },
    { "0x07", "NTFS / exFAT", NULL },
    { "0x0b", "FAT32", NULL },
    { "0x0c", "FAT32 (LBA)", NULL },
    { "0x27", "Windows recovery", "Windows" },
    { "0xa5", "FreeBSD", "FreeBSD" },
    { "0xa6", "OpenBSD", "OpenBSD" },
    { "0xa9", "NetBSD", "NetBSD" },
    { "0xaf", "Apple HFS", "macOS" },
};

/* Filesystems no Linux install puts back. */
static const struct {
    const char *fstype;
    const char *whose;
} foreign_fs[] = {
    { "ntfs", "Windows" },     { "BitLocker", "Windows (BitLocker)" }, { "ReFS", "Windows" },
    { "apfs", "macOS" },       { "hfsplus", "macOS" },                  { "hfs", "macOS" },
    { "ufs", "a BSD" },        { "zfs_member", "ZFS" },
};

static bool eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static bool eq_nocase(const char *a, const char *b)
{
    if (!a || !b)
    {
        return false;
    }
    while (*a && *b)
    {
        unsigned char x = (unsigned char)*a;
        unsigned char y = (unsigned char)*b;

        x = (x >= 'A' && x <= 'Z') ? (unsigned char)(x + ('a' - 'A')) : x;
        y = (y >= 'A' && y <= 'Z') ? (unsigned char)(y + ('a' - 'A')) : y;

        if (x != y)
        {
            return false;
        }
        a++;
        b++;
    }
    return *a == *b;
}

const char *rs_ptype_name(const char *ptype)
{
    size_t i;

    for (i = 0; ptype && i < sizeof(ptypes) / sizeof(ptypes[0]); i++)
    {
        if (eq_nocase(ptypes[i].type, ptype))
        {
            return ptypes[i].name;
        }
    }
    return NULL;
}

bool rs_ptype_is(const char *ptype, const char *type)
{
    return eq_nocase(ptype, type);
}

static const char *ptype_foreign(const char *ptype)
{
    size_t i;

    for (i = 0; ptype && i < sizeof(ptypes) / sizeof(ptypes[0]); i++)
    {
        if (eq_nocase(ptypes[i].type, ptype))
        {
            return ptypes[i].foreign;
        }
    }
    return NULL;
}

void rs_human_size(uint64_t bytes, char *out, size_t len)
{
    static const char *const units[] = { "bytes", "KiB", "MiB", "GiB", "TiB", "PiB" };
    size_t                   u = 0;
    uint64_t                 whole = bytes;
    uint64_t                 rem = 0;

    while (whole >= 1024 && u + 1 < sizeof(units) / sizeof(units[0]))
    {
        rem = whole % 1024;
        whole /= 1024;
        u++;
    }
    if (u == 0)
    {
        (void)snprintf(out, len, "%llu bytes", (unsigned long long)bytes);
    } else if (whole < 10 && rem * 10 / 1024 > 0)
    {
        (void)snprintf(out, len, "%llu.%llu %s", (unsigned long long)whole,
                       (unsigned long long)(rem * 10 / 1024), units[u]);
    } else
    {
        (void)snprintf(out, len, "%llu %s", (unsigned long long)whole, units[u]);
    }
}

static uint64_t num(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return (v && v->type == RS_JINT && !v->neg) ? v->u : 0;
}

static bool flag(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return v && v->type == RS_JBOOL && v->b;
}

static const struct rs_jval *array(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return (v && v->type == RS_JARRAY) ? v : NULL;
}

static struct rs_vol *add_vol(struct rs_layout *l, enum rs_vol_kind kind, const char *name,
                              const char *kname)
{
    struct rs_vol *v;

    l->vols = rs_xreallocarray(l->vols, l->nvols + 1, sizeof(*l->vols));
    v = &l->vols[l->nvols++];
    memset(v, 0, sizeof(*v));
    v->kind = kind;
    v->name = name;
    v->kname = kname ? kname : name;
    v->disk = SIZE_MAX;
    v->vg = SIZE_MAX;
    return v;
}

static void add_parent(struct rs_vol *v, size_t parent)
{
    size_t i;

    for (i = 0; i < v->nparents; i++)
    {
        if (v->parents[i] == parent)
        {
            return;
        }
    }
    v->parents = rs_xreallocarray(v->parents, v->nparents + 1, sizeof(*v->parents));
    v->parents[v->nparents++] = parent;
}

static void read_content(struct rs_vol *v, const struct rs_jval *dev)
{
    const struct rs_jval *c = rs_jobject_get(dev, "content");
    const struct rs_jval *luks = rs_jobject_get(dev, "luks");
    const struct rs_jval *tokens = array(luks, "tokens");

    if (c && c->type == RS_JOBJECT)
    {
        v->fstype = rs_jobject_str(c, "type");
        v->usage = rs_jobject_str(c, "usage");
        v->uuid = rs_jobject_str(c, "uuid");
        v->label = rs_jobject_str(c, "label");
        v->version = rs_jobject_str(c, "version");
    }
    if (luks && luks->type == RS_JOBJECT)
    {
        size_t i;

        v->cipher = rs_jobject_str(luks, "cipher");
        v->key_size = num(luks, "key_size");
        for (i = 0; tokens && i < tokens->n; i++)
        {
            const char *t = rs_jobject_str(&tokens->items[i], "type");

            v->tpm = v->tpm || eq(t, "systemd-tpm2") || eq(t, "clevis") || eq(t, "systemd-fido2");
        }
    }
}

size_t rs_layout_find(const struct rs_layout *l, const char *name)
{
    size_t i;

    for (i = 0; name && i < l->nvols; i++)
    {
        if (eq(l->vols[i].name, name) || eq(l->vols[i].kname, name))
        {
            return i;
        }
    }
    return SIZE_MAX;
}

static size_t find_path(const struct rs_layout *l, const char *path)
{
    size_t i;

    for (i = 0; path && i < l->nvols; i++)
    {
        if (eq(l->vols[i].path, path))
        {
            return i;
        }
    }
    return SIZE_MAX;
}

size_t rs_layout_children(const struct rs_layout *l, size_t parent, size_t *out, size_t max)
{
    size_t n = 0;
    size_t i;
    size_t j;

    for (i = 0; i < l->nvols; i++)
    {
        for (j = 0; j < l->vols[i].nparents; j++)
        {
            if (l->vols[i].parents[j] == parent)
            {
                if (n < max)
                {
                    out[n] = i;
                }
                n++;
                break;
            }
        }
    }
    return n < max ? n : max;
}

static void read_disks(const struct rs_jval *machine, struct rs_layout *l)
{
    const struct rs_jval *disks = array(machine, "disks");
    size_t                i;
    size_t                j;

    for (i = 0; disks && i < disks->n; i++)
    {
        const struct rs_jval *d = &disks->items[i];
        const struct rs_jval *table = rs_jobject_get(d, "table");
        const struct rs_jval *parts = array(d, "partitions");
        struct rs_disk       *disk;

        l->disks = rs_xreallocarray(l->disks, l->ndisks + 1, sizeof(*l->disks));
        disk = &l->disks[l->ndisks];
        memset(disk, 0, sizeof(*disk));
        disk->name = rs_jobject_str(d, "name");
        disk->model = rs_jobject_str(d, "model");
        disk->serial = rs_jobject_str(d, "serial");
        disk->size = num(d, "size");
        disk->sector = num(d, "logical_block_size");
        if (disk->sector == 0)
        {
            disk->sector = 512;
        }
        disk->rotational = flag(d, "rotational");
        disk->removable = flag(d, "removable");
        if (table && table->type == RS_JOBJECT)
        {
            disk->table = rs_jobject_str(table, "type");
            disk->table_uuid = rs_jobject_str(table, "uuid");
        }
        l->ndisks++;
        if (!disk->name)
        {
            continue;
        }
        if (!disk->table || !parts)
        {
            /* A disk used whole -- LUKS, a PV or a filesystem on the device
             * itself -- is a volume in its own right. */
            if (rs_jobject_get(d, "content"))
            {
                struct rs_vol *v = add_vol(l, RS_VOL_DISK, disk->name, NULL);

                v->path = rs_xasprintf("/dev/%s", disk->name);
                v->size = disk->size;
                v->disk = l->ndisks - 1;
                read_content(v, d);
            }
            continue;
        }
        for (j = 0; j < parts->n; j++)
        {
            const struct rs_jval *p = &parts->items[j];
            const char           *name = rs_jobject_str(p, "name");
            struct rs_vol        *v;

            if (!name)
            {
                continue;
            }
            v = add_vol(l, RS_VOL_PART, name, NULL);
            v->path = rs_xasprintf("/dev/%s", name);
            v->size = num(p, "size");
            v->start = num(p, "start");
            v->number = (unsigned)num(p, "number");
            v->ptype = rs_jobject_str(p, "type");
            v->pname = rs_jobject_str(p, "label");
            v->puuid = rs_jobject_str(p, "uuid");
            v->pflags = rs_jobject_str(p, "flags");
            v->disk = l->ndisks - 1;
            read_content(v, p);
        }
    }
}

/* "vg0-root" -> "vg0", "root"; "my--vg-my--lv" -> "my-vg", "my-lv". */
static bool split_dm_lv(const char *dm, char **vg, char **lv)
{
    struct rs_buf  a;
    struct rs_buf  b;
    struct rs_buf *cur = &a;
    size_t         i;
    bool           split = false;

    rs_buf_init(&a);
    rs_buf_init(&b);
    rs_buf_add(&a, "", 0);
    rs_buf_add(&b, "", 0);
    for (i = 0; dm[i] != '\0'; i++)
    {
        if (dm[i] == '-' && dm[i + 1] == '-')
        {
            rs_buf_add(cur, "-", 1);
            i++;
        } else if (dm[i] == '-' && !split)
        {
            split = true;
            cur = &b;
        } else
        {
            rs_buf_add(cur, &dm[i], 1);
        }
    }
    if (!split || a.len == 0 || b.len == 0)
    {
        rs_buf_free(&a);
        rs_buf_free(&b);
        return false;
    }
    *vg = rs_buf_detach(&a);
    *lv = rs_buf_detach(&b);
    return true;
}

static void read_mapped(const struct rs_jval *machine, struct rs_layout *l)
{
    const struct rs_jval *mapped = array(machine, "mapped");
    size_t                i;

    for (i = 0; mapped && i < mapped->n; i++)
    {
        const struct rs_jval *m = &mapped->items[i];
        const char           *name = rs_jobject_str(m, "name");
        const char           *kind = rs_jobject_str(m, "kind");
        enum rs_vol_kind      k = RS_VOL_OTHER;
        struct rs_vol        *v;

        if (!name)
        {
            continue;
        }
        if (eq(kind, "luks"))
        {
            k = RS_VOL_LUKS;
        } else if (eq(kind, "crypt"))
        {
            k = RS_VOL_CRYPT;
        } else if (eq(kind, "lvm"))
        {
            k = RS_VOL_LV;
        }
        v = add_vol(l, k, name, rs_jobject_str(m, "device"));
        v->path = rs_xasprintf("/dev/mapper/%s", name);
        read_content(v, m);
        if (k == RS_VOL_LV)
        {
            char *vg = NULL;
            char *lv = NULL;

            if (split_dm_lv(name, &vg, &lv))
            {
                free(v->path);
                v->path = rs_xasprintf("/dev/%s/%s", vg, lv);
                v->lvname = lv;
                free(vg);
            }
        }
    }
}

static void read_raid(const struct rs_jval *machine, struct rs_layout *l)
{
    const struct rs_jval *raid = array(machine, "raid");
    size_t                i;

    for (i = 0; raid && i < raid->n; i++)
    {
        const struct rs_jval *m = &raid->items[i];
        const char           *dev = rs_jobject_str(m, "device");
        struct rs_vol        *v;

        if (!dev)
        {
            continue;
        }
        v = add_vol(l, RS_VOL_MD, dev, NULL);
        v->path = rs_xasprintf("/dev/%s", dev);
        v->level = rs_jobject_str(m, "level");
        v->metadata = rs_jobject_str(m, "metadata");
        v->chunk = num(m, "chunk_size");
        v->md_uuid = rs_jobject_str(m, "uuid");   /* the array's; content has the fs's */
        read_content(v, m);
    }
}

/* The parent links, now that every volume exists: device-mapper devices and
 * md arrays name the devices under them by kernel name. */
static void link_parents(const struct rs_jval *machine, struct rs_layout *l)
{
    static const char *const lists[] = { "mapped", "raid" };
    size_t                   li;

    for (li = 0; li < 2; li++)
    {
        const struct rs_jval *arr = array(machine, lists[li]);
        size_t                i;
        size_t                j;

        for (i = 0; arr && i < arr->n; i++)
        {
            const struct rs_jval *m = &arr->items[i];
            const char           *self = rs_jobject_str(m, li == 0 ? "name" : "device");
            const struct rs_jval *devs = array(m, "devices");
            size_t                me = rs_layout_find(l, self);

            for (j = 0; me != SIZE_MAX && devs && j < devs->n; j++)
            {
                size_t p = devs->items[j].type == RS_JSTRING
                               ? rs_layout_find(l, devs->items[j].s)
                               : SIZE_MAX;

                if (p != SIZE_MAX && p != me)
                {
                    add_parent(&l->vols[me], p);
                }
            }
        }
    }
}

static const struct rs_jval *member_object(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return (v && v->type == RS_JOBJECT) ? v : NULL;
}

static void read_lvm(const struct rs_jval *machine, struct rs_layout *l)
{
    const struct rs_jval *lvm = array(machine, "lvm");
    size_t                i;
    size_t                j;
    size_t                k;

    for (i = 0; lvm && i < lvm->n; i++)
    {
        const char           *name = rs_jobject_str(&lvm->items[i], "name");
        const char           *text = rs_jobject_str(&lvm->items[i], "metadata");
        struct rs_vg         *vg;
        const struct rs_jval *top;
        const struct rs_jval *pvs;
        const struct rs_jval *lvs;
        struct rs_buf         err;

        if (!name || !text)
        {
            continue;
        }
        l->vgs = rs_xreallocarray(l->vgs, l->nvgs + 1, sizeof(*l->vgs));
        vg = &l->vgs[l->nvgs];
        memset(vg, 0, sizeof(*vg));
        rs_buf_init(&err);
        if (!rs_lvm_parse(text, strlen(text), &vg->tree, &err))
        {
            rs_buf_free(&err);
            rs_jval_free(&vg->tree);
            continue;
        }
        rs_buf_free(&err);
        l->nvgs++;
        vg->name = rs_xstrdup(name);
        vg->metadata = text;
        /* The volume group is the one section at the top of the file; its key
         * is the group's name, which the backup file is named after. */
        top = member_object(&vg->tree, name);
        for (j = 0; !top && j < vg->tree.n; j++)
        {
            if (vg->tree.items[j].type == RS_JOBJECT)
            {
                top = &vg->tree.items[j];
                free(vg->name);
                vg->name = rs_xstrdup(vg->tree.keys[j]);
            }
        }
        if (!top)
        {
            continue;
        }
        vg->id = rs_jobject_str(top, "id");
        vg->extent = num(top, "extent_size") * 512;
        pvs = member_object(top, "physical_volumes");
        for (j = 0; pvs && j < pvs->n; j++)
        {
            struct rs_pv *pv;

            if (pvs->items[j].type != RS_JOBJECT)
            {
                continue;
            }
            vg->pvs = rs_xreallocarray(vg->pvs, vg->npvs + 1, sizeof(*vg->pvs));
            pv = &vg->pvs[vg->npvs++];
            pv->name = pvs->keys[j];
            pv->id = rs_jobject_str(&pvs->items[j], "id");
            pv->device = rs_jobject_str(&pvs->items[j], "device");
            pv->vol = find_path(l, pv->device);
        }
        lvs = member_object(top, "logical_volumes");
        for (j = 0; lvs && j < lvs->n; j++)
        {
            const struct rs_jval *lv = &lvs->items[j];
            uint64_t              extents = 0;
            char                 *dm;
            struct rs_buf         b;
            size_t                c;
            size_t                at;

            if (lv->type != RS_JOBJECT)
            {
                continue;
            }
            for (k = 0; k < lv->n; k++)
            {
                if (lv->items[k].type == RS_JOBJECT && rs_starts_with(lv->keys[k], "segment"))
                {
                    extents += num(&lv->items[k], "extent_count");
                }
            }
            /* The device-mapper name: each "-" in either name doubled. */
            rs_buf_init(&b);
            for (c = 0; vg->name[c] != '\0'; c++)
            {
                rs_buf_add(&b, vg->name[c] == '-' ? "--" : &vg->name[c], vg->name[c] == '-' ? 2 : 1);
            }
            rs_buf_add(&b, "-", 1);
            for (c = 0; lvs->keys[j][c] != '\0'; c++)
            {
                rs_buf_add(&b, lvs->keys[j][c] == '-' ? "--" : &lvs->keys[j][c],
                           lvs->keys[j][c] == '-' ? 2 : 1);
            }
            dm = rs_buf_detach(&b);
            at = rs_layout_find(l, dm);
            if (at == SIZE_MAX)
            {
                /* Not active when the description was taken: still part of the
                 * group, and still rebuilt. */
                struct rs_vol *v = add_vol(l, RS_VOL_LV, lvs->keys[j], NULL);

                v->path = rs_xasprintf("/dev/%s/%s", vg->name, lvs->keys[j]);
                at = l->nvols - 1;
            }
            free(dm);
            l->vols[at].vg = l->nvgs - 1;
            if (!l->vols[at].lvname)
            {
                l->vols[at].lvname = rs_xstrdup(lvs->keys[j]);
            }
            l->vols[at].size = extents * vg->extent;
            for (k = 0; k < vg->npvs; k++)
            {
                if (vg->pvs[k].vol != SIZE_MAX)
                {
                    add_parent(&l->vols[at], vg->pvs[k].vol);
                }
            }
        }
    }
}

/* Whether fstab's first field names this volume. */
static bool names_vol(const char *spec, const struct rs_vol *v)
{
    char *by;
    bool  hit;

    if (!spec)
    {
        return false;
    }
    if ((v->uuid && rs_starts_with(spec, "UUID=") && eq_nocase(spec + 5, v->uuid)) ||
        (v->label && rs_starts_with(spec, "LABEL=") && eq(spec + 6, v->label)) ||
        (v->puuid && rs_starts_with(spec, "PARTUUID=") && eq_nocase(spec + 9, v->puuid)) ||
        eq(spec, v->path))
    {
        return true;
    }
    by = rs_xasprintf("/dev/mapper/%s", v->name);
    hit = eq(spec, by);
    free(by);
    if (!hit && v->uuid)
    {
        by = rs_xasprintf("/dev/disk/by-uuid/%s", v->uuid);
        hit = eq(spec, by);
        free(by);
    }
    return hit;
}

static void read_mounts(const struct rs_jval *machine, struct rs_layout *l)
{
    const struct rs_jval *fstab = array(machine, "fstab");
    const struct rs_jval *mounts = array(machine, "mounts");
    const struct rs_jval *crypttab = array(machine, "crypttab");
    const struct rs_jval *swap = array(machine, "swap");
    size_t                i;
    size_t                j;

    for (i = 0; fstab && i < fstab->n; i++)
    {
        const struct rs_jval *e = &fstab->items[i];
        const char           *spec = rs_jobject_str(e, "spec");
        const char           *file = rs_jobject_str(e, "file");
        const char           *type = rs_jobject_str(e, "type");
        bool                  found = false;

        for (j = 0; j < l->nvols; j++)
        {
            if (!l->vols[j].mountpoint && names_vol(spec, &l->vols[j]))
            {
                l->vols[j].mountpoint = eq(type, "swap") ? "[swap]" : file;
                l->vols[j].options = rs_jobject_str(e, "options");
                found = true;
                break;
            }
        }
        if (found || !spec || !file)
        {
            continue;
        }
        if (eq(type, "nfs") || eq(type, "nfs4") || eq(type, "cifs") || eq(type, "smb3") ||
            eq(type, "sshfs") || eq(type, "fuse.sshfs") || eq(type, "glusterfs") ||
            eq(type, "ceph"))
        {
            struct rs_netmount *n;

            l->netmounts = rs_xreallocarray(l->netmounts, l->nnetmounts + 1, sizeof(*n));
            n = &l->netmounts[l->nnetmounts++];
            n->spec = spec;
            n->file = file;
            n->type = type;
            n->options = rs_jobject_str(e, "options");
        }
    }
    for (i = 0; mounts && i < mounts->n; i++)
    {
        const struct rs_jval *e = &mounts->items[i];
        const char           *source = rs_jobject_str(e, "source");

        for (j = 0; j < l->nvols; j++)
        {
            if (names_vol(source, &l->vols[j]))
            {
                l->vols[j].fs_size = num(e, "size");
                l->vols[j].fs_used = num(e, "used");
                if (!l->vols[j].mountpoint)
                {
                    l->vols[j].mountpoint = rs_jobject_str(e, "mountpoint");
                }
                break;
            }
        }
    }
    for (i = 0; crypttab && i < crypttab->n; i++)
    {
        const struct rs_jval *e = &crypttab->items[i];
        const char           *key = rs_jobject_str(e, "keyfile");
        size_t                v = rs_layout_find(l, rs_jobject_str(e, "name"));

        if (v != SIZE_MAX && key && !eq(key, "none") && !eq(key, "-"))
        {
            l->vols[v].keyfile = key;
        }
    }
    for (i = 0; swap && i < swap->n; i++)
    {
        const struct rs_jval *e = &swap->items[i];

        if (eq(rs_jobject_str(e, "type"), "file"))
        {
            struct rs_swapfile *s;

            l->swapfiles = rs_xreallocarray(l->swapfiles, l->nswapfiles + 1, sizeof(*s));
            s = &l->swapfiles[l->nswapfiles++];
            s->file = rs_jobject_str(e, "file");
            s->size = num(e, "size");
        }
    }
}

/* Another system's volumes: by partition type, by filesystem, and a container
 * whose every child is another system's. */
static void mark_foreign(struct rs_layout *l)
{
    size_t i;
    size_t j;
    bool   changed = true;

    for (i = 0; i < l->nvols; i++)
    {
        struct rs_vol *v = &l->vols[i];
        const char    *whose = ptype_foreign(v->ptype);

        for (j = 0; !whose && v->fstype && j < sizeof(foreign_fs) / sizeof(foreign_fs[0]); j++)
        {
            if (eq(v->fstype, foreign_fs[j].fstype))
            {
                whose = foreign_fs[j].whose;
            }
        }
        if (!whose && v->kind == RS_VOL_OTHER)
        {
            whose = "a device-mapper volume restate cannot recreate (VeraCrypt or similar)";
        }
        if (!whose && v->disk != SIZE_MAX && l->disks[v->disk].removable)
        {
            whose = "a removable disk, not part of the machine";
        }
        if (whose)
        {
            v->foreign = true;
            v->foreign_why = whose;
        }
    }
    /* A partition with nothing restate recognizes on it, held by a foreign
     * mapping (a VeraCrypt container), is that system's too; and so is
     * anything built only on foreign volumes. */
    while (changed)
    {
        changed = false;
        for (i = 0; i < l->nvols; i++)
        {
            size_t kids[16];
            size_t n;
            bool   all = true;

            if (l->vols[i].foreign)
            {
                continue;
            }
            for (j = 0; j < l->vols[i].nparents; j++)
            {
                all = all && l->vols[l->vols[i].parents[j]].foreign;
            }
            if (l->vols[i].nparents > 0 && all)
            {
                l->vols[i].foreign = true;
                l->vols[i].foreign_why = l->vols[l->vols[i].parents[0]].foreign_why;
                changed = true;
                continue;
            }
            all = true;
            if (l->vols[i].fstype)
            {
                continue;
            }
            n = rs_layout_children(l, i, kids, 16);
            for (j = 0; j < n; j++)
            {
                all = all && l->vols[kids[j]].foreign;
            }
            if (n > 0 && all)
            {
                l->vols[i].foreign = true;
                l->vols[i].foreign_why = l->vols[kids[0]].foreign_why;
                changed = true;
            }
        }
    }
}

/* The LUKS details live on the device holding the header, the partition;
 * the mapping is what the rest of the layout refers to. */
static void inherit_luks(struct rs_layout *l)
{
    size_t i;

    for (i = 0; i < l->nvols; i++)
    {
        struct rs_vol *v = &l->vols[i];

        if ((v->kind == RS_VOL_LUKS || v->kind == RS_VOL_CRYPT) && v->nparents == 1)
        {
            const struct rs_vol *p = &l->vols[v->parents[0]];

            v->cipher = p->cipher;
            v->key_size = p->key_size;
            v->tpm = p->tpm;
            if (v->size == 0 && p->size > 16 * MIB)
            {
                v->size = p->size - 16 * MIB;
            }
        }
    }
}

/*
 * A PV recorded by a name its device no longer has (/dev/sda2 is /dev/sdb2
 * now): if exactly one LVM physical volume belongs to no group, it is that one.
 */
static void claim_pvs(struct rs_layout *l)
{
    size_t g;
    size_t k;
    size_t i;
    size_t j;

    for (g = 0; g < l->nvgs; g++)
    {
        for (k = 0; k < l->vgs[g].npvs; k++)
        {
            size_t free_pv = SIZE_MAX;
            size_t nfree = 0;

            if (l->vgs[g].pvs[k].vol != SIZE_MAX)
            {
                continue;
            }
            for (i = 0; i < l->nvols; i++)
            {
                bool   claimed = false;
                size_t h;

                if (!eq(l->vols[i].fstype, "LVM2_member"))
                {
                    continue;
                }
                for (h = 0; h < l->nvgs && !claimed; h++)
                {
                    for (j = 0; j < l->vgs[h].npvs; j++)
                    {
                        claimed = claimed || l->vgs[h].pvs[j].vol == i;
                    }
                }
                if (!claimed)
                {
                    free_pv = i;
                    nfree++;
                }
            }
            if (nfree == 1)
            {
                l->vgs[g].pvs[k].vol = free_pv;
                for (i = 0; i < l->nvols; i++)
                {
                    if (l->vols[i].vg == g)
                    {
                        add_parent(&l->vols[i], free_pv);
                    }
                }
            }
        }
    }
}

bool rs_layout_build(const struct rs_jval *machine, struct rs_layout *out)
{
    const struct rs_jval *fw = rs_jobject_get(machine, "firmware");

    memset(out, 0, sizeof(*out));
    read_disks(machine, out);
    read_mapped(machine, out);
    read_raid(machine, out);
    link_parents(machine, out);
    read_lvm(machine, out);
    claim_pvs(out);
    read_mounts(machine, out);
    inherit_luks(out);
    mark_foreign(out);
    out->firmware = rs_jobject_str(fw, "mode");
    out->secure_boot = flag(fw, "secure_boot");
    return out->ndisks > 0;
}

void rs_layout_free(struct rs_layout *l)
{
    size_t i;

    for (i = 0; i < l->nvols; i++)
    {
        free(l->vols[i].path);
        free(l->vols[i].parents);
        free(l->vols[i].lvname);
    }
    for (i = 0; i < l->nvgs; i++)
    {
        free(l->vgs[i].name);
        free(l->vgs[i].pvs);
        rs_jval_free(&l->vgs[i].tree);
    }
    free(l->vols);
    free(l->disks);
    free(l->vgs);
    free(l->swapfiles);
    free(l->netmounts);
    memset(l, 0, sizeof(*l));
}

static uint64_t round_up(uint64_t v, uint64_t unit)
{
    return (v + unit - 1) / unit * unit;
}

/*
 * A filesystem in a virtual machine: what it uses, a quarter again, and 2 GiB
 * for the system to grow into, never less than 1 GiB and never more than it
 * had. One that was not mounted -- so its use is unknown -- keeps its size.
 */
static uint64_t fit_fs(const struct rs_vol *v)
{
    uint64_t want;

    if (v->fs_size == 0)
    {
        return v->size;
    }
    want = round_up(v->fs_used + v->fs_used / 4 + 2 * GIB, GIB);
    if (v->size > 0 && want > v->size)
    {
        want = v->size;
    }
    if (want < GIB)
    {
        want = (v->size > 0 && v->size < GIB) ? v->size : GIB;
    }
    return want;
}

uint64_t rs_layout_fit(const struct rs_layout *l, size_t vol, enum rs_target target) /* NOLINT(misc-no-recursion) */
{
    const struct rs_vol *v = &l->vols[vol];
    size_t               kids[64];
    size_t               n;
    size_t               i;
    uint64_t             sum = 0;

    if (v->foreign)
    {
        return target == RS_TARGET_SAME ? v->size : 0;
    }
    if (target != RS_TARGET_VM)
    {
        return v->size;
    }
    if (eq_nocase(v->ptype, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b") || eq_nocase(v->ptype, "0xef") ||
        eq_nocase(v->ptype, "21686148-6449-6e6f-744e-656564454649"))
    {
        return v->size;
    }
    if (eq(v->fstype, "swap"))
    {
        return v->size < 8 * GIB ? v->size : 8 * GIB;
    }
    if (eq(v->usage, "filesystem"))
    {
        return fit_fs(v);
    }
    if (eq(v->fstype, "LVM2_member"))
    {
        /* This PV's share of what the group's volumes need, plus metadata. */
        for (i = 0; i < l->nvgs; i++)
        {
            size_t k;
            size_t mine = SIZE_MAX;

            for (k = 0; k < l->vgs[i].npvs; k++)
            {
                if (l->vgs[i].pvs[k].vol == vol)
                {
                    mine = k;
                }
            }
            if (mine == SIZE_MAX)
            {
                continue;
            }
            for (k = 0; k < l->nvols; k++)
            {
                if (l->vols[k].vg == i)
                {
                    sum += round_up(rs_layout_fit(l, k, target), l->vgs[i].extent ? l->vgs[i].extent : 4 * MIB);
                }
            }
            sum = sum / l->vgs[i].npvs + 8 * MIB;
            return round_up(sum, MIB);
        }
        return v->size;
    }
    n = rs_layout_children(l, vol, kids, 64);
    if (n == 0)
    {
        return v->size;
    }
    for (i = 0; i < n; i++)
    {
        sum += rs_layout_fit(l, kids[i], target);
    }
    if (eq(v->fstype, "crypto_LUKS"))
    {
        sum += 16 * MIB;   /* the LUKS2 header and keyslots */
    } else if (eq(v->fstype, "linux_raid_member"))
    {
        sum += 128 * MIB;  /* md's metadata and the data offset it leaves */
    }
    sum = round_up(sum, MIB);
    return (v->size > 0 && sum > v->size) ? v->size : sum;
}
