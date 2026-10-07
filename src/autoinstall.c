/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "autoinstall.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "image.h"
#include "packages.h"

#define MIB ((uint64_t)1024 * 1024)

struct gen {
    const struct rs_jval      *machine;
    const struct rs_jval      *sys;
    const struct rs_auto_opts *o;
    struct rs_layout           l;
    struct rs_buf             *out;
    bool                       keep_table;  /* another system shares the disk */
    bool                      *made;        /* per volume: in the config already */
    bool                      *vg_made;
    struct rs_buf              late;        /* the late-commands, as YAML lines */
};

static bool eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

/* A YAML double-quoted scalar. */
static void q(struct rs_buf *b, const char *s)
{
    rs_buf_addc(b, '"');
    for (; s && *s; s++)
    {
        unsigned char c = (unsigned char)*s;

        if (c == '"' || c == '\\')
        {
            rs_buf_addc(b, '\\');
            rs_buf_addc(b, (char)c);
        } else if (c < 0x20)
        {
            rs_buf_addf(b, "\\x%02x", c);
        } else
        {
            rs_buf_addc(b, (char)c);
        }
    }
    rs_buf_addc(b, '"');
}

/* "key: "value"\n" at an indent. */
static void kv(struct gen *g, int indent, const char *key, const char *value)
{
    rs_buf_addf(g->out, "%*s%s: ", indent, "", key);
    q(g->out, value);
    rs_buf_addc(g->out, '\n');
}

/* An id curtin accepts: the kind, then the name with anything odd as "-". */
static char *id_for(const char *kind, const char *name)
{
    char  *id = rs_xasprintf("%s-%s", kind, name ? name : "x");
    size_t i;

    for (i = 0; id[i] != '\0'; i++)
    {
        char c = id[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '_'))
        {
            id[i] = '-';
        }
    }
    return id;
}

static char *vol_id(const struct gen *g, size_t i)
{
    const struct rs_vol *v = &g->l.vols[i];

    switch (v->kind)
    {
    case RS_VOL_DISK:
        return id_for("disk", v->name);
    case RS_VOL_PART:
        return id_for("part", v->name);
    case RS_VOL_LUKS:
    case RS_VOL_CRYPT:
        return id_for("crypt", v->name);
    case RS_VOL_MD:
        return id_for("md", v->name);
    case RS_VOL_LV:
        return id_for("lv", v->name);
    case RS_VOL_OTHER:
    default:
        return id_for("vol", v->name);
    }
}

static bool is_esp(const struct rs_vol *v)
{
    return rs_ptype_is(v->ptype, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b") ||
           rs_ptype_is(v->ptype, "0xef");
}

static const char *part_flag(const struct rs_vol *v)
{
    static const struct {
        const char *type;
        const char *flag;
    } flags[] = {
        { "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "boot" },
        { "21686148-6449-6e6f-744e-656564454649", "bios_grub" },
        { "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "swap" },
        { "e3c9e316-0b5c-4db8-817d-f92df00215ae", "msftres" },
        { "e6d6d379-f507-44c2-a23c-238f2a3df928", "lvm" },
        { "a19d880f-05fc-4d3b-a006-743f0f84911e", "raid" },
        { "0xef", "boot" }, { "0x82", "swap" }, { "0x8e", "lvm" }, { "0xfd", "raid" },
        { "0x05", "extended" }, { "0x0f", "extended" },
    };
    size_t i;

    for (i = 0; v->ptype && i < sizeof(flags) / sizeof(flags[0]); i++)
    {
        if (rs_ptype_is(v->ptype, flags[i].type))
        {
            return flags[i].flag;
        }
    }
    return NULL;
}

static void header(struct gen *g)
{
    const char *host = rs_jobject_str(g->sys, "hostname");
    static const char *const targets[] = {
        "this machine, or one like it, on the same storage layout",
        "a virtual machine, its Linux volumes sized to what they use",
        "other hardware, its Linux volumes at their original sizes"
    };

    rs_buf_addstr(g->out, "#cloud-config\n");
    rs_buf_addf(g->out, "# restate autoinstall: %s, rebuilt as %s.\n", host ? host : "(no host name)",
                targets[g->o->target]);
    rs_buf_addf(g->out, "# Made by restate %s from %s.\n", g->o->version ? g->o->version : "",
                g->o->image ? g->o->image : "the running system");
    rs_buf_addstr(g->out,
                  "#\n"
                  "# Before using it, replace every CHANGE-ME below. Each LUKS passphrase has to be\n"
                  "# in this file -- the installer formats the volume with it -- so keep the file\n"
                  "# as private as the passphrase, and change the passphrase after the install\n"
                  "# (cryptsetup luksChangeKey) if the file is shared.\n"
                  "#\n"
                  "# To use it: save it as user-data beside an empty meta-data file on a volume\n"
                  "# labeled CIDATA (or serve both over HTTP), and boot the installer with\n"
                  "# \"autoinstall\" added to the kernel command line. It ERASES the disks it\n"
                  "# names: try it in a VM first (restate autoinstall --target vm).\n"
                  "#\n"
                  "# The installer formats the volumes itself, so the restore keeps its\n"
                  "# /etc/fstab and /etc/crypttab rather than the old ones.\n");
    if (g->o->packages && g->o->image_at)
    {
        rs_buf_addf(g->out,
                    "#\n"
                    "# The late-commands install the packages and restore the files from the\n"
                    "# image at %s, so it has to be there when the installer gets to them:\n"
                    "# a disk or share mounted there by an early-command, or by the installer's\n"
                    "# environment. Without it, the install stops with that said in its log.\n",
                    g->o->image_at);
    } else
    {
        rs_buf_addstr(g->out,
                      "#\n"
                      "# After the first boot, install the packages and put the files back as the\n"
                      "# build sheet describes (restate buildsheet) -- or make this file with\n"
                      "# --image-at PATH, where the installer will find the image, and it does\n"
                      "# both itself.\n");
    }
    if (g->keep_table)
    {
        rs_buf_addstr(g->out,
                      "#\n"
                      "# Another operating system shares the disk. Its partitions, the partition\n"
                      "# table and the EFI system partition are kept (preserve: true); only the\n"
                      "# Linux volumes are formatted.\n");
    }
}

static void identity(struct gen *g)
{
    const char           *locale = rs_jobject_str(g->sys, "locale");
    const char           *layout = rs_jobject_str(g->sys, "keyboard_layout");
    const char           *variant = rs_jobject_str(g->sys, "keyboard_variant");
    const char           *tz = rs_jobject_str(g->sys, "timezone");
    const char           *host = rs_jobject_str(g->sys, "hostname");
    const struct rs_jval *ssh = rs_jobject_get(g->sys, "ssh_server");

    rs_buf_addstr(g->out, "autoinstall:\n  version: 1\n");
    kv(g, 2, "locale", locale ? locale : "en_US.UTF-8");
    rs_buf_addstr(g->out, "  keyboard:\n");
    kv(g, 4, "layout", layout ? layout : "us");
    kv(g, 4, "variant", variant ? variant : "");
    if (tz)
    {
        kv(g, 2, "timezone", tz);
    }
    rs_buf_addstr(g->out, "  identity:\n");
    kv(g, 4, "hostname", host ? host : "restored");
    {
        /* The old machine's first person, as the install's own account: the
         * restore's merged accounts then give them back their password,
         * groups and home, with no installer account on their number. */
        const struct rs_jval *users = rs_jobject_get(g->sys, "users");
        const struct rs_jval *first = NULL;
        size_t                i;
        uint64_t              best = UINT64_MAX;

        for (i = 0; users && users->type == RS_JARRAY && i < users->n; i++)
        {
            uint64_t    uid = 0;
            const char *name = rs_jobject_str(&users->items[i], "name");

            if (name && rs_jval_u64(rs_jobject_get(&users->items[i], "uid"), &uid) && uid < best &&
                strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789_-.") == strlen(name) &&
                name[0] >= 'a' && name[0] <= 'z')
            {
                best = uid;
                first = &users->items[i];
            }
        }
        if (first)
        {
            const char *gecos = rs_jobject_str(first, "gecos");
            char       *real = rs_xstrndup(gecos ? gecos : "", gecos ? strcspn(gecos, ",") : 0);

            kv(g, 4, "realname", real[0] ? real : rs_jobject_str(first, "name"));
            kv(g, 4, "username", rs_jobject_str(first, "name"));
            free(real);
        } else
        {
            kv(g, 4, "realname", "restate");
            kv(g, 4, "username", "restate");
        }
    }
    rs_buf_addstr(g->out,
                  "    # Locked until the restore brings back /etc/shadow and the real accounts.\n"
                  "    # To log in before that, replace it with a hash from `mkpasswd -m sha-512`.\n");
    kv(g, 4, "password", "!CHANGE-ME");
    if (ssh && ssh->type == RS_JBOOL && ssh->b)
    {
        rs_buf_addstr(g->out, "  ssh:\n    install-server: true\n    allow-pw: false\n");
    }
}

static void network(struct gen *g)
{
    const struct rs_jval *hw = rs_jobject_get(g->machine, "hardware");
    const struct rs_jval *net = rs_jobject_get(hw, "network");
    bool                  any = false;

    rs_buf_addstr(g->out, "  network:\n    version: 2\n");
    if (eq(rs_jobject_str(g->sys, "type"), "desktop"))
    {
        rs_buf_addstr(g->out, "    renderer: NetworkManager\n");
    }
    rs_buf_addstr(g->out, "    ethernets:\n");
    if (g->o->target == RS_TARGET_SAME)
    {
        size_t i;

        /* The same interfaces, by MAC, with their old names. Wireless needs a
         * passphrase this file does not have; it comes back with the restore. */
        for (i = 0; net && net->type == RS_JARRAY && i < net->n; i++)
        {
            const char *name = rs_jobject_str(&net->items[i], "name");
            const char *mac = rs_jobject_str(&net->items[i], "mac");

            if (!name || !mac || rs_starts_with(name, "wl"))
            {
                continue;
            }
            rs_buf_addf(g->out, "      %s:\n        match:\n", name);
            kv(g, 10, "macaddress", mac);
            kv(g, 8, "set-name", name);
            rs_buf_addstr(g->out, "        dhcp4: true\n");
            any = true;
        }
    }
    if (!any)
    {
        /* New interfaces whose names are not known yet: every wired one. */
        rs_buf_addstr(g->out, "      wired:\n        match:\n          name: \"en*\"\n"
                              "        dhcp4: true\n");
    }
}

static void put_disk(struct gen *g, size_t d)
{
    const struct rs_disk *disk = &g->l.disks[d];
    char                 *id = id_for("disk", disk->name);
    bool                  bios = eq(g->l.firmware, "bios");
    size_t                n = 0;
    size_t                i;

    for (i = 0; i < g->l.ndisks; i++)
    {
        n += g->l.disks[i].removable ? 0 : 1;
    }
    rs_buf_addstr(g->out, "      - type: disk\n");
    kv(g, 8, "id", id);
    if (g->o->target == RS_TARGET_VM)
    {
        char *path = rs_xasprintf("/dev/vd%c", (char)('a' + d % 26));

        kv(g, 8, "path", path);
        free(path);
    } else if (g->o->target == RS_TARGET_METAL && n == 1)
    {
        rs_buf_addstr(g->out, "        match:\n          size: largest\n");
    } else if (g->o->target == RS_TARGET_METAL)
    {
        rs_buf_addstr(g->out, "        # CHANGE-ME: the new machine's disk, from lsblk\n");
        kv(g, 8, "path", "/dev/CHANGE-ME");
    } else
    {
        char *path = rs_xasprintf("/dev/%s", disk->name);

        kv(g, 8, "path", path);
        if (disk->serial)
        {
            kv(g, 8, "serial", disk->serial);
        }
        free(path);
    }
    if (disk->table)
    {
        kv(g, 8, "ptable", strcmp(disk->table, "dos") == 0 ? "msdos" : "gpt");
    }
    if (g->keep_table)
    {
        rs_buf_addstr(g->out, "        preserve: true\n");
    } else
    {
        rs_buf_addstr(g->out, "        preserve: false\n        wipe: superblock-recursive\n");
    }
    if (bios)
    {
        rs_buf_addstr(g->out, "        grub_device: true\n");
    }
    free(id);
}

static void put_partitions(struct gen *g, size_t d)
{
    char    *disk_id = id_for("disk", g->l.disks[d].name);
    size_t   i;
    size_t   last = SIZE_MAX;
    unsigned num = 0;

    for (i = 0; i < g->l.nvols; i++)
    {
        if (g->l.vols[i].disk == d && g->l.vols[i].kind == RS_VOL_PART &&
            rs_layout_fit(&g->l, i, g->o->target) > 0)
        {
            last = i;
        }
    }
    for (i = 0; i < g->l.nvols; i++)
    {
        const struct rs_vol *v = &g->l.vols[i];
        uint64_t             fit = rs_layout_fit(&g->l, i, g->o->target);
        const char          *flag = part_flag(v);
        char                *id;

        if (v->disk != d || v->kind != RS_VOL_PART || fit == 0)
        {
            continue;
        }
        num++;
        id = vol_id(g, i);
        rs_buf_addstr(g->out, "      - type: partition\n");
        kv(g, 8, "id", id);
        kv(g, 8, "device", disk_id);
        rs_buf_addf(g->out, "        number: %u\n", g->o->target == RS_TARGET_SAME ? v->number : num);
        if (g->o->target == RS_TARGET_SAME)
        {
            rs_buf_addf(g->out, "        offset: %" PRIu64 "\n        size: %" PRIu64 "\n", v->start, v->size);
        } else if (i == last)
        {
            rs_buf_addstr(g->out, "        size: -1    # the rest of the disk\n");
        } else
        {
            rs_buf_addf(g->out, "        size: %" PRIu64 "\n", (fit + MIB - 1) / MIB * MIB);
        }
        if (flag)
        {
            kv(g, 8, "flag", flag);
        }
        if (v->ptype && !rs_starts_with(v->ptype, "0x"))
        {
            kv(g, 8, "partition_type", v->ptype);
        }
        if (is_esp(v) && !eq(g->l.firmware, "bios"))
        {
            rs_buf_addstr(g->out, "        grub_device: true\n");
        }
        /* Kept as they are: another system's, and the ESP it boots from. */
        rs_buf_addf(g->out, "        preserve: %s\n", g->keep_table ? "true" : "false");
        if (v->foreign)
        {
            rs_buf_addf(g->out, "        # %s: left alone\n", v->foreign_why);
        }
        g->made[i] = true;
        free(id);
    }
    free(disk_id);
}

static void put_format(struct gen *g, size_t i)
{
    const struct rs_vol *v = &g->l.vols[i];
    char                *id = vol_id(g, i);
    char                *fid = id_for("fmt", id + 0);
    bool                 keep = g->keep_table && is_esp(v);

    if (!v->fstype || (!eq(v->usage, "filesystem") && !eq(v->fstype, "swap")) || v->foreign)
    {
        free(id);
        free(fid);
        return;
    }
    rs_buf_addstr(g->out, "      - type: format\n");
    kv(g, 8, "id", fid);
    kv(g, 8, "volume", id);
    kv(g, 8, "fstype", eq(v->fstype, "vfat") ? "fat32" : v->fstype);
    if (v->label)
    {
        kv(g, 8, "label", v->label);
    }
    if (v->uuid && (rs_starts_with(v->fstype, "ext") || eq(v->fstype, "xfs") || eq(v->fstype, "btrfs") ||
                    eq(v->fstype, "swap")))
    {
        kv(g, 8, "uuid", v->uuid);
    }
    rs_buf_addf(g->out, "        preserve: %s\n", keep ? "true" : "false");
    if (keep)
    {
        rs_buf_addstr(g->out, "        # not reformatted: the other system boots from it too\n");
    }
    if (v->mountpoint)
    {
        char *mid = id_for("mnt", id);

        rs_buf_addstr(g->out, "      - type: mount\n");
        kv(g, 8, "id", mid);
        kv(g, 8, "device", fid);
        kv(g, 8, "path", eq(v->mountpoint, "[swap]") ? "none" : v->mountpoint);
        if (v->options && !eq(v->options, "defaults") && !eq(v->mountpoint, "[swap]"))
        {
            kv(g, 8, "options", v->options);
        }
        free(mid);
    }
    free(id);
    free(fid);
}

static void put_luks(struct gen *g, size_t i)
{
    size_t kids[2];
    char  *vol = vol_id(g, i);
    char  *id;

    if (rs_layout_children(&g->l, i, kids, 2) == 0)
    {
        free(vol);
        return;
    }
    id = vol_id(g, kids[0]);
    rs_buf_addstr(g->out, "      - type: dm_crypt\n");
    kv(g, 8, "id", id);
    kv(g, 8, "volume", vol);
    kv(g, 8, "dm_name", g->l.vols[kids[0]].name);
    kv(g, 8, "key", "CHANGE-ME");
    rs_buf_addstr(g->out, "        preserve: false\n");
    g->made[kids[0]] = true;
    free(id);
    free(vol);
}

static void put_raid(struct gen *g, size_t md)
{
    const struct rs_vol *v = &g->l.vols[md];
    char                *id = vol_id(g, md);
    size_t               k;

    rs_buf_addstr(g->out, "      - type: raid\n");
    kv(g, 8, "id", id);
    kv(g, 8, "name", v->name);
    kv(g, 8, "raidlevel", v->level ? v->level : "raid1");
    if (v->metadata)
    {
        kv(g, 8, "metadata", v->metadata);
    }
    rs_buf_addstr(g->out, "        devices:\n");
    for (k = 0; k < v->nparents; k++)
    {
        char *p = vol_id(g, v->parents[k]);

        rs_buf_addstr(g->out, "          - ");
        q(g->out, p);
        rs_buf_addc(g->out, '\n');
        free(p);
    }
    rs_buf_addstr(g->out, "        preserve: false\n");
    g->made[md] = true;
    free(id);
}

static void put_vg(struct gen *g, size_t vgi)
{
    const struct rs_vg *vg = &g->l.vgs[vgi];
    char               *id = id_for("vg", vg->name);
    size_t              k;
    size_t              i;

    rs_buf_addstr(g->out, "      - type: lvm_volgroup\n");
    kv(g, 8, "id", id);
    kv(g, 8, "name", vg->name);
    rs_buf_addstr(g->out, "        devices:\n");
    for (k = 0; k < vg->npvs; k++)
    {
        char *p = vg->pvs[k].vol != SIZE_MAX ? vol_id(g, vg->pvs[k].vol) : rs_xstrdup("CHANGE-ME");

        rs_buf_addstr(g->out, "          - ");
        q(g->out, p);
        rs_buf_addc(g->out, '\n');
        free(p);
    }
    rs_buf_addstr(g->out, "        preserve: false\n");
    for (i = 0; i < g->l.nvols; i++)
    {
        const struct rs_vol *v = &g->l.vols[i];
        char                *lid;

        if (v->vg != vgi || !v->lvname || v->foreign)
        {
            continue;
        }
        lid = vol_id(g, i);
        rs_buf_addstr(g->out, "      - type: lvm_partition\n");
        kv(g, 8, "id", lid);
        kv(g, 8, "name", v->lvname);
        kv(g, 8, "volgroup", id);
        rs_buf_addf(g->out, "        size: %" PRIu64 "\n",
                    (rs_layout_fit(&g->l, i, g->o->target) + MIB - 1) / MIB * MIB);
        rs_buf_addstr(g->out, "        preserve: false\n");
        g->made[i] = true;
        free(lid);
    }
    g->vg_made[vgi] = true;
    free(id);
}

static bool all_made(const struct gen *g, const struct rs_vol *v)
{
    size_t k;

    for (k = 0; k < v->nparents; k++)
    {
        if (!g->made[v->parents[k]])
        {
            return false;
        }
    }
    return true;
}

static void storage(struct gen *g)
{
    bool  *handled = rs_xcalloc(g->l.nvols + 1, sizeof(*handled));
    bool   progress = true;
    size_t d;
    size_t i;

    rs_buf_addstr(g->out, "  storage:\n    config:\n");
    for (d = 0; d < g->l.ndisks; d++)
    {
        bool used = false;

        for (i = 0; i < g->l.nvols; i++)
        {
            used = used || (g->l.vols[i].disk == d && rs_layout_fit(&g->l, i, g->o->target) > 0);
        }
        if (!used || g->l.disks[d].removable)
        {
            continue;
        }
        put_disk(g, d);
        put_partitions(g, d);
    }
    for (i = 0; i < g->l.nvols; i++)
    {
        if (g->l.vols[i].kind == RS_VOL_DISK && !g->l.vols[i].foreign)
        {
            g->made[i] = true;
        }
    }
    /* Then what sits on what, each once everything under it exists. */
    while (progress)
    {
        progress = false;
        for (i = 0; i < g->l.nvols; i++)
        {
            const struct rs_vol *v = &g->l.vols[i];

            if (handled[i] || !g->made[i] || v->foreign)
            {
                continue;
            }
            if (eq(v->fstype, "crypto_LUKS"))
            {
                put_luks(g, i);
            } else if (eq(v->fstype, "linux_raid_member"))
            {
                size_t kids[2];

                if (rs_layout_children(&g->l, i, kids, 2) > 0 && !g->made[kids[0]])
                {
                    if (!all_made(g, &g->l.vols[kids[0]]))
                    {
                        continue;
                    }
                    put_raid(g, kids[0]);
                }
            } else if (eq(v->fstype, "LVM2_member"))
            {
                size_t vgi;
                bool   wait = false;

                for (vgi = 0; vgi < g->l.nvgs; vgi++)
                {
                    size_t k;
                    bool   mine = false;
                    bool   ready = true;

                    for (k = 0; k < g->l.vgs[vgi].npvs; k++)
                    {
                        size_t pv = g->l.vgs[vgi].pvs[k].vol;

                        mine = mine || pv == i;
                        ready = ready && (pv == SIZE_MAX || g->made[pv]);
                    }
                    if (mine && !g->vg_made[vgi])
                    {
                        if (ready)
                        {
                            put_vg(g, vgi);
                        } else
                        {
                            wait = true;
                        }
                    }
                }
                if (wait)
                {
                    continue;
                }
            } else
            {
                put_format(g, i);
            }
            handled[i] = true;
            progress = true;
        }
    }
    free(handled);
    /* curtin makes a swap file of its own unless told; the machine's own swap
     * file (or partition) comes back through /etc/fstab and the build sheet. */
    rs_buf_addstr(g->out, "    swap:\n      size: 0\n");
}

/* ------------------------------------------------------------------------- */
/* After the install: the packages, then the files                           */
/* ------------------------------------------------------------------------- */

/* A late-command: run by the installer with sh -c, on the installer's side,
 * the new system mounted at /target. */
static void late(struct gen *g, const char *cmd)
{
    rs_buf_addstr(&g->late, "    - ");
    q(&g->late, cmd);
    rs_buf_addc(&g->late, '\n');
}

static void late_comment(struct gen *g, const char *text)
{
    rs_buf_addf(&g->late, "    # %s\n", text);
}

/* A file written into the new system, carried as base64 so that nothing in
 * it is ever read by the shell or YAML. */
static void late_file(struct gen *g, const char *path, const char *content, const char *mode)
{
    struct rs_buf b64;
    struct rs_buf cmd;
    const char   *slash = strrchr(path, '/');

    rs_buf_init(&b64);
    rs_buf_init(&cmd);
    rs_base64_encode(&b64, content, strlen(content));
    rs_buf_addf(&cmd, "mkdir -p /target%.*s && echo %s | base64 -d > /target%s && chmod %s /target%s",
                (int)(slash - path), path, b64.data ? b64.data : "", path, mode, path);
    late(g, cmd.data);
    rs_buf_free(&cmd);
    rs_buf_free(&b64);
}

/* "curtin in-target -- " COMMAND WORDS..., then "|| echo ... >&2" with
 * `failed`: a package that will not install is said in the installer's log,
 * and the restore goes on, because the files are worth more than any one
 * package. */
static void late_in_target(struct gen *g, const char *command, char *const *words, size_t n,
                           const char *failed)
{
    struct rs_buf b;
    size_t        i;

    if (n == 0)
    {
        return;
    }
    rs_buf_init(&b);
    rs_buf_addf(&b, "curtin in-target -- %s", command);
    for (i = 0; i < n; i++)
    {
        rs_buf_addc(&b, ' ');
        rs_shell_word(&b, words[i]);
    }
    rs_buf_addf(&b, " || echo 'restate: %s' >&2", failed);
    late(g, b.data);
    rs_buf_free(&b);
}

static bool flag_set(const struct rs_jval *obj, const char *key)
{
    const struct rs_jval *v = rs_jobject_get(obj, key);

    return v && v->type == RS_JBOOL && v->b;
}

/* The words of one language package manager's system-wide inventory. */
static char **system_words(const struct rs_jval *arr, const char *sep, const char *not_where,
                           size_t *n)
{
    char **words = NULL;
    size_t i;

    *n = 0;
    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        const char *name = rs_jobject_str(&arr->items[i], "name");
        const char *version = rs_jobject_str(&arr->items[i], "version");
        const char *where = rs_jobject_str(&arr->items[i], "where");

        if (!name || !where || rs_starts_with(where, "/home/") || rs_starts_with(where, "/root") ||
            (not_where && eq(where, not_where)))
        {
            continue;
        }
        words = rs_xreallocarray(words, *n + 1, sizeof(*words));
        words[(*n)++] = version ? rs_xasprintf("%s%s%s", name, sep, version) : rs_xstrdup(name);
    }
    return words;
}

static void free_words(char **words, size_t n)
{
    size_t i;

    for (i = 0; words && i < n; i++)
    {
        free(words[i]);
    }
    free(words);
}

/* Whether a snap's name or channel from the inventory is what snapd allows. */
static bool snap_word(const char *s)
{
    return s && s[0] != '\0' &&
           strspn(s, "abcdefghijklmnopqrstuvwxyz0123456789-./_") == strlen(s);
}

/*
 * The snaps, at the new system's first boot. Not in the installer's snaps
 * section: the desktop installer ignores it ("not interactive for desktop"),
 * and snapd does not run in the installer's chroot. So a service is left in
 * the new system that installs them once snapd has seeded, then removes
 * itself; what it says goes to the journal (journalctl -u restate-firstboot).
 */
static void first_boot_snaps(struct gen *g)
{
    static const char *const implied[] = { "base", "core", "os", "snapd", "gadget", "kernel" };
    static const char        unit[] =
        "[Unit]\n"
        "Description=restate: install the snaps the old machine had\n"
        "Wants=network-online.target\n"
        "After=network-online.target snapd.seeded.service\n"
        "ConditionPathExists=/usr/local/sbin/restate-firstboot\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/local/sbin/restate-firstboot\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";
    const struct rs_jval *arr = rs_jobject_get(g->o->packages, "snap");
    struct rs_buf         sh;
    size_t                i;
    size_t                j;
    size_t                any = 0;

    rs_buf_init(&sh);
    rs_buf_addstr(&sh, "#!/bin/sh\n"
                       "# Written by restate: the snaps the old machine had, installed once\n"
                       "# the new one is running, by restate-firstboot.service, which this\n"
                       "# then removes.\n"
                       "snap wait system seed.loaded\n");
    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        const struct rs_jval *sn = &arr->items[i];
        const char           *name = rs_jobject_str(sn, "name");
        const char           *type = rs_jobject_str(sn, "type");
        const char           *channel = rs_jobject_str(sn, "channel");
        const char           *kept = rs_jobject_str(sn, "kept");
        bool                  skip = !snap_word(name);

        for (j = 0; type && j < sizeof(implied) / sizeof(implied[0]); j++)
        {
            skip = skip || eq(type, implied[j]);
        }
        if (!type && name)
        {
            skip = skip || eq(name, "snapd") || eq(name, "bare") ||
                   (rs_starts_with(name, "core") &&
                    strspn(name + 4, "0123456789") == strlen(name + 4));
        }
        if (skip || (flag_set(sn, "local") && !kept))
        {
            continue;
        }
        if (flag_set(sn, "local"))
        {
            rs_buf_addstr(&sh, "snap install --dangerous ");
            rs_shell_word(&sh, kept);
        } else
        {
            rs_buf_addf(&sh, "snap install %s", name);
            if (snap_word(channel))
            {
                rs_buf_addf(&sh, " --channel=%s", channel);
            }
            if (flag_set(sn, "classic"))
            {
                rs_buf_addstr(&sh, " --classic");
            }
            if (flag_set(sn, "devmode"))
            {
                rs_buf_addstr(&sh, " --devmode");
            }
        }
        rs_buf_addf(&sh, " || echo 'restate: the snap %s did not install' >&2\n", name);
        if (flag_set(sn, "disabled"))
        {
            rs_buf_addf(&sh, "snap disable %s\n", name);
        }
        any++;
    }
    rs_buf_addstr(&sh, "systemctl disable restate-firstboot.service\n"
                       "rm -f /etc/systemd/system/restate-firstboot.service \"$0\"\n");
    if (any > 0)
    {
        late_comment(g, "The snaps, at the first boot: a service that installs them, then goes.");
        late_file(g, "/usr/local/sbin/restate-firstboot", sh.data, "0755");
        late_file(g, "/etc/systemd/system/restate-firstboot.service", unit, "0644");
        late(g, "mkdir -p /target/etc/systemd/system/multi-user.target.wants && "
                "ln -sf /etc/systemd/system/restate-firstboot.service "
                "/target/etc/systemd/system/multi-user.target.wants/restate-firstboot.service");
    }
    rs_buf_free(&sh);
}

/* The keys kept outside /etc, written into the new system from the inventory. */
static void late_keys(struct gen *g, const struct rs_jval *keys)
{
    size_t i;

    for (i = 0; keys && keys->type == RS_JARRAY && i < keys->n; i++)
    {
        const struct rs_jval *k = &keys->items[i];
        const char           *path = rs_jobject_str(k, "path");
        const char           *data = rs_jobject_str(k, "data");
        const char           *base;
        struct rs_buf         b;
        char                 *dir;
        char                 *target;

        if (!path || !data || rs_starts_with(path, "/etc/") ||
            strspn(data, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") !=
                strlen(data))
        {
            continue;
        }
        base = strrchr(path, '/');
        base = base ? base + 1 : path;
        if (rs_starts_with(base, "ubuntu-") || rs_starts_with(base, "debian-"))
        {
            continue;
        }
        dir = rs_xasprintf("/target%.*s", (int)(base - path), path);
        target = rs_xasprintf("/target%s", path);
        rs_buf_init(&b);
        rs_buf_addstr(&b, "mkdir -p ");
        rs_shell_word(&b, dir);
        rs_buf_addf(&b, " && echo %s | base64 -d > ", data);
        rs_shell_word(&b, target);
        late(g, b.data);
        rs_buf_free(&b);
        free(dir);
        free(target);
    }
}

/* The .deb files the image keeps, extracted into the new system's apt cache
 * and installed from there. */
static void late_kept_debs(struct gen *g, const char *img, const struct rs_jval *pkgs)
{
    struct rs_buf tar;
    char        **files = NULL;
    size_t        n = 0;
    size_t        i;

    rs_buf_init(&tar);
    rs_buf_addstr(&tar, "tar -xpzf ");
    rs_shell_word(&tar, img);
    rs_buf_addstr(&tar, " --numeric-owner -C /target --strip-components=2");
    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const char *kept = rs_jobject_str(&pkgs->items[i], "kept");
        char       *member;

        if (!kept || !rs_starts_with(kept, "/") ||
            (g->o->old_image && !rs_starts_with(kept, "/var/cache/apt/archives/")))
        {
            continue;
        }
        member = rs_xasprintf("restate/files%s", kept);
        rs_buf_addc(&tar, ' ');
        rs_shell_word(&tar, member);
        free(member);
        files = rs_xreallocarray(files, n + 1, sizeof(*files));
        files[n++] = rs_xstrdup(kept);
    }
    if (n > 0)
    {
        late_comment(g, "the packages no repository has, kept in the image");
        /* From an image in parts the kit has put them in place already. */
        if (g->o->old_image)
        {
            late(g, tar.data);
        }
        late_in_target(g, "env DEBIAN_FRONTEND=noninteractive apt-get install -y", files, n,
                       "the kept packages did not all install");
    }
    free_words(files, n);
    rs_buf_free(&tar);
}

/* What a person has to do after the first boot: per-user installations, and
 * what neither a repository nor the image has. */
static void first_boot(struct gen *g)
{
    const struct rs_jval *pk = g->o->packages;
    const struct rs_jval *pkgs = rs_jobject_get(rs_jobject_get(pk, "apt"), "packages");
    const struct rs_jval *arr = rs_jobject_get(pk, "snap");
    size_t                i;
    bool                  listed = false;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        const char *name = rs_jobject_str(&arr->items[i], "name");
        const char *kept = rs_jobject_str(&arr->items[i], "kept");

        /* A kept one the first-boot service installs. */
        if (!name || !flag_set(&arr->items[i], "local") || kept)
        {
            continue;
        }
        if (!listed)
        {
            late_comment(g, "Left for after the first boot (the build sheet has the commands):");
            listed = true;
        }
        rs_buf_addf(&g->late, "    #   the snap %s, from the file it was installed from\n", name);
    }
    for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
    {
        const struct rs_jval *p = &pkgs->items[i];

        if (flag_set(p, "manual") && eq(rs_jobject_str(p, "unavailable"), "local") &&
            !rs_jobject_str(p, "kept") && rs_jobject_str(p, "name"))
        {
            if (!listed)
            {
                late_comment(g, "Left for after the first boot (the build sheet has the commands):");
                listed = true;
            }
            rs_buf_addf(&g->late, "    #   %s, from its .deb (no repository has it)\n",
                        rs_jobject_str(p, "name"));
        }
    }
    {
        static const char *const per_user[] = { "pip", "pipx", "cargo" };
        size_t                   k;

        for (k = 0; k < sizeof(per_user) / sizeof(per_user[0]); k++)
        {
            arr = rs_jobject_get(pk, per_user[k]);
            for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
            {
                const char *where = rs_jobject_str(&arr->items[i], "where");

                if (where && (rs_starts_with(where, "/home/") || rs_starts_with(where, "/root")))
                {
                    if (!listed)
                    {
                        late_comment(g, "Left for after the first boot (the build sheet has the "
                                        "commands):");
                        listed = true;
                    }
                    rs_buf_addf(&g->late, "    #   %s's packages in the home directories, each "
                                "by its owner\n", per_user[k]);
                    break;
                }
            }
        }
    }
}

static void late_packages(struct gen *g)
{
    const struct rs_jval *pk = g->o->packages;
    const struct rs_jval *apt = rs_jobject_get(pk, "apt");
    const struct rs_jval *pkgs = rs_jobject_get(apt, "packages");
    const struct rs_jval *fp = rs_jobject_get(pk, "flatpak");
    const struct rs_jval *alts = rs_jobject_get(pk, "alternatives");
    const struct rs_jval *skip = NULL;
    const char           *img = g->o->image_at;
    struct rs_buf         b;
    char                **words;
    size_t                n;
    size_t                i;

    if (g->o->target == RS_TARGET_VM)
    {
        skip = rs_jobject_get(g->sys, "hardware_packages");
    } else if (g->o->target == RS_TARGET_METAL)
    {
        skip = rs_jobject_get(g->sys, "guest_packages");
    }
    late_comment(g, "The packages, then the files, from the image -- as the build sheet does it.");
    rs_buf_init(&b);
    rs_buf_addstr(&b, "test -f ");
    rs_shell_word(&b, img);
    rs_buf_addstr(&b, " || { echo 'restate: the image is not at ");
    rs_buf_addstr(&b, img);
    rs_buf_addstr(&b, "' >&2; exit 1; }");
    late(g, b.data);
    rs_buf_reset(&b);
    if (apt)
    {
        if (g->o->old_image)
        {
            rs_buf_addstr(&b, "tar -xpzf ");
            rs_shell_word(&b, img);
            rs_buf_addstr(&b, " --numeric-owner -C /target --strip-components=2 "
                              "restate/files/etc/apt");
        } else
        {
            /* The kit: /etc/apt and the kept packages, in seconds. */
            rs_image_part_command(&b, img, RS_IMAGE_KIT_PART, "/target", NULL);
        }
        late(g, b.data);
        late_keys(g, rs_jobject_get(apt, "keys"));
        late(g, "curtin in-target -- apt-get update || true");
        /* Each package looked up first, so one that cannot be had -- a
         * version gone, a repository refused -- does not sink the others. */
        rs_buf_reset(&b);
        rs_packages_apt_script(pk, skip, &b);
        late_file(g, "/var/tmp/restate-packages.sh", b.data, "0700");
        late(g, "curtin in-target -- sh /var/tmp/restate-packages.sh; "
                "rm -f /target/var/tmp/restate-packages.sh");
        late_kept_debs(g, img, pkgs);
        words = NULL;
        n = 0;
        for (i = 0; pkgs && pkgs->type == RS_JARRAY && i < pkgs->n; i++)
        {
            if (flag_set(&pkgs->items[i], "hold") && rs_jobject_str(&pkgs->items[i], "name"))
            {
                words = rs_xreallocarray(words, n + 1, sizeof(*words));
                words[n++] = rs_xstrdup(rs_jobject_str(&pkgs->items[i], "name"));
            }
        }
        late_in_target(g, "apt-mark hold", words, n, "the holds were not all set");
        free_words(words, n);
    }
    {
        const struct rs_jval *remotes = rs_jobject_get(fp, "remotes");
        const struct rs_jval *apps = rs_jobject_get(fp, "apps");

        for (i = 0; remotes && remotes->type == RS_JARRAY && i < remotes->n; i++)
        {
            const struct rs_jval *r = &remotes->items[i];
            char                 *w[2];

            if (!eq(rs_jobject_str(r, "scope"), "system") || !rs_jobject_str(r, "name") ||
                !rs_jobject_str(r, "url"))
            {
                continue;
            }
            w[0] = rs_xstrdup(rs_jobject_str(r, "name"));
            w[1] = rs_xstrdup(rs_jobject_str(r, "url"));
            late_in_target(g, "flatpak remote-add --if-not-exists", w, 2, "a flatpak remote was not added");
            free(w[0]);
            free(w[1]);
        }
        for (i = 0; apps && apps->type == RS_JARRAY && i < apps->n; i++)
        {
            const struct rs_jval *a = &apps->items[i];
            char                 *w[2];

            if (!eq(rs_jobject_str(a, "scope"), "system") || !rs_jobject_str(a, "remote") ||
                !rs_jobject_str(a, "id") || !rs_jobject_str(a, "branch"))
            {
                continue;
            }
            w[0] = rs_xstrdup(rs_jobject_str(a, "remote"));
            w[1] = rs_xasprintf("%s//%s", rs_jobject_str(a, "id"), rs_jobject_str(a, "branch"));
            late_in_target(g, "flatpak install -y --noninteractive", w, 2, "a flatpak app did not install");
            free(w[0]);
            free(w[1]);
        }
    }
    words = system_words(rs_jobject_get(pk, "pip"), "==", NULL, &n);
    late_in_target(g, "pip install --break-system-packages", words, n, "the Python packages did not all install");
    free_words(words, n);
    words = system_words(rs_jobject_get(pk, "npm"), "@", "/usr/lib/node_modules", &n);
    late_in_target(g, "npm install -g", words, n, "the npm packages did not all install");
    free_words(words, n);
    words = system_words(rs_jobject_get(pk, "gem"), ":", NULL, &n);
    late_in_target(g, "gem install", words, n, "the gems did not all install");
    free_words(words, n);
    for (i = 0; alts && alts->type == RS_JARRAY && i < alts->n; i++)
    {
        char *w[2];

        if (!rs_jobject_str(&alts->items[i], "name") || !rs_jobject_str(&alts->items[i], "path"))
        {
            continue;
        }
        w[0] = rs_xstrdup(rs_jobject_str(&alts->items[i], "name"));
        w[1] = rs_xstrdup(rs_jobject_str(&alts->items[i], "path"));
        late_in_target(g, "update-alternatives --set", w, 2, "an alternative was not set");
        free(w[0]);
        free(w[1]);
    }

    late_comment(g, "The files, over the packages' own; the installer's fstab and crypttab stay.");
    rs_buf_reset(&b);
    if (g->o->old_image)
    {
        rs_buf_addstr(&b, "tar -xpzf ");
        rs_shell_word(&b, img);
        rs_buf_addstr(&b, " --numeric-owner -C /target --strip-components=2 "
                          "--exclude=restate/files/etc/fstab --exclude=restate/files/etc/crypttab "
                          "restate/files");
    } else
    {
        /* restate restore, from the kit -- each file checked against the
         * index before it lands -- or tar, if the kit had no restate. */
        rs_image_restore_command(&b, img, "/target", true);
    }
    late(g, b.data);
    late(g, "curtin in-target -- update-initramfs -u -k all");
    late(g, "curtin in-target -- update-grub");
    rs_buf_free(&b);
    first_boot(g);
}

static void extras(struct gen *g)
{
    const struct rs_jval *hwp = rs_jobject_get(g->sys, "hardware_packages");
    size_t                i;
    bool                  md = false;

    if (g->o->target == RS_TARGET_VM)
    {
        rs_buf_addstr(g->out, "  packages:\n    - \"qemu-guest-agent\"\n");
    } else if (g->o->target == RS_TARGET_METAL)
    {
        rs_buf_addstr(g->out, "  packages:\n    - \"intel-microcode\"    # or amd64-microcode, for the new CPU\n");
    }
    for (i = 0; i < g->l.nvols; i++)
    {
        md = md || (!g->l.vols[i].foreign && g->l.vols[i].kind == RS_VOL_MD);
    }
    if (g->o->target == RS_TARGET_VM && hwp && hwp->type == RS_JARRAY)
    {
        bool any = false;

        for (i = 0; i < hwp->n; i++)
        {
            if (hwp->items[i].type != RS_JSTRING || (md && eq(hwp->items[i].s, "mdadm")))
            {
                continue;
            }
            if (!any)
            {
                late_comment(g, "real hardware's packages, of no use in a VM");
                any = true;
            }
            {
                struct rs_buf cmd;

                rs_buf_init(&cmd);
                rs_buf_addstr(&cmd, "curtin in-target -- apt-get purge -y ");
                rs_shell_word(&cmd, hwp->items[i].s);
                rs_buf_addstr(&cmd, " || true");
                late(g, cmd.data);
                rs_buf_free(&cmd);
            }
        }
    }
}

/* Every late-command, under one key. */
static void late_commands(struct gen *g)
{
    if (g->o->packages && g->o->image_at)
    {
        late_packages(g);
    }
    if (g->o->packages)
    {
        first_boot_snaps(g);
    }
    if (g->late.len)
    {
        rs_buf_addstr(g->out, "  late-commands:\n");
        rs_buf_addstr(g->out, g->late.data);
    }
}

bool rs_autoinstall(const struct rs_jval *machine, const struct rs_auto_opts *o,
                    struct rs_buf *out, struct rs_buf *err)
{
    struct gen g;
    size_t     i;

    memset(&g, 0, sizeof(g));
    g.machine = machine;
    g.sys = rs_jobject_get(machine, "system");
    g.o = o;
    g.out = out;
    if (!eq(rs_jobject_str(g.sys, "id"), "ubuntu"))
    {
        rs_buf_addf(err, "autoinstall files are for Ubuntu; this machine is %s",
                    rs_jobject_str(g.sys, "id") ? rs_jobject_str(g.sys, "id") : "of an unknown system");
        return false;
    }
    if (!rs_layout_build(machine, &g.l))
    {
        rs_buf_addstr(err, "the machine description has no disks to rebuild (it is made on "
                           "Linux, from the running system or an image captured from its root)");
        rs_layout_free(&g.l);
        return false;
    }
    for (i = 0; i < g.l.nvols; i++)
    {
        if (g.l.vols[i].foreign && g.l.vols[i].kind == RS_VOL_PART && o->target == RS_TARGET_SAME &&
            !g.l.disks[g.l.vols[i].disk].removable)
        {
            g.keep_table = true;
        }
    }
    g.made = rs_xcalloc(g.l.nvols + 1, sizeof(*g.made));
    g.vg_made = rs_xcalloc(g.l.nvgs + 1, sizeof(*g.vg_made));
    header(&g);
    identity(&g);
    network(&g);
    storage(&g);
    rs_buf_init(&g.late);
    extras(&g);
    late_commands(&g);
    rs_buf_free(&g.late);
    free(g.made);
    free(g.vg_made);
    rs_layout_free(&g.l);
    return true;
}
