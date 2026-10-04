/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "autoinstall.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
                  "# After the first boot, put the files back as the build sheet describes\n"
                  "# (restate buildsheet). The installer formats the volumes itself, so keep its\n"
                  "# /etc/fstab and /etc/crypttab rather than the restored ones.\n");
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
    kv(g, 4, "realname", "restate");
    kv(g, 4, "username", "restate");
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
                rs_buf_addstr(g->out, "  late-commands:\n");
                rs_buf_addstr(g->out, "    # real hardware's packages, of no use in a VM\n");
                any = true;
            }
            rs_buf_addstr(g->out, "    - ");
            {
                char *cmd = rs_xasprintf("curtin in-target -- apt-get purge -y %s || true",
                                         hwp->items[i].s);

                q(g->out, cmd);
                free(cmd);
            }
            rs_buf_addc(g->out, '\n');
        }
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
    extras(&g);
    free(g.made);
    free(g.vg_made);
    rs_layout_free(&g.l);
    return true;
}
