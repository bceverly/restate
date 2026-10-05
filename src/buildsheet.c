/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "buildsheet.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "installer.h"

#define MIB ((uint64_t)1024 * 1024)
#define GIB (MIB * 1024)

/* Everything one sheet needs while it is written. */
struct sheet {
    const struct rs_jval       *machine;
    const struct rs_jval       *sys;
    const struct rs_sheet_opts *o;
    struct rs_layout            l;
    struct rs_buf              *out;
    struct rs_installer         in;
    bool                        have_installer;
    bool                        any_foreign;
    bool                        shared_esp;   /* an ESP another system boots from too */
    unsigned                   *newnum;       /* per volume: its partition number now */
    bool                       *done;         /* per volume: created by the steps so far */
    bool                       *vg_done;
    struct rs_buf               notes;
    unsigned                    step;
};

static void say(struct sheet *s, const char *fmt, ...) RESTATE_PRINTF(2, 3);

static void say(struct sheet *s, const char *fmt, ...)
{
    va_list ap;
    char   *text;

    va_start(ap, fmt);
    text = rs_xvasprintf(fmt, ap);
    va_end(ap);
    rs_buf_addstr(s->out, text);
    rs_buf_add(s->out, "\n", 1);
    free(text);
}

static void note(struct sheet *s, const char *fmt, ...) RESTATE_PRINTF(2, 3);

static void note(struct sheet *s, const char *fmt, ...)
{
    va_list ap;
    char   *text;

    va_start(ap, fmt);
    text = rs_xvasprintf(fmt, ap);
    va_end(ap);
    rs_buf_addf(&s->notes, "  - %s\n", text);
    free(text);
}

static void heading(struct sheet *s, const char *title)
{
    size_t i;
    size_t n;

    s->step++;
    rs_buf_addf(s->out, "\n%u. %s\n", s->step, title);
    n = strlen(title) + (s->step >= 10 ? 4 : 3);
    for (i = 0; i < n; i++)
    {
        rs_buf_add(s->out, "-", 1);
    }
    rs_buf_add(s->out, "\n", 1);
}

static const char *size_text(uint64_t bytes, char *buf, size_t len)
{
    rs_human_size(bytes, buf, len);
    return buf;
}

static bool eq(const char *a, const char *b)
{
    return a && b && strcmp(a, b) == 0;
}

static bool is_esp(const struct rs_vol *v)
{
    return rs_ptype_is(v->ptype, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b") ||
           rs_ptype_is(v->ptype, "0xef");
}

/* Whether a volume is rebuilt at all for this target. */
static bool kept(const struct sheet *s, size_t i)
{
    return !s->l.vols[i].foreign;
}

/* The shell expression for a volume's device, in the commands. */
static char *dev_expr(const struct sheet *s, size_t i)
{
    const struct rs_vol *v = &s->l.vols[i];

    if (v->kind == RS_VOL_PART && v->disk != SIZE_MAX)
    {
        return rs_xasprintf("\"$(part \"$DISK%zu\" %u)\"", v->disk + 1,
                            s->newnum[i] ? s->newnum[i] : v->number);
    }
    if (v->kind == RS_VOL_DISK && v->disk != SIZE_MAX)
    {
        return rs_xasprintf("\"$DISK%zu\"", v->disk + 1);
    }
    return rs_xstrdup(v->path);
}

/* The name of the disk variable's default for this target. */
static char *disk_default(const struct sheet *s, size_t d)
{
    if (s->o->target == RS_TARGET_VM)
    {
        return rs_xasprintf("/dev/vd%c", (char)('a' + (d % 26)));
    }
    if (s->o->target == RS_TARGET_METAL)
    {
        return rs_xstrdup("/dev/CHANGE-ME");
    }
    return rs_xasprintf("/dev/%s", s->l.disks[d].name);
}

/* GPT attribute bits as sfdisk spells them. */
static void gpt_attrs(const char *flags, struct rs_buf *b)
{
    uint64_t bits;
    unsigned i;
    bool     first = true;

    if (!flags || !rs_starts_with(flags, "0x"))
    {
        return;
    }
    bits = strtoull(flags + 2, NULL, 16);
    for (i = 0; i < 64; i++)
    {
        const char *name = NULL;
        char        guid[16];

        if (!(bits & ((uint64_t)1 << i)))
        {
            continue;
        }
        if (i == 0)
        {
            name = "RequiredPartition";
        } else if (i == 1)
        {
            name = "NoBlockIOProtocol";
        } else if (i == 2)
        {
            name = "LegacyBIOSBootable";
        } else if (i >= 48)
        {
            (void)snprintf(guid, sizeof(guid), "GUID:%u", i);
            name = guid;
        }
        if (name)
        {
            rs_buf_addf(b, "%s%s", first ? "" : ",", name);
            first = false;
        }
    }
}

/* A GPT name sfdisk can take between double quotes. */
static char *clean_name(const char *name)
{
    char  *c = rs_xstrdup(name ? name : "");
    size_t i;

    for (i = 0; c[i] != '\0'; i++)
    {
        if (c[i] == '"' || c[i] == '\\' || (unsigned char)c[i] < 0x20)
        {
            c[i] = ' ';
        }
    }
    return c;
}

/* ------------------------------------------------------------------------- */
/* The sections                                                              */
/* ------------------------------------------------------------------------- */

static void intro(struct sheet *s)
{
    const struct rs_jval *hw = rs_jobject_get(s->machine, "hardware");
    const char           *host = rs_jobject_str(s->sys, "hostname");
    const char           *pretty = rs_jobject_str(s->sys, "pretty_name");
    const char           *type = rs_jobject_str(s->sys, "type");
    const char           *virt = rs_jobject_str(s->sys, "virtualization");
    const char           *vendor = rs_jobject_str(hw, "sys_vendor");
    const char           *product = rs_jobject_str(hw, "product_version");
    const char           *model = rs_jobject_str(hw, "product_name");
    const char           *cpu = rs_jobject_str(hw, "cpu");
    const struct rs_jval *mem = rs_jobject_get(hw, "memory");
    const struct rs_jval *cpus = rs_jobject_get(hw, "cpus");
    char                  buf[32];
    static const char    *const targets[] = {
        "this machine, or one like it -- the original sizes, exactly",
        "a virtual machine -- the Linux volumes only, sized to what they use",
        "other hardware -- the Linux volumes only, at their original sizes"
    };

    say(s, "restate build sheet: %s", host ? host : "(no host name recorded)");
    say(s, "%s", "==========================================================================");
    say(s, "%s", "");
    {
        const char *id = rs_jobject_str(s->sys, "id");
        const char *ver = rs_jobject_str(s->sys, "version");

        if (pretty)
        {
            say(s, "  System     %s%s%s", pretty, type ? ", " : "", type ? type : "");
        } else
        {
            say(s, "  System     %s%s%s%s%s", id ? id : "(unknown)", ver ? " " : "", ver ? ver : "",
                type ? ", " : "", type ? type : "");
        }
    }
    if (vendor || model)
    {
        say(s, "  Hardware   %s %s%s%s%s", vendor ? vendor : "", product ? product : (model ? model : ""),
            (product && model) ? " (" : "", (product && model) ? model : "", (product && model) ? ")" : "");
    }
    if (virt && strcmp(virt, "none") != 0)
    {
        say(s, "             a virtual machine (%s)", virt);
    }
    if (cpu || cpus || mem)
    {
        say(s, "             %s%s%" PRIu64 " CPUs, %s memory", cpu ? cpu : "", cpu ? ", " : "",
            cpus ? cpus->u : 0, size_text(mem ? mem->u : 0, buf, sizeof(buf)));
    }
    {
        bool        uefi = eq(s->l.firmware, "uefi");
        const char *mode = uefi ? "UEFI" : (s->l.firmware ? "BIOS (legacy)" : "(unknown)");
        const char *sb = uefi ? (s->l.secure_boot ? ", Secure Boot on" : ", Secure Boot off") : "";

        say(s, "  Firmware   %s%s", mode, sb);
    }
    say(s, "  Rebuilt as %s", targets[s->o->target]);
    say(s, "  Made by    restate %s%s%s", s->o->version ? s->o->version : "",
        s->o->image ? " from " : " from the running system", s->o->image ? s->o->image : "");
    say(s, "%s", "");
    say(s, "%s", "Read it all before starting. The commands below are printed, not run: each");
    say(s, "%s", "one destroys whatever is on the device it names, so check every device name");
    say(s, "%s", "against `lsblk` before running anything.");
}

static void needs(struct sheet *s)
{
    char   buf[32];
    char   buf2[32];
    size_t d;

    heading(s, "What you need");
    for (d = 0; d < s->l.ndisks; d++)
    {
        const struct rs_disk *disk = &s->l.disks[d];
        uint64_t              need = 0;
        size_t                i;

        if (disk->removable)
        {
            continue;
        }
        for (i = 0; i < s->l.nvols; i++)
        {
            const struct rs_vol *v = &s->l.vols[i];

            if (v->disk == d && (v->kind == RS_VOL_PART || v->kind == RS_VOL_DISK))
            {
                uint64_t fit = rs_layout_fit(&s->l, i, s->o->target);

                if (s->o->target == RS_TARGET_SAME)
                {
                    need = v->start + v->size > need ? v->start + v->size : need;
                } else
                {
                    need += fit;
                }
            }
        }
        if (s->o->target != RS_TARGET_SAME)
        {
            need = (need + 2 * MIB + GIB - 1) / GIB * GIB;
        }
        if (need == 0)
        {
            continue;
        }
        if (s->o->target == RS_TARGET_SAME)
        {
            say(s, "  - Disk %zu: at least %s, as the original was (%s%s%s, %s).", d + 1,
                size_text(need, buf, sizeof(buf)), disk->name, disk->model ? ", " : "",
                disk->model ? disk->model : "", size_text(disk->size, buf2, sizeof(buf2)));
        } else
        {
            say(s, "  - Disk %zu: at least %s (it was %s, %s).", d + 1, size_text(need, buf, sizeof(buf)),
                disk->name, size_text(disk->size, buf2, sizeof(buf2)));
        }
    }
    if (s->l.firmware && strcmp(s->l.firmware, "uefi") == 0)
    {
        say(s, "%s", "  - Firmware set to boot UEFI, not legacy BIOS.");
    } else if (s->l.firmware)
    {
        say(s, "%s", "  - Firmware set to boot legacy BIOS (CSM), as the original did.");
    }
    if (s->have_installer)
    {
        char *iso = s->in.point ? rs_xasprintf("ubuntu-%s-%s-%s.iso", s->in.point, s->in.flavor, s->in.arch)
                                : rs_xstrdup(s->in.pattern);

        say(s, "  - The installer: %s, on a USB stick.", s->in.description);
        say(s, "      restate installer fetch%s%s   # downloads and verifies %s", s->o->image ? " " : "",
            s->o->image ? s->o->image : "", iso);
        free(iso);
    } else
    {
        say(s, "%s", "  - The installer for this system: see `restate installer`.");
    }
    say(s, "  - The image to restore%s%s, on a disk the new machine can read.",
        s->o->image ? ": " : "", s->o->image ? s->o->image : "");
}

static void tree_line(struct sheet *s, size_t i, int depth) /* NOLINT(misc-no-recursion) */
{
    const struct rs_vol *v = &s->l.vols[i];
    char                 buf[32];
    char                 what[128] = "";
    size_t               kids[32];
    size_t               n;
    size_t               k;
    const char          *pt = rs_ptype_name(v->ptype);

    if (v->fstype)
    {
        (void)snprintf(what, sizeof(what), "%s%s%s", v->fstype,
                       v->version && eq(v->fstype, "crypto_LUKS") ? " v" : "",
                       v->version && eq(v->fstype, "crypto_LUKS") ? v->version : "");
    }
    if (!pt)
    {
        if (v->kind == RS_VOL_LUKS)
        {
            pt = "LUKS mapping";
        } else if (v->kind == RS_VOL_LV)
        {
            pt = "LVM volume";
        } else if (v->kind == RS_VOL_MD)
        {
            pt = v->level ? v->level : "RAID";
        } else
        {
            pt = "";
        }
    }
    rs_buf_addf(s->out, "  %*s%-*s %9s  %-20s %-14s %s%s%s\n", depth * 2, "", 22 - depth * 2,
                v->kind == RS_VOL_PART ? v->name : v->path,
                v->size ? size_text(v->size, buf, sizeof(buf)) : "", pt, what,
                v->mountpoint ? v->mountpoint : "", v->foreign ? "  -- not rebuilt: " : "",
                v->foreign ? v->foreign_why : "");
    n = rs_layout_children(&s->l, i, kids, 32);
    for (k = 0; k < n; k++)
    {
        /* A volume with several parents (an array, a group) is shown under
         * the first only. */
        if (s->l.vols[kids[k]].parents[0] == i && depth < 6)
        {
            tree_line(s, kids[k], depth + 1);
        }
    }
}

static void layout(struct sheet *s)
{
    size_t d;
    size_t i;
    char   buf[32];

    heading(s, "The disk layout, as it was");
    for (d = 0; d < s->l.ndisks; d++)
    {
        const struct rs_disk *disk = &s->l.disks[d];

        say(s, "%s%s %s  %s%s%s", d ? "\n" : "", disk->name, size_text(disk->size, buf, sizeof(buf)),
            disk->table ? (strcmp(disk->table, "dos") == 0 ? "MBR" : "GPT") : "no partition table",
            disk->model ? ", " : "", disk->model ? disk->model : "");
        for (i = 0; i < s->l.nvols; i++)
        {
            if (s->l.vols[i].disk == d && s->l.vols[i].nparents == 0)
            {
                tree_line(s, i, 1);
            }
        }
    }
}

static void shell(struct sheet *s)
{
    size_t d;
    bool   uefi = s->l.firmware && strcmp(s->l.firmware, "uefi") == 0;

    heading(s, "Boot the installer and open a root shell");
    if (s->o->target == RS_TARGET_VM)
    {
        say(s, "%s", "Start the virtual machine; it boots the installer. On the desktop installer,");
    } else
    {
        say(s, "%s", "Boot the new machine from the USB stick. On the desktop installer,");
    }
    say(s, "%s", "choose \"Try Ubuntu\" and open a terminal; on the server installer, press");
    say(s, "%s", "Ctrl-Alt-F2.");
    if (uefi)
    {
        say(s, "%s", "Check it booted in UEFI mode -- this directory exists only then:");
        say(s, "%s", "");
        say(s, "%s", "    ls /sys/firmware/efi");
    }
    say(s, "%s", "");
    say(s, "%s", "Then become root, name the disks, and define a helper for partition names:");
    say(s, "%s", "");
    say(s, "%s", "    sudo -i");
    say(s, "%s", "    lsblk -o NAME,SIZE,MODEL,SERIAL");
    for (d = 0; d < s->l.ndisks; d++)
    {
        char *def;
        char  buf[32];

        if (s->l.disks[d].removable)
        {
            continue;
        }
        def = disk_default(s, d);
        say(s, "    DISK%zu=%-14s # was %s: %s%s%s", d + 1, def, s->l.disks[d].name,
            size_text(s->l.disks[d].size, buf, sizeof(buf)), s->l.disks[d].model ? ", " : "",
            s->l.disks[d].model ? s->l.disks[d].model : "");
        free(def);
    }
    say(s, "%s", "    part() { case \"$1\" in *[0-9]) echo \"${1}p$2\" ;; *) echo \"$1$2\" ;; esac; }");
    if (s->o->target == RS_TARGET_METAL)
    {
        say(s, "%s", "");
        say(s, "%s", "Set each DISK to the new machine's disk from the lsblk listing: the names on");
        say(s, "%s", "other hardware are not knowable in advance, and /dev/CHANGE-ME fails safely.");
    }
}

static void partition(struct sheet *s)
{
    size_t d;
    size_t i;

    heading(s, "Partition the disks");
    if (s->any_foreign && s->o->target == RS_TARGET_SAME)
    {
        say(s, "%s", "This disk also holds another operating system. Two ways from here:");
        say(s, "%s", "");
        say(s, "%s", "  A. A new or blank disk: run this step. Only the Linux volumes are filled");
        say(s, "%s", "     in afterwards; the other system's partitions are recreated empty, at");
        say(s, "%s", "     the same places, ready for its own restore.");
        say(s, "%s", "  B. The same disk, keeping the other system: SKIP this step, and skip");
        say(s, "%s", "     every command marked \"new disk only\" below. The partition table stays,");
        say(s, "%s", "     and with it the other system and its boot loader.");
        say(s, "%s", "");
    }
    for (d = 0; d < s->l.ndisks; d++)
    {
        const struct rs_disk *disk = &s->l.disks[d];
        bool                  gpt;
        bool                  any = false;
        unsigned              num = 0;

        if (!disk->table || disk->removable)
        {
            continue;
        }
        for (i = 0; i < s->l.nvols; i++)
        {
            any = any || (s->l.vols[i].disk == d && s->l.vols[i].kind == RS_VOL_PART &&
                          rs_layout_fit(&s->l, i, s->o->target) > 0);
        }
        if (!any)
        {
            continue;
        }
        gpt = strcmp(disk->table, "dos") != 0;
        say(s, "    wipefs --all \"$DISK%zu\"", d + 1);
        say(s, "    sfdisk \"$DISK%zu\" <<'RESTATE_END'", d + 1);
        say(s, "    label: %s", gpt ? "gpt" : "dos");
        if (s->o->target == RS_TARGET_SAME && disk->table_uuid)
        {
            say(s, "    label-id: %s%s", gpt ? "" : "0x", disk->table_uuid);
        }
        if (s->o->target == RS_TARGET_SAME)
        {
            say(s, "    unit: sectors");
            say(s, "    sector-size: %" PRIu64, disk->sector);
        }
        say(s, "%s", "    ");
        for (i = 0; i < s->l.nvols; i++)
        {
            const struct rs_vol *v = &s->l.vols[i];
            uint64_t             fit = rs_layout_fit(&s->l, i, s->o->target);
            struct rs_buf        line;

            if (v->disk != d || v->kind != RS_VOL_PART || fit == 0)
            {
                continue;
            }
            num++;
            s->newnum[i] = s->o->target == RS_TARGET_SAME ? v->number : num;
            rs_buf_init(&line);
            {
                char       *def = disk_default(s, d);
                const char *base = s->o->target == RS_TARGET_VM ? def + 5 : disk->name;
                size_t      bl = strlen(base);

                rs_buf_addf(&line, "    %s%s%u : ", base,
                            (bl > 0 && base[bl - 1] >= '0' && base[bl - 1] <= '9') ? "p" : "",
                            s->newnum[i]);
                free(def);
            }
            if (s->o->target == RS_TARGET_SAME)
            {
                rs_buf_addf(&line, "start=%" PRIu64 ", size=%" PRIu64, v->start / disk->sector,
                            v->size / disk->sector);
            } else
            {
                rs_buf_addf(&line, "size=%" PRIu64 "MiB", (fit + MIB - 1) / MIB);
            }
            if (v->ptype)
            {
                rs_buf_addf(&line, ", type=%s", rs_starts_with(v->ptype, "0x") ? v->ptype + 2 : v->ptype);
            }
            if (gpt && v->puuid)
            {
                rs_buf_addf(&line, ", uuid=%s", v->puuid);
            }
            if (gpt && v->pname)
            {
                char *name = clean_name(v->pname);

                rs_buf_addf(&line, ", name=\"%s\"", name);
                free(name);
            }
            if (gpt && v->pflags)
            {
                struct rs_buf a;

                rs_buf_init(&a);
                gpt_attrs(v->pflags, &a);
                if (a.len)
                {
                    rs_buf_addf(&line, ", attrs=\"%s\"", a.data);
                }
                rs_buf_free(&a);
            } else if (!gpt && v->pflags && strcmp(v->pflags, "0x80") == 0)
            {
                rs_buf_addstr(&line, ", bootable");
            }
            say(s, "%s", line.data);
            rs_buf_free(&line);
            s->done[i] = true;
        }
        say(s, "%s", "    RESTATE_END");
        say(s, "%s", "");
    }
    for (i = 0; i < s->l.nvols; i++)
    {
        if (s->l.vols[i].kind == RS_VOL_DISK && kept(s, i))
        {
            s->done[i] = true;
        }
    }
    say(s, "%s", "Check the result with `lsblk` before going on.");
}

static void mkfs(struct sheet *s, size_t i)
{
    const struct rs_vol *v = &s->l.vols[i];
    char                *dev = dev_expr(s, i);
    struct rs_buf        c;
    const char          *mark = "";

    if (s->shared_esp && is_esp(v))
    {
        mark = "      # new disk only: it holds the other system's boot loader too";
    }
    rs_buf_init(&c);
    if (eq(v->fstype, "ext4") || eq(v->fstype, "ext3") || eq(v->fstype, "ext2"))
    {
        rs_buf_addf(&c, "mkfs.%s -F", v->fstype);
        if (v->uuid)
        {
            rs_buf_addf(&c, " -U %s", v->uuid);
        }
        if (v->label)
        {
            rs_buf_addf(&c, " -L '%s'", v->label);
        }
    } else if (eq(v->fstype, "xfs"))
    {
        rs_buf_addstr(&c, "mkfs.xfs -f");
        if (v->uuid)
        {
            rs_buf_addf(&c, " -m uuid=%s", v->uuid);
        }
        if (v->label)
        {
            rs_buf_addf(&c, " -L '%s'", v->label);
        }
    } else if (eq(v->fstype, "btrfs"))
    {
        rs_buf_addstr(&c, "mkfs.btrfs -f");
        if (v->uuid)
        {
            rs_buf_addf(&c, " -U %s", v->uuid);
        }
        if (v->label)
        {
            rs_buf_addf(&c, " -L '%s'", v->label);
        }
        note(s, "%s is btrfs: its subvolumes are not recorded in this version; create the "
             "ones /etc/fstab mounts (subvol=...) before installing.", v->path);
    } else if (eq(v->fstype, "vfat"))
    {
        rs_buf_addf(&c, "mkfs.vfat -F %s", (v->version && strstr(v->version, "16")) ? "16" : "32");
        if (v->uuid && strlen(v->uuid) == 9 && v->uuid[4] == '-')
        {
            rs_buf_addf(&c, " -i %.4s%.4s", v->uuid, v->uuid + 5);
        }
        if (v->label)
        {
            rs_buf_addf(&c, " -n '%s'", v->label);
        }
    } else if (eq(v->fstype, "swap"))
    {
        rs_buf_addstr(&c, "mkswap");
        if (v->uuid)
        {
            rs_buf_addf(&c, " -U %s", v->uuid);
        }
        if (v->label)
        {
            rs_buf_addf(&c, " -L '%s'", v->label);
        }
    } else if (eq(v->fstype, "exfat"))
    {
        rs_buf_addstr(&c, "mkfs.exfat");
        if (v->label)
        {
            rs_buf_addf(&c, " -L '%s'", v->label);
        }
        note(s, "%s is exFAT, whose volume serial mkfs.exfat cannot set: change any "
             "/etc/fstab line naming it by UUID after the restore.", v->path);
    } else if (v->fstype && eq(v->usage, "filesystem"))
    {
        note(s, "%s holds %s, which this sheet does not know how to recreate; make it by "
             "hand, with UUID %s.", v->path, v->fstype, v->uuid ? v->uuid : "(unknown)");
    }
    if (c.len)
    {
        say(s, "    %s %s%s", c.data, dev, mark);
    }
    rs_buf_free(&c);
    free(dev);
}

static void luks(struct sheet *s, size_t i)
{
    const struct rs_vol *v = &s->l.vols[i];
    char                *dev = dev_expr(s, i);
    size_t               kids[4];
    size_t               n = rs_layout_children(&s->l, i, kids, 4);
    const char          *name = n > 0 ? s->l.vols[kids[0]].name : NULL;
    struct rs_buf        c;

    rs_buf_init(&c);
    rs_buf_addf(&c, "cryptsetup luksFormat --batch-mode --type luks%s",
                eq(v->version, "1") ? "1" : "2");
    if (v->uuid)
    {
        rs_buf_addf(&c, " --uuid %s", v->uuid);
    }
    if (v->cipher)
    {
        rs_buf_addf(&c, " --cipher %s", v->cipher);
    }
    if (v->key_size)
    {
        rs_buf_addf(&c, " --key-size %" PRIu64, v->key_size);
    }
    say(s, "    %s %s", c.data, dev);
    rs_buf_free(&c);
    if (!v->cipher)
    {
        note(s, "The cipher of %s was not recorded -- the description was taken without "
             "root, which reading a LUKS header needs -- so cryptsetup's default is used.",
             v->path);
    }
    if (name)
    {
        say(s, "    cryptsetup open %s %s", dev, name);
        s->done[kids[0]] = true;
    }
    free(dev);
}

static void raid(struct sheet *s, size_t md)
{
    const struct rs_vol *v = &s->l.vols[md];
    struct rs_buf        c;
    size_t               k;

    rs_buf_init(&c);
    rs_buf_addf(&c, "mdadm --create %s --run --level=%s --raid-devices=%zu", v->path,
                v->level ? v->level : "raid1", v->nparents);
    if (v->metadata)
    {
        rs_buf_addf(&c, " --metadata=%s", v->metadata);
    }
    if (v->md_uuid)
    {
        rs_buf_addf(&c, " --uuid=%s", v->md_uuid);
    }
    if (v->chunk && !eq(v->level, "raid1"))
    {
        rs_buf_addf(&c, " --chunk=%" PRIu64 "K", v->chunk / 1024);
    }
    for (k = 0; k < v->nparents; k++)
    {
        char *dev = dev_expr(s, v->parents[k]);

        rs_buf_addf(&c, " %s", dev);
        free(dev);
    }
    say(s, "    %s", c.data);
    rs_buf_free(&c);
    s->done[md] = true;
}

static void lvm(struct sheet *s, size_t g)
{
    const struct rs_vg *vg = &s->l.vgs[g];
    size_t              k;
    size_t              i;
    bool                exact = s->o->target == RS_TARGET_SAME &&
                                !strstr(vg->metadata, "RESTATE_LVM_END") &&
                                !strstr(vg->metadata, "thin-pool");
    struct rs_buf       c;

    s->vg_done[g] = true;
    if (exact)
    {
        /* The group's own metadata backup, put back as it was: every volume
         * at its old extents, with its old UUIDs. */
        say(s, "    cat > /tmp/restate-%s.vg <<'RESTATE_LVM_END'", vg->name);
        rs_buf_addstr(s->out, vg->metadata);
        if (vg->metadata[0] && vg->metadata[strlen(vg->metadata) - 1] != '\n')
        {
            rs_buf_add(s->out, "\n", 1);
        }
        say(s, "%s", "RESTATE_LVM_END");
        for (k = 0; k < vg->npvs; k++)
        {
            char *dev = vg->pvs[k].vol != SIZE_MAX ? dev_expr(s, vg->pvs[k].vol)
                                                   : rs_xstrdup(vg->pvs[k].device);

            say(s, "    pvcreate --yes --uuid %s --restorefile /tmp/restate-%s.vg %s",
                vg->pvs[k].id ? vg->pvs[k].id : "(unknown)", vg->name, dev);
            free(dev);
        }
        say(s, "    vgcfgrestore -f /tmp/restate-%s.vg %s", vg->name, vg->name);
        say(s, "    vgchange -ay %s", vg->name);
    } else
    {
        if (strstr(vg->metadata, "thin-pool"))
        {
            note(s, "Volume group %s has a thin pool, which these commands recreate as "
                 "ordinary volumes; see lvmthin(7) to make it a pool again.", vg->name);
        }
        rs_buf_init(&c);
        for (k = 0; k < vg->npvs; k++)
        {
            char *dev = vg->pvs[k].vol != SIZE_MAX ? dev_expr(s, vg->pvs[k].vol)
                                                   : rs_xstrdup(vg->pvs[k].device);

            say(s, "    pvcreate --yes %s", dev);
            rs_buf_addf(&c, " %s", dev);
            free(dev);
        }
        say(s, "    vgcreate %s%s", vg->name, c.data ? c.data : "");
        rs_buf_free(&c);
        for (i = 0; i < s->l.nvols; i++)
        {
            if (s->l.vols[i].vg == g && s->l.vols[i].lvname && !s->l.vols[i].foreign)
            {
                uint64_t fit = rs_layout_fit(&s->l, i, s->o->target);

                say(s, "    lvcreate --yes -n %s -L %" PRIu64 "M %s", s->l.vols[i].lvname,
                    (fit + MIB - 1) / MIB, vg->name);
            }
        }
    }
    for (i = 0; i < s->l.nvols; i++)
    {
        if (s->l.vols[i].vg == g)
        {
            s->done[i] = true;
        }
    }
}

/* Every PV of a group created, so the group can be. */
static bool vg_ready(const struct sheet *s, size_t g)
{
    size_t k;

    for (k = 0; k < s->l.vgs[g].npvs; k++)
    {
        if (s->l.vgs[g].pvs[k].vol != SIZE_MAX && !s->done[s->l.vgs[g].pvs[k].vol])
        {
            return false;
        }
    }
    return true;
}

static void volumes(struct sheet *s)
{
    bool  *handled = rs_xcalloc(s->l.nvols, sizeof(*handled));
    bool   progress = true;
    size_t i;
    size_t g;

    heading(s, "Encryption, RAID, LVM, filesystems and swap");
    say(s, "%s", "In this order: each step needs the devices the one before it made. The");
    say(s, "%s", "UUIDs are the original ones, so the /etc/fstab and /etc/crypttab restored");
    say(s, "%s", "later name these volumes without editing. luksFormat asks for a passphrase:");
    say(s, "%s", "nothing restored depends on it, so the old one is only a convenience.");
    say(s, "%s", "");
    while (progress)
    {
        progress = false;
        for (i = 0; i < s->l.nvols; i++)
        {
            const struct rs_vol *v = &s->l.vols[i];

            if (handled[i] || !s->done[i] || !kept(s, i))
            {
                continue;
            }
            if (eq(v->fstype, "crypto_LUKS"))
            {
                luks(s, i);
            } else if (eq(v->fstype, "linux_raid_member"))
            {
                size_t kids[2];
                size_t k;
                bool   ready = true;

                if (rs_layout_children(&s->l, i, kids, 2) == 0)
                {
                    handled[i] = true;
                    progress = true;
                    continue;
                }
                for (k = 0; k < s->l.vols[kids[0]].nparents; k++)
                {
                    ready = ready && s->done[s->l.vols[kids[0]].parents[k]];
                }
                if (!ready)
                {
                    continue;
                }
                if (!s->done[kids[0]])
                {
                    raid(s, kids[0]);
                }
            } else if (eq(v->fstype, "LVM2_member"))
            {
                bool wait = false;

                for (g = 0; g < s->l.nvgs; g++)
                {
                    size_t k;

                    for (k = 0; k < s->l.vgs[g].npvs; k++)
                    {
                        if (s->l.vgs[g].pvs[k].vol == i && !s->vg_done[g])
                        {
                            if (vg_ready(s, g))
                            {
                                lvm(s, g);
                            } else
                            {
                                wait = true;
                            }
                        }
                    }
                }
                if (wait)
                {
                    continue;
                }
            } else
            {
                mkfs(s, i);
            }
            handled[i] = true;
            progress = true;
        }
    }
    for (g = 0; g < s->l.nvgs; g++)
    {
        if (!s->vg_done[g])
        {
            note(s, "Volume group %s: the devices its physical volumes were on are not in "
                 "the description, so it is not recreated here. Its metadata is in the "
                 "image under /etc/lvm/backup/%s.", s->l.vgs[g].name, s->l.vgs[g].name);
        }
    }
    free(handled);
}

/* A mounted volume, for sorting by where it is mounted. */
struct mounted {
    const struct rs_vol *vol;
};

static int by_mountpoint(const void *a, const void *b)
{
    const struct mounted *x = a;
    const struct mounted *y = b;

    return strcmp(x->vol->mountpoint, y->vol->mountpoint);
}

static void install(struct sheet *s)
{
    struct mounted *list = rs_xcalloc(s->l.nvols + 1, sizeof(*list));
    size_t          n = 0;
    size_t          i;
    bool            desktop = s->have_installer && eq(s->in.flavor, "desktop");
    bool            any_luks = false;

    heading(s, "Install onto that layout");
    for (i = 0; i < s->l.nvols; i++)
    {
        if (kept(s, i) && s->l.vols[i].mountpoint)
        {
            list[n++].vol = &s->l.vols[i];
        }
        any_luks = any_luks || (kept(s, i) && s->l.vols[i].kind == RS_VOL_LUKS);
    }
    qsort(list, n, sizeof(*list), by_mountpoint);
    if (desktop)
    {
        say(s, "%s", "Start the installer from the desktop. At \"How do you want to install");
        say(s, "%s", "Ubuntu?\" choose \"Manual installation\".");
    } else
    {
        say(s, "%s", "Go back to the installer (Ctrl-Alt-F1). At \"Guided storage configuration\"");
        say(s, "%s", "choose \"Custom storage layout\".");
    }
    say(s, "%s", "");
    say(s, "%s", "Give each device below the use shown and its mount point, and do NOT format");
    say(s, "%s", "it: it was formatted above with its original UUID, and formatting it again");
    say(s, "%s", "would give it a new one.");
    say(s, "%s", "");
    for (i = 0; i < n; i++)
    {
        const struct rs_vol *v = list[i].vol;
        bool                 swap = strcmp(v->mountpoint, "[swap]") == 0;

        say(s, "    %-22s %-32s %s", swap ? "swap" : v->mountpoint, v->path,
            is_esp(v) ? "EFI System Partition" : (v->fstype ? v->fstype : ""));
    }
    free(list);
    if (s->l.firmware && strcmp(s->l.firmware, "bios") == 0)
    {
        say(s, "%s", "");
        say(s, "%s", "Install the boot loader to $DISK1 itself (the whole disk, not a partition).");
    }
    if (any_luks)
    {
        say(s, "%s", "");
        say(s, "%s", "The encrypted volumes are open (cryptsetup open, above), so the installer");
        say(s, "%s", "sees the filesystems inside them under /dev/mapper. If it does not offer");
        say(s, "%s", "them -- not every installer version reuses encryption it did not create --");
        say(s, "%s", "use `restate autoinstall` instead, or let the installer encrypt and format");
        say(s, "%s", "those volumes itself and keep its own /etc/fstab and /etc/crypttab when");
        say(s, "%s", "restoring the files, since their UUIDs will then be new.");
    }
    say(s, "%s", "");
    say(s, "%s", "Create a user when asked; the restore brings back the real accounts. When");
    say(s, "%s", "the installer finishes, reboot into the new system.");
}

static void after(struct sheet *s)
{
    const struct rs_jval *hwp = rs_jobject_get(s->sys, "hardware_packages");
    const struct rs_jval *gup = rs_jobject_get(s->sys, "guest_packages");
    size_t                i;
    bool                  nfs = false;
    bool                  cifs = false;
    bool                  any_tpm = false;
    char                  buf[32];

    heading(s, "After the install, before the restore");
    say(s, "%s", "As root on the new system:");
    say(s, "%s", "");
    for (i = 0; i < s->l.nnetmounts; i++)
    {
        nfs = nfs || rs_starts_with(s->l.netmounts[i].type, "nfs");
        cifs = cifs || eq(s->l.netmounts[i].type, "cifs") || eq(s->l.netmounts[i].type, "smb3");
    }
    if (nfs || cifs)
    {
        say(s, "    apt-get install -y%s%s    # for the network mounts in /etc/fstab", nfs ? " nfs-common" : "",
            cifs ? " cifs-utils" : "");
    }
    for (i = 0; i < s->l.nswapfiles; i++)
    {
        const char *f = s->l.swapfiles[i].file;

        say(s, "    fallocate -l %" PRIu64 "M %s && chmod 600 %s && mkswap %s    # %s swap file",
            (s->l.swapfiles[i].size + MIB / 2) / MIB, f, f, f, size_text(s->l.swapfiles[i].size, buf, sizeof(buf)));
    }
    if (s->o->target == RS_TARGET_VM)
    {
        say(s, "%s", "    apt-get install -y qemu-guest-agent    # the hypervisor's view into the guest");
        if (hwp && hwp->type == RS_JARRAY && hwp->n > 0)
        {
            struct rs_buf b;
            bool          md = false;

            for (i = 0; i < s->l.nvols; i++)
            {
                md = md || (kept(s, i) && s->l.vols[i].kind == RS_VOL_MD);
            }
            rs_buf_init(&b);
            for (i = 0; i < hwp->n; i++)
            {
                /* The arrays are rebuilt in the VM too, and need mdadm there. */
                if (!(md && eq(hwp->items[i].s, "mdadm")))
                {
                    rs_buf_addf(&b, " %s", hwp->items[i].s);
                }
            }
            if (b.len)
            {
                say(s, "    apt-get purge -y%s    # real hardware's, no use in a VM", b.data);
            }
            rs_buf_free(&b);
        }
    } else if (s->o->target == RS_TARGET_METAL)
    {
        if (gup && gup->type == RS_JARRAY && gup->n > 0)
        {
            struct rs_buf b;

            rs_buf_init(&b);
            for (i = 0; i < gup->n; i++)
            {
                rs_buf_addf(&b, " %s", gup->items[i].s);
            }
            say(s, "    apt-get purge -y%s    # a virtual machine's, no use on hardware", b.data);
            rs_buf_free(&b);
        }
        say(s, "%s", "    apt-get install -y intel-microcode    # or amd64-microcode, for the new CPU");
    }
    for (i = 0; i < s->l.nvols; i++)
    {
        any_tpm = any_tpm || (kept(s, i) && s->l.vols[i].tpm);
    }
    if (any_tpm)
    {
        say(s, "%s", "");
        say(s, "%s", "These volumes unlocked with the old machine's TPM, which cannot be moved:");
        say(s, "%s", "re-enroll them on this one once it boots with the passphrase.");
        say(s, "%s", "");
        for (i = 0; i < s->l.nvols; i++)
        {
            const struct rs_vol *v = &s->l.vols[i];

            if (kept(s, i) && v->tpm && v->kind == RS_VOL_LUKS && v->nparents == 1 &&
                s->l.vols[v->parents[0]].uuid)
            {
                say(s, "    systemd-cryptenroll --tpm2-device=auto /dev/disk/by-uuid/%s    # %s",
                    s->l.vols[v->parents[0]].uuid, v->name);
            }
        }
    }
    for (i = 0; i < s->l.nvols; i++)
    {
        if (kept(s, i) && s->l.vols[i].keyfile && s->l.vols[i].nparents == 1 &&
            s->l.vols[s->l.vols[i].parents[0]].uuid)
        {
            say(s, "    cryptsetup luksAddKey /dev/disk/by-uuid/%s %s    # after the restore puts "
                "the key file back", s->l.vols[s->l.vols[i].parents[0]].uuid, s->l.vols[i].keyfile);
        }
    }
    if (s->l.secure_boot)
    {
        say(s, "%s", "");
        say(s, "%s", "Secure Boot was on. Turn it back on in the firmware; a module signed with a");
        say(s, "%s", "locally enrolled key (DKMS drivers) needs that key enrolled again with");
        say(s, "%s", "`mokutil --import` before it will load.");
    }
    if (s->o->target != RS_TARGET_SAME)
    {
        const struct rs_jval *hw = rs_jobject_get(s->machine, "hardware");
        const struct rs_jval *net = rs_jobject_get(hw, "network");

        say(s, "%s", "");
        say(s, "%s", "The network interfaces are new. A restored /etc/netplan or NetworkManager");
        say(s, "%s", "connection that names the old ones by name or MAC needs editing to match");
        say(s, "%s", "`ip link` after the restore. They were:");
        for (i = 0; net && net->type == RS_JARRAY && i < net->n; i++)
        {
            say(s, "      was %s (%s)", rs_jobject_str(&net->items[i], "name") ? rs_jobject_str(&net->items[i], "name") : "?",
                rs_jobject_str(&net->items[i], "mac") ? rs_jobject_str(&net->items[i], "mac") : "no MAC recorded");
        }
        say(s, "%s", "If the old machine hibernated, remove its resume device:");
        say(s, "%s", "    rm -f /etc/initramfs-tools/conf.d/resume");
    }
}

static void restore(struct sheet *s)
{
    const char *img = s->o->image ? s->o->image : "IMAGE.tgz";

    heading(s, "Restore the files");
    say(s, "%s", "`restate restore` is not in this version. Until it is, an image's files go");
    say(s, "%s", "back with tar, as root, on the new system:");
    say(s, "%s", "");
    say(s, "    tar -xpzf %s --numeric-owner -C / --strip-components=2 restate/files", img);
    say(s, "%s", "");
    say(s, "%s", "If the installer formatted any volume itself (so its UUID is new), keep the");
    say(s, "%s", "installer's /etc/fstab and /etc/crypttab instead of the old ones:");
    say(s, "%s", "");
    say(s, "    tar -xpzf %s --numeric-owner -C / --strip-components=2 \\", img);
    say(s, "%s", "        --exclude=restate/files/etc/fstab --exclude=restate/files/etc/crypttab \\");
    say(s, "%s", "        restate/files");
    say(s, "%s", "");
    say(s, "%s", "Packages installed after the original install are not reinstalled by this");
    say(s, "%s", "version: install them first, or the restored configuration may refer to");
    say(s, "%s", "programs that are not there yet. Then rebuild the boot files and reboot:");
    say(s, "%s", "");
    say(s, "%s", "    update-initramfs -u -k all && update-grub && reboot");
}

static void vm(struct sheet *s)
{
    const struct rs_jval *hw = rs_jobject_get(s->machine, "hardware");
    const struct rs_jval *mem = rs_jobject_get(hw, "memory");
    const struct rs_jval *cpus = rs_jobject_get(hw, "cpus");
    const char           *host = rs_jobject_str(s->sys, "hostname");
    bool                  uefi = s->l.firmware && strcmp(s->l.firmware, "uefi") == 0;
    size_t                d;

    uint64_t              orig_mib = mem ? mem->u / MIB : 0;
    uint64_t              orig_cpus = cpus ? cpus->u : 0;
    /* A VM is a guest on someone's host, often the very machine it was taken
     * from: a modest share of it, never more than the original had. */
    uint64_t              vm_mib = orig_mib == 0 ? 4096 : (orig_mib < 8192 ? orig_mib : 8192);
    uint64_t              vm_cpus = orig_cpus == 0 ? 2 : (orig_cpus < 4 ? orig_cpus : 4);
    char                  buf[32];

    heading(s, "Create the virtual machine");
    say(s, "%s", "With libvirt, on the host. Its disks are sized from what the Linux volumes");
    say(s, "%s", "will hold, and it gets a modest share of a host -- at most 8 GiB and 4 CPUs:");
    say(s, "%s", "");
    say(s, "    virt-install --name %s \\", host ? host : "restored");
    say(s, "        --memory %" PRIu64 " --vcpus %" PRIu64 " --cpu host-passthrough \\", vm_mib,
        vm_cpus);
    for (d = 0; d < s->l.ndisks; d++)
    {
        uint64_t need = 0;
        size_t   i;

        for (i = 0; i < s->l.nvols; i++)
        {
            if (s->l.vols[i].disk == d && (s->l.vols[i].kind == RS_VOL_PART || s->l.vols[i].kind == RS_VOL_DISK))
            {
                need += rs_layout_fit(&s->l, i, RS_TARGET_VM);
            }
        }
        if (need > 0)
        {
            say(s, "        --disk size=%" PRIu64 ",bus=virtio,format=qcow2 \\",
                (need + 2 * MIB + GIB - 1) / GIB);
        }
    }
    say(s, "%s", "        --network network=default,model=virtio \\");
    if (uefi)
    {
        say(s, "%s", "        --boot uefi \\");
    }
    if (s->have_installer && eq(s->in.flavor, "desktop"))
    {
        say(s, "%s", "        --graphics spice --video virtio \\");
    } else
    {
        say(s, "%s", "        --graphics none --console pty,target_type=serial \\");
    }
    say(s, "%s", "        --osinfo detect=on,require=off \\");
    if (s->have_installer)
    {
        if (s->in.point)
        {
            say(s, "        --cdrom %s/%s/%s/ubuntu-%s-%s-%s.iso", rs_installer_default_cache(), s->in.vendor,
                s->in.release, s->in.point, s->in.flavor, s->in.arch);
        } else
        {
            say(s, "        --cdrom %s/%s/%s/%s", rs_installer_default_cache(), s->in.vendor,
                s->in.release, s->in.pattern);
        }
    } else
    {
        say(s, "%s", "        --cdrom INSTALLER.iso");
    }
    say(s, "%s", "");
    if (vm_mib < orig_mib || vm_cpus < orig_cpus)
    {
        say(s, "The original had %s of memory and %" PRIu64 " CPUs; raise --memory and --vcpus",
            size_text(orig_mib * MIB, buf, sizeof(buf)), orig_cpus);
        say(s, "%s", "if the VM is to do the original's work, and the host can spare them.");
    }
    say(s, "%s", "The VM's disks appear as /dev/vda, /dev/vdb...; Ubuntu's generic kernel has");
    say(s, "%s", "the virtio drivers, so the initramfs needs nothing added.");
    if (s->l.secure_boot)
    {
        say(s, "%s", "For Secure Boot in the guest, use firmware with the Microsoft keys enrolled:");
        say(s, "%s", "--boot uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=yes");
    }
}

static void notes(struct sheet *s)
{
    const struct rs_jval *mn = rs_jobject_get(s->machine, "notes");
    size_t                i;

    for (i = 0; i < s->l.nvols; i++)
    {
        const struct rs_vol *v = &s->l.vols[i];

        if (v->foreign && (v->kind == RS_VOL_PART || v->kind == RS_VOL_DISK))
        {
            note(s, "%s is %s: not rebuilt here%s.", v->path, v->foreign_why,
                 s->o->target == RS_TARGET_SAME ? "; restore it with that system's own tools" : "");
        }
    }
    for (i = 0; i < s->l.nnetmounts; i++)
    {
        note(s, "%s is mounted from %s (%s): it comes back with /etc/fstab, and needs the "
             "server reachable from the new machine.", s->l.netmounts[i].file, s->l.netmounts[i].spec,
             s->l.netmounts[i].type);
    }
    for (i = 0; mn && mn->type == RS_JARRAY && i < mn->n; i++)
    {
        /* Said already, with what it means for the rebuild. */
        if (mn->items[i].type == RS_JSTRING && !strstr(mn->items[i].s, "LUKS header could not be read"))
        {
            note(s, "%s", mn->items[i].s);
        }
    }
    if (s->notes.len)
    {
        heading(s, "Notes");
        rs_buf_addstr(s->out, s->notes.data);
    }
}

bool rs_buildsheet(const struct rs_jval *machine, const struct rs_sheet_opts *o,
                   struct rs_buf *out, struct rs_buf *err)
{
    struct sheet  s;
    struct rs_buf ierr;
    size_t        i;

    memset(&s, 0, sizeof(s));
    s.machine = machine;
    s.sys = rs_jobject_get(machine, "system");
    s.o = o;
    s.out = out;
    {
        const char *kernel = rs_jobject_str(s.sys, "kernel_name");

        /* The commands are Linux's: sfdisk, cryptsetup, mdadm, LVM. */
        if (kernel && strcmp(kernel, "Linux") != 0)
        {
            rs_buf_addf(err, "build sheets are written for Linux in this version, and this is "
                        "%s; its disk layout is in `restate machine`", kernel);
            return false;
        }
    }
    if (!rs_layout_build(machine, &s.l))
    {
        rs_buf_addstr(err, "the machine description has no disks to rebuild (it is made on "
                           "Linux, from the running system or an image captured from its root)");
        rs_layout_free(&s.l);
        return false;
    }
    rs_buf_init(&s.notes);
    rs_buf_init(&ierr);
    s.have_installer = rs_installer_resolve(machine, &s.in, &ierr);
    rs_buf_free(&ierr);
    s.newnum = rs_xcalloc(s.l.nvols + 1, sizeof(*s.newnum));
    s.done = rs_xcalloc(s.l.nvols + 1, sizeof(*s.done));
    s.vg_done = rs_xcalloc(s.l.nvgs + 1, sizeof(*s.vg_done));
    for (i = 0; i < s.l.nvols; i++)
    {
        if (s.l.vols[i].foreign && (s.l.vols[i].kind == RS_VOL_PART || s.l.vols[i].kind == RS_VOL_DISK))
        {
            s.any_foreign = true;
        }
    }
    for (i = 0; i < s.l.nvols; i++)
    {
        s.shared_esp = s.shared_esp || (s.any_foreign && o->target == RS_TARGET_SAME && is_esp(&s.l.vols[i]));
    }

    intro(&s);
    needs(&s);
    layout(&s);
    if (o->target == RS_TARGET_VM)
    {
        vm(&s);
    }
    shell(&s);
    partition(&s);
    volumes(&s);
    install(&s);
    after(&s);
    restore(&s);
    notes(&s);

    if (s.have_installer)
    {
        rs_installer_free(&s.in);
    }
    free(s.newnum);
    free(s.done);
    free(s.vg_done);
    rs_buf_free(&s.notes);
    rs_layout_free(&s.l);
    return true;
}
