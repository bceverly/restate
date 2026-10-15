/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "fstab.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* The ways a table names a disk other than by its path, and where in /dev
 * udev makes a link by each. */
static const struct {
    const char *tag;
    const char *dir;
} tags[] = {
    { "UUID=", "disk/by-uuid/" },
    { "PARTUUID=", "disk/by-partuuid/" },
    { "LABEL=", "disk/by-label/" },
    { "PARTLABEL=", "disk/by-partlabel/" },
};

static const struct rs_jval *table(const struct rs_jval *machine, const char *name)
{
    const struct rs_jval *t = rs_jobject_get(machine, name);

    return t && t->type == RS_JARRAY ? t : NULL;
}

/* Whether `word` is one of the comma-separated options in `options`. */
static bool has_option(const char *options, const char *word)
{
    size_t      n = strlen(word);
    const char *p = options;

    while (p && *p)
    {
        if (strncmp(p, word, n) == 0 && (p[n] == ',' || p[n] == '\0'))
        {
            return true;
        }
        p = strchr(p, ',');
        p = p ? p + 1 : NULL;
    }
    return false;
}

static bool exists(const char *dev, const char *rest)
{
    char       *path = rs_xasprintf("%s/%s", dev, rest);
    struct stat st;
    bool        found = stat(path, &st) == 0;

    free(path);
    return found;
}

/* Whether `name` is a mapping the image's crypttab opens. */
static bool opened_by(const struct rs_jval *crypttab, const char *name)
{
    size_t i;

    for (i = 0; crypttab && i < crypttab->n; i++)
    {
        const char *n = rs_jobject_str(&crypttab->items[i], "name");

        if (n && strcmp(n, name) == 0)
        {
            return true;
        }
    }
    return false;
}

/*
 * Whether `spec` names a disk that `dev` does not have. What is not a disk
 * -- a network filesystem, a bind mount, tmpfs, a swap file -- is not
 * missing. A mapping the image's crypttab opens is there when what it opens
 * is, which is checked as the crypttab's own entry.
 */
static bool missing(const char *dev, const char *spec, const struct rs_jval *crypttab)
{
    size_t i;

    for (i = 0; i < sizeof(tags) / sizeof(tags[0]); i++)
    {
        size_t n = strlen(tags[i].tag);

        if (strncmp(spec, tags[i].tag, n) == 0)
        {
            char  *value = rs_xstrdup(spec + n);
            size_t len = strlen(value);
            char  *rest;
            bool   there;

            /* UUID="..." is allowed too. */
            if (len >= 2 && value[0] == '"' && value[len - 1] == '"')
            {
                memmove(value, value + 1, len - 2);
                value[len - 2] = '\0';
            }
            rest = rs_xasprintf("%s%s", tags[i].dir, value);
            there = value[0] != '\0' && strchr(value, '/') == NULL && exists(dev, rest);
            free(rest);
            free(value);
            return !there;
        }
    }
    if (strncmp(spec, "/dev/", 5) != 0)
    {
        return false;
    }
    if (strstr(spec, "/../") != NULL)
    {
        return true;
    }
    if (exists(dev, spec + 5))
    {
        return false;
    }
    return !(strncmp(spec, "/dev/mapper/", 12) == 0 && opened_by(crypttab, spec + 12));
}

static void add(struct rs_buf *why, const char *spec, const char *what)
{
    rs_buf_addf(why, "%s%s (%s)", why->len > 0 ? ", " : "", spec, what ? what : "?");
}

bool rs_fstab_foreign(const struct rs_jval *machine, const char *dev, struct rs_buf *why)
{
    const struct rs_jval *fstab = table(machine, "fstab");
    const struct rs_jval *crypttab = table(machine, "crypttab");
    size_t                before = why->len;
    size_t                i;

    for (i = 0; fstab && i < fstab->n; i++)
    {
        const struct rs_jval *e = &fstab->items[i];
        const char           *spec = rs_jobject_str(e, "spec");
        const char           *options = rs_jobject_str(e, "options");

        if (spec && !has_option(options, "noauto") && !has_option(options, "nofail") &&
            missing(dev, spec, crypttab))
        {
            add(why, spec, rs_jobject_str(e, "file"));
        }
    }
    for (i = 0; crypttab && i < crypttab->n; i++)
    {
        const struct rs_jval *e = &crypttab->items[i];
        const char           *device = rs_jobject_str(e, "device");
        const char           *options = rs_jobject_str(e, "options");

        if (device && !has_option(options, "noauto") && !has_option(options, "nofail") &&
            missing(dev, device, NULL))
        {
            add(why, device, rs_jobject_str(e, "name"));
        }
    }
    return why->len > before;
}
