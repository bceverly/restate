/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "diff.h"

#include <string.h>

/* Both sorted by name, as the walk and the index reader leave them. */
static bool xattrs_equal(const struct rs_entry *a, const struct rs_entry *b)
{
    size_t i;

    if (a->nxattrs != b->nxattrs)
    {
        return false;
    }
    for (i = 0; i < a->nxattrs; i++)
    {
        const struct rs_xattr *x = &a->xattrs[i];
        const struct rs_xattr *y = &b->xattrs[i];

        if (strcmp(x->name, y->name) != 0 || x->len != y->len ||
            (x->len && memcmp(x->value, y->value, x->len) != 0))
        {
            return false;
        }
    }
    return true;
}

unsigned rs_diff_entries(const struct rs_entry *old, const struct rs_entry *new_)
{
    unsigned what = 0;

    if (old->type != new_->type)
    {
        /* Nothing else is comparable across a change of type. */
        return RS_DIFF_TYPE;
    }
    if (old->mode != new_->mode)
    {
        what |= RS_DIFF_MODE;
    }
    if (old->uid != new_->uid || old->gid != new_->gid)
    {
        what |= RS_DIFF_OWNER;
    }
    if (!xattrs_equal(old, new_))
    {
        what |= RS_DIFF_XATTRS;
    }
    if (old->type == 'l')
    {
        const char *a = old->target ? old->target : "";
        const char *b = new_->target ? new_->target : "";

        if (strcmp(a, b) != 0)
        {
            what |= RS_DIFF_TARGET;
        }
    } else if (old->type == 'f')
    {
        if (old->hash_state == RS_HASH_PRESENT && new_->hash_state == RS_HASH_PRESENT)
        {
            if (strcmp(old->hash, new_->hash) != 0)
            {
                what |= RS_DIFF_CONTENT;
            }
        } else if (old->size != new_->size || !rs_time_equal(&old->mtime, &new_->mtime))
        {
            what |= RS_DIFF_CONTENT;
        }
    }
    return what;
}

void rs_diff_describe(unsigned what, struct rs_buf *out)
{
    static const struct {
        unsigned    bit;
        const char *name;
    } names[] = {
        { RS_DIFF_TYPE,    "type" },
        { RS_DIFF_CONTENT, "content" },
        { RS_DIFF_TARGET,  "target" },
        { RS_DIFF_MODE,    "mode" },
        { RS_DIFF_OWNER,   "owner" },
        { RS_DIFF_XATTRS,  "xattrs" },
    };
    size_t i;
    bool   first = true;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        if (what & names[i].bit)
        {
            if (!first)
            {
                rs_buf_addc(out, ',');
            }
            rs_buf_addstr(out, names[i].name);
            first = false;
        }
    }
}

static void line(FILE *out, char kind, const char *path, unsigned what)
{
    struct rs_buf shown;

    rs_buf_init(&shown);
    rs_escape(&shown, path);
    if (what)
    {
        rs_buf_addc(&shown, '\t');
        rs_diff_describe(what, &shown);
    }
    (void)fprintf(out, "%c\t%s\n", kind, shown.data);
    rs_buf_free(&shown);
}

bool rs_diff_write(const struct rs_index *old, const struct rs_index *new_,
                   FILE *out, struct rs_diff_stats *stats)
{
    size_t i = 0;
    size_t j = 0;

    memset(stats, 0, sizeof(*stats));
    while (i < old->count || j < new_->count)
    {
        int c;

        if (i == old->count)
        {
            c = 1;
        } else if (j == new_->count)
        {
            c = -1;
        } else
        {
            c = strcmp(old->entries[i].path, new_->entries[j].path);
        }

        if (c < 0)
        {
            line(out, 'D', old->entries[i].path, 0);
            stats->deleted++;
            i++;
        } else if (c > 0)
        {
            line(out, 'A', new_->entries[j].path, 0);
            stats->added++;
            j++;
        } else
        {
            unsigned what = rs_diff_entries(&old->entries[i], &new_->entries[j]);

            if (what)
            {
                line(out, 'M', new_->entries[j].path, what);
                stats->modified++;
            }
            i++;
            j++;
        }
    }
    return fflush(out) == 0 && !ferror(out);
}
