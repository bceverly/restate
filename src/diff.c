/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "diff.h"

#include <stdlib.h>
#include <string.h>

#include "json.h"

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

/* Where changes go as JSON instead of lines, when they do (rs_diff_json). */
static struct rs_jval *json_changes;
static struct rs_jval *json_packages;

void rs_diff_json(struct rs_jval *changes, struct rs_jval *packages)
{
    json_changes = changes;
    json_packages = packages;
    if (changes)
    {
        memset(changes, 0, sizeof(*changes));
        rs_jval_set_array(changes);
    }
    if (packages)
    {
        memset(packages, 0, sizeof(*packages));
        rs_jval_set_array(packages);
    }
}

/* Where a result's package changes go as well (rs_diff_collect_packages). */
static struct rs_jval *collected_packages;

void rs_diff_collect_packages(struct rs_jval *packages)
{
    collected_packages = packages;
    if (packages)
    {
        memset(packages, 0, sizeof(*packages));
        rs_jval_set_array(packages);
    }
}

/* Where a result's changes go (rs_diff_collect), how many of each kind it
 * takes, how many of each it has, and whether it has had to leave any out. */
static struct rs_jval *collected;
static size_t          collect_cap;
static size_t          ncollected[3];
static bool            left_out;

bool rs_diff_collect(struct rs_jval *changes, size_t cap)
{
    bool was = left_out;

    collected = changes;
    collect_cap = cap;
    memset(ncollected, 0, sizeof(ncollected));
    left_out = false;
    if (changes)
    {
        memset(changes, 0, sizeof(*changes));
        rs_jval_set_array(changes);
    }
    return was;
}

/* `kind` and `path` as a change object, appended to `list`. */
static void json_line(struct rs_jval *list, char kind, const char *path, unsigned what)
{
    struct rs_jval *c = rs_jarr_add(list);
    const char      k[2] = { kind, '\0' };
    char           *p = rs_utf8_lossy(path, strlen(path));

    rs_jval_set_object(c);
    rs_jobj_str(c, "change", k);
    rs_jobj_str(c, "path", p);
    free(p);
    if (what)
    {
        struct rs_buf names;

        rs_buf_init(&names);
        rs_diff_describe(what, &names);
        rs_jobj_str(c, "what", names.data);
        rs_buf_free(&names);
    }
}

static void line(FILE *out, char kind, const char *path, unsigned what)
{
    struct rs_buf shown;

    if (collected)
    {
        size_t *n = &ncollected[kind == 'A' ? 0 : kind == 'D' ? 1 : 2];

        if (*n < collect_cap)
        {
            json_line(collected, kind, path, what);
            (*n)++;
        } else
        {
            left_out = true;
        }
    }
    if (json_changes)
    {
        json_line(json_changes, kind, path, what);
        return;
    }
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

/* ------------------------------------------------------------------------- */
/* By package                                                                 */
/* ------------------------------------------------------------------------- */

/* One package as an inventory records it. */
struct pkg {
    const char *manager;   /* "apt", "snap" */
    const char *name;
    const char *arch;      /* apt's; "" for a snap */
    const char *version;   /* apt's version, a snap's revision */
};

/* One package whose installation changed. */
struct change {
    char        kind;      /* I, R or U */
    const char *manager;
    const char *name;
    const char *arch;
    const char *from;      /* NULL where it was not installed */
    const char *to;        /* NULL where it is not now */
    size_t      files;     /* file changes it accounts for */
};

struct changes {
    struct change *c;
    size_t         n;
    const char    *native;   /* the machine's own architecture, not written after a name */
};

static int compare_pkg(const void *a, const void *b)
{
    const struct pkg *x = a;
    const struct pkg *y = b;
    int               c = strcmp(x->manager, y->manager);

    c = c != 0 ? c : strcmp(x->name, y->name);
    return c != 0 ? c : strcmp(x->arch, y->arch);
}

/* The packages an index's inventory records: apt's and snap's. */
static struct pkg *inventory(const struct rs_index *ix, size_t *n)
{
    const struct rs_jval *apt = rs_jobject_get(rs_jobject_get(&ix->packages, "apt"), "packages");
    const struct rs_jval *snap = rs_jobject_get(&ix->packages, "snap");
    struct pkg           *p = NULL;
    size_t                i;

    *n = 0;
    for (i = 0; apt && apt->type == RS_JARRAY && i < apt->n; i++)
    {
        const char *name = rs_jobject_str(&apt->items[i], "name");
        const char *arch = rs_jobject_str(&apt->items[i], "architecture");
        const char *version = rs_jobject_str(&apt->items[i], "version");

        if (name && version)
        {
            p = rs_xreallocarray(p, *n + 1, sizeof(*p));
            p[*n].manager = "apt";
            p[*n].name = name;
            p[*n].arch = arch ? arch : "";
            p[(*n)++].version = version;
        }
    }
    for (i = 0; snap && snap->type == RS_JARRAY && i < snap->n; i++)
    {
        const char *name = rs_jobject_str(&snap->items[i], "name");
        const char *rev = rs_jobject_str(&snap->items[i], "revision");

        if (name && rev)
        {
            p = rs_xreallocarray(p, *n + 1, sizeof(*p));
            p[*n].manager = "snap";
            p[*n].name = name;
            p[*n].arch = "";
            p[(*n)++].version = rev;
        }
    }
    if (*n > 1)
    {
        qsort(p, *n, sizeof(*p), compare_pkg);
    }
    /* Never NULL, even for none: so the analyzers need not wonder whether a
     * NULL list can have a count. */
    return p ? p : rs_xcalloc(1, sizeof(*p));
}

static void add_change(struct changes *cs, char kind, const struct pkg *p, const char *from,
                       const char *to)
{
    struct change *c;

    cs->c = rs_xreallocarray(cs->c, cs->n + 1, sizeof(*cs->c));
    c = &cs->c[cs->n++];
    c->kind = kind;
    c->manager = p->manager;
    c->name = p->name;
    c->arch = p->arch;
    c->from = from;
    c->to = to;
    c->files = 0;
}

/* What changed between the two inventories, sorted by manager and name. */
static void package_changes(const struct rs_index *old, const struct rs_index *new_,
                            struct changes *cs)
{
    const struct rs_jval *archs = rs_jobject_get(rs_jobject_get(&new_->packages, "apt"),
                                                 "architectures");
    size_t                na;
    size_t                nb;
    struct pkg           *a = inventory(old, &na);
    struct pkg           *b = inventory(new_, &nb);
    size_t                i = 0;
    size_t                j = 0;

    memset(cs, 0, sizeof(*cs));
    cs->native = archs && archs->type == RS_JARRAY && archs->n > 0 &&
                 archs->items[0].type == RS_JSTRING ? archs->items[0].s : NULL;
    while (i < na || j < nb)
    {
        int c = i == na ? 1 : j == nb ? -1 : compare_pkg(&a[i], &b[j]);

        if (c < 0)
        {
            add_change(cs, 'R', &a[i], a[i].version, NULL);
            i++;
        } else if (c > 0)
        {
            add_change(cs, 'I', &b[j], NULL, b[j].version);
            j++;
        } else
        {
            if (strcmp(a[i].version, b[j].version) != 0)
            {
                add_change(cs, 'U', &b[j], a[i].version, b[j].version);
            }
            i++;
            j++;
        }
    }
    free(a);
    free(b);
}

/* The apt package called `name` that changed, if one did. */
static struct change *changed(const struct changes *cs, const char *name)
{
    size_t i;

    for (i = 0; name && i < cs->n; i++)
    {
        if (strcmp(cs->c[i].manager, "apt") == 0 && strcmp(cs->c[i].name, name) == 0)
        {
            return &cs->c[i];
        }
    }
    return NULL;
}

/* The package change that accounts for a file's change, or NULL: `kind` is
 * A, D or M, and either entry may be NULL. */
static struct change *accounts_for(const struct changes *cs, char kind,
                                   const struct rs_entry *old, const struct rs_entry *new_)
{
    struct change *c;

    if (cs->n == 0)
    {
        return NULL;
    }
    if (kind == 'D')
    {
        c = changed(cs, old->package);
        return c && c->kind != 'I' ? c : NULL;
    }
    /* Added or modified: the new file has to be what its package put there. */
    if (!new_->package || new_->modified)
    {
        return NULL;
    }
    c = changed(cs, new_->package);
    return c && c->kind != 'R' ? c : NULL;
}

static bool walk(const struct rs_index *old, const struct rs_index *new_, FILE *out,
                 struct rs_diff_stats *stats, const struct changes *cs, bool write)
{
    size_t i = 0;
    size_t j = 0;

    while (i < old->count || j < new_->count)
    {
        const struct rs_entry *a = i < old->count ? &old->entries[i] : NULL;
        const struct rs_entry *b = j < new_->count ? &new_->entries[j] : NULL;
        struct change         *why;
        char                   kind = 0;
        unsigned               what = 0;
        int                    c = !a ? 1 : !b ? -1 : strcmp(a->path, b->path);

        if (c < 0)
        {
            kind = 'D';
            b = NULL;
            i++;
        } else if (c > 0)
        {
            kind = 'A';
            a = NULL;
            j++;
        } else
        {
            what = rs_diff_entries(a, b);
            kind = what ? 'M' : 0;
            i++;
            j++;
        }
        if (!kind)
        {
            continue;
        }
        why = cs ? accounts_for(cs, kind, a, b) : NULL;
        if (why)
        {
            why->files += write ? 0 : 1;
            stats->explained += write ? 0 : 1;
            continue;
        }
        if (write)
        {
            line(out, kind, kind == 'D' ? a->path : b->path, what);
        }
        stats->added += kind == 'A';
        stats->deleted += kind == 'D';
        stats->modified += kind == 'M';
    }
    return !write || (fflush(out) == 0 && !ferror(out));
}

bool rs_diff_write(const struct rs_index *old, const struct rs_index *new_,
                   FILE *out, struct rs_diff_stats *stats)
{
    memset(stats, 0, sizeof(*stats));
    return walk(old, new_, out, stats, NULL, true);
}

bool rs_diff_write_packages(const struct rs_index *old, const struct rs_index *new_,
                            FILE *out, struct rs_diff_stats *stats)
{
    struct changes cs;
    size_t         i;
    bool           ok;

    memset(stats, 0, sizeof(*stats));
    memset(&cs, 0, sizeof(cs));
    if (old->packages.type == RS_JOBJECT && new_->packages.type == RS_JOBJECT)
    {
        package_changes(old, new_, &cs);
    }
    /* Counted first, so each package's line can say how many files it
     * accounts for; then written. */
    (void)walk(old, new_, out, stats, &cs, false);
    for (i = 0; i < cs.n; i++)
    {
        const struct change *c = &cs.c[i];
        bool                 foreign = c->arch[0] && strcmp(c->arch, "all") != 0 && cs.native &&
                                       strcmp(c->arch, cs.native) != 0;
        struct rs_buf        b;

        if (json_packages || collected_packages)
        {
            struct rs_jval j;
            const char     k[2] = { c->kind, '\0' };

            memset(&j, 0, sizeof(j));
            rs_jval_set_object(&j);
            rs_jobj_str(&j, "change", k);
            rs_jobj_str(&j, "manager", c->manager);
            rs_jobj_str(&j, "name", c->name);
            if (foreign)
            {
                rs_jobj_str(&j, "arch", c->arch);
            }
            rs_jobj_str(&j, "from", c->from);
            rs_jobj_str(&j, "to", c->to);
            rs_jobj_u64(&j, "files", c->files);
            if (collected_packages)
            {
                rs_jval_copy(rs_jarr_add(collected_packages), &j);
            }
            if (json_packages)
            {
                *rs_jarr_add(json_packages) = j;
                continue;
            }
            rs_jval_free(&j);
        }
        rs_buf_init(&b);
        rs_buf_addf(&b, "%c\t%s:", c->kind, c->manager);
        rs_escape(&b, c->name);
        if (foreign)
        {
            rs_buf_addc(&b, ':');
            rs_escape(&b, c->arch);
        }
        rs_buf_addc(&b, '\t');
        if (c->from && c->to)
        {
            rs_escape(&b, c->from);
            rs_buf_addstr(&b, " -> ");
        }
        rs_escape(&b, c->to ? c->to : c->from);
        if (c->files > 0)
        {
            rs_buf_addf(&b, ", %zu file%s", c->files, c->files == 1 ? "" : "s");
        }
        (void)fprintf(out, "%s\n", b.data);
        rs_buf_free(&b);
    }
    stats->packages = cs.n;
    stats->added = 0;
    stats->deleted = 0;
    stats->modified = 0;
    ok = walk(old, new_, out, stats, &cs, true);
    free(cs.c);
    return ok;
}
