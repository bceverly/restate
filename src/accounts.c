/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "accounts.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYSTEM_MIN  100
#define SYSTEM_MAX  999
#define PERSON_MIN  1000
#define PERSON_MAX  59999

/* One line of an account file, split at its colons. */
struct line {
    char **f;
    size_t n;
};

struct table {
    struct line *l;
    size_t       n;
};

static void line_free(struct line *l)
{
    size_t i;

    for (i = 0; i < l->n; i++)
    {
        free(l->f[i]);
    }
    free(l->f);
    l->f = NULL;
    l->n = 0;
}

static void table_free(struct table *t)
{
    size_t i;

    for (i = 0; i < t->n; i++)
    {
        line_free(&t->l[i]);
    }
    free(t->l);
    t->l = NULL;
    t->n = 0;
}

static void line_copy(struct line *dst, const struct line *src)
{
    size_t i;

    dst->n = src->n;
    dst->f = rs_xcalloc(src->n + 1, sizeof(*dst->f));
    for (i = 0; i < src->n; i++)
    {
        dst->f[i] = rs_xstrdup(src->f[i]);
    }
}

static void set_field(struct line *l, size_t i, const char *value)
{
    if (i < l->n)
    {
        free(l->f[i]);
        l->f[i] = rs_xstrdup(value);
    }
}

/* The lines of `text` that have at least `fields` fields and a name; the
 * first of two lines with one name. */
static void parse(const char *text, size_t fields, struct table *t)
{
    const char *p = text;

    memset(t, 0, sizeof(*t));
    while (p && *p)
    {
        const char *nl = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : strlen(p);
        struct line l;
        const char *q = p;
        size_t      i;
        bool        dup = false;

        memset(&l, 0, sizeof(l));
        for (;;)
        {
            const char *colon = memchr(q, ':', (size_t)(p + len - q));
            size_t      flen = colon ? (size_t)(colon - q) : (size_t)(p + len - q);

            l.f = rs_xreallocarray(l.f, l.n + 1, sizeof(*l.f));
            l.f[l.n++] = rs_xstrndup(q, flen);
            if (!colon)
            {
                break;
            }
            q = colon + 1;
        }
        for (i = 0; i < t->n; i++)
        {
            dup = dup || strcmp(t->l[i].f[0], l.f[0]) == 0;
        }
        if (l.n >= fields && l.f[0][0] != '\0' && l.f[0][0] != '#' && !dup)
        {
            t->l = rs_xreallocarray(t->l, t->n + 1, sizeof(*t->l));
            t->l[t->n++] = l;
        } else
        {
            line_free(&l);
        }
        p = nl ? nl + 1 : NULL;
    }
}

static char *render(const struct table *t)
{
    struct rs_buf b;
    size_t        i;
    size_t        j;

    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    for (i = 0; i < t->n; i++)
    {
        for (j = 0; j < t->l[i].n; j++)
        {
            rs_buf_addf(&b, "%s%s", j ? ":" : "", t->l[i].f[j]);
        }
        rs_buf_addc(&b, '\n');
    }
    return rs_buf_detach(&b);
}

static struct line *find(const struct table *t, const char *name)
{
    size_t i;

    for (i = 0; t && i < t->n; i++)
    {
        if (strcmp(t->l[i].f[0], name) == 0)
        {
            return &t->l[i];
        }
    }
    return NULL;
}

static bool number(const char *s, uint64_t *out)
{
    char *end = NULL;

    if (!s || s[0] < '0' || s[0] > '9')
    {
        return false;
    }
    errno = 0;
    *out = strtoull(s, &end, 10);
    return errno == 0 && end && *end == '\0';
}

/* Whether id `id` is used in column `col` of `t`. */
static bool used(const struct table *t, size_t col, uint64_t id)
{
    size_t   i;
    uint64_t v;

    for (i = 0; i < t->n; i++)
    {
        if (t->l[i].n > col && number(t->l[i].f[col], &v) && v == id)
        {
            return true;
        }
    }
    return false;
}

/* `want` if it is free in column `col`; else the next free id in its range:
 * a system id counting down from 999, a person's up from 1000. */
static uint64_t free_id(const struct table *t, size_t col, uint64_t want)
{
    uint64_t id;

    if (!used(t, col, want))
    {
        return want;
    }
    if (want >= PERSON_MIN)
    {
        for (id = PERSON_MIN; id <= PERSON_MAX; id++)
        {
            if (!used(t, col, id))
            {
                return id;
            }
        }
    }
    for (id = SYSTEM_MAX; id >= SYSTEM_MIN; id--)
    {
        if (!used(t, col, id))
        {
            return id;
        }
    }
    return want;   /* every id taken: shared, as it was */
}

static bool person(const struct line *l)
{
    uint64_t uid;

    return l->n > 2 && number(l->f[2], &uid) &&
           (uid == 0 || (uid >= PERSON_MIN && uid <= PERSON_MAX));
}

/* The union of two comma-separated member lists. */
static char *members_union(const char *a, const char *b)
{
    struct rs_buf out;
    const char   *lists[2];
    size_t        k;

    lists[0] = a;
    lists[1] = b;
    rs_buf_init(&out);
    rs_buf_add(&out, "", 0);
    for (k = 0; k < 2; k++)
    {
        const char *p = lists[k];

        while (p && *p)
        {
            size_t n = strcspn(p, ",");

            if (n > 0)
            {
                char  *m = rs_xstrndup(p, n);
                bool   seen = false;
                char  *have = rs_xasprintf(",%s,", out.data);
                char  *needle = rs_xasprintf(",%s,", m);

                seen = strstr(have, needle) != NULL;
                if (!seen)
                {
                    rs_buf_addf(&out, "%s%s", out.len ? "," : "", m);
                }
                free(needle);
                free(have);
                free(m);
            }
            p += n + (p[n] == ',' ? 1 : 0);
        }
    }
    return rs_buf_detach(&out);
}

static void add_id(struct rs_id **ids, size_t *n, const char *name, uint64_t id)
{
    *ids = rs_xreallocarray(*ids, *n + 1, sizeof(**ids));
    (*ids)[*n].name = rs_xstrdup(name);
    (*ids)[*n].id = id;
    (*n)++;
}

/* The group that `gid` names in `t`, or NULL. */
static const char *group_name(const struct table *t, const char *gid)
{
    size_t i;

    for (i = 0; i < t->n; i++)
    {
        if (strcmp(t->l[i].f[2], gid) == 0)
        {
            return t->l[i].f[0];
        }
    }
    return NULL;
}

/* A shadow-style file for the merged names: each one's line from `old`,
 * else from `now`, else locked; for gshadow, with the merged members. */
static char *merge_shadow(const struct table *names, const char *now_text, const char *old_text,
                          bool groups)
{
    struct table now;
    struct table old;
    struct table out;
    size_t       i;
    char        *text;

    parse(now_text ? now_text : "", 2, &now);
    parse(old_text ? old_text : "", 2, &old);
    memset(&out, 0, sizeof(out));
    out.l = rs_xcalloc(names->n + 1, sizeof(*out.l));
    for (i = 0; i < names->n; i++)
    {
        const char        *name = names->l[i].f[0];
        const struct line *src = find(&old, name);
        struct line       *dst = &out.l[out.n++];

        src = src ? src : find(&now, name);
        if (src)
        {
            line_copy(dst, src);
        } else
        {
            struct table one;
            char        *synth = groups ? rs_xasprintf("%s:!::", name)
                                        : rs_xasprintf("%s:!:::::::", name);

            parse(synth, 2, &one);
            *dst = one.l[0];
            free(one.l);
            free(synth);
        }
        if (groups && dst->n >= 4)
        {
            set_field(dst, 3, names->l[i].f[3]);
        }
    }
    text = render(&out);
    table_free(&now);
    table_free(&old);
    table_free(&out);
    return text;
}

bool rs_accounts_merge(const struct rs_account_files *now, const struct rs_account_files *old,
                       struct rs_accounts *out, struct rs_buf *err)
{
    struct table ng;
    struct table og;
    struct table nu;
    struct table ou;
    size_t       i;

    memset(out, 0, sizeof(*out));
    if (!old->passwd || !old->group)
    {
        rs_buf_addstr(err, "the image has no /etc/passwd or /etc/group to merge");
        return false;
    }
    parse(now->group ? now->group : "", 4, &ng);
    parse(old->group, 4, &og);
    parse(now->passwd ? now->passwd : "", 7, &nu);
    parse(old->passwd, 7, &ou);

    /* Groups first: a user's primary group is mapped through them. */
    for (i = 0; i < og.n; i++)
    {
        const struct line *g = &og.l[i];
        struct line       *have = find(&ng, g->f[0]);

        if (have)
        {
            char *m = members_union(have->f[3], g->f[3]);

            set_field(have, 3, m);
            free(m);
        } else
        {
            uint64_t gid = 0;

            ng.l = rs_xreallocarray(ng.l, ng.n + 1, sizeof(*ng.l));
            line_copy(&ng.l[ng.n], g);
            if (number(g->f[2], &gid))
            {
                char buf[32];

                (void)snprintf(buf, sizeof(buf), "%llu",
                               (unsigned long long)free_id(&ng, 2, gid));
                set_field(&ng.l[ng.n], 2, buf);
            }
            ng.n++;
        }
    }
    for (i = 0; i < ng.n; i++)
    {
        uint64_t gid;

        if (number(ng.l[i].f[2], &gid))
        {
            add_id(&out->gids, &out->ngids, ng.l[i].f[0], gid);
        }
    }

    for (i = 0; i < ou.n; i++)
    {
        const struct line *u = &ou.l[i];
        struct line       *have = find(&nu, u->f[0]);
        const char        *gname = group_name(&og, u->f[3]);
        uint64_t           gid = 0;
        char               gbuf[32];

        /* Its primary group, by name, through the merged groups. */
        gbuf[0] = '\0';
        if (gname && rs_accounts_gid(out, gname, &gid))
        {
            (void)snprintf(gbuf, sizeof(gbuf), "%llu", (unsigned long long)gid);
        }
        if (have)
        {
            if (person(u) || person(have))
            {
                set_field(have, 4, u->f[4]);
                set_field(have, 5, u->f[5]);
                set_field(have, 6, u->f[6]);
                if (gbuf[0])
                {
                    set_field(have, 3, gbuf);
                }
            }
        } else
        {
            uint64_t uid = 0;

            nu.l = rs_xreallocarray(nu.l, nu.n + 1, sizeof(*nu.l));
            line_copy(&nu.l[nu.n], u);
            if (number(u->f[2], &uid))
            {
                char buf[32];

                (void)snprintf(buf, sizeof(buf), "%llu",
                               (unsigned long long)free_id(&nu, 2, uid));
                set_field(&nu.l[nu.n], 2, buf);
            }
            if (gbuf[0])
            {
                set_field(&nu.l[nu.n], 3, gbuf);
            }
            nu.n++;
        }
    }
    for (i = 0; i < nu.n; i++)
    {
        uint64_t uid;

        if (number(nu.l[i].f[2], &uid))
        {
            add_id(&out->uids, &out->nuids, nu.l[i].f[0], uid);
        }
    }

    out->passwd = render(&nu);
    out->group = render(&ng);
    if (now->shadow || old->shadow)
    {
        out->shadow = merge_shadow(&nu, now->shadow, old->shadow, false);
    }
    if (now->gshadow || old->gshadow)
    {
        out->gshadow = merge_shadow(&ng, now->gshadow, old->gshadow, true);
    }
    table_free(&ng);
    table_free(&og);
    table_free(&nu);
    table_free(&ou);
    return true;
}

void rs_accounts_free(struct rs_accounts *a)
{
    size_t i;

    for (i = 0; i < a->nuids; i++)
    {
        free(a->uids[i].name);
    }
    for (i = 0; i < a->ngids; i++)
    {
        free(a->gids[i].name);
    }
    free(a->uids);
    free(a->gids);
    free(a->passwd);
    free(a->group);
    free(a->shadow);
    free(a->gshadow);
    memset(a, 0, sizeof(*a));
}

static bool lookup(const struct rs_id *ids, size_t n, const char *name, uint64_t *out)
{
    size_t i;

    for (i = 0; name && i < n; i++)
    {
        if (strcmp(ids[i].name, name) == 0)
        {
            *out = ids[i].id;
            return true;
        }
    }
    return false;
}

bool rs_accounts_uid(const struct rs_accounts *a, const char *name, uint64_t *out)
{
    return lookup(a->uids, a->nuids, name, out);
}

bool rs_accounts_gid(const struct rs_accounts *a, const char *name, uint64_t *out)
{
    return lookup(a->gids, a->ngids, name, out);
}
