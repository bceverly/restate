/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "sources.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "meta.h"
#include "packages.h"
#include "pgp.h"
#include "run.h"

/* A Release file, or a key, is read up to this much. */
#define RELEASE_MAX ((size_t)32 * 1024 * 1024)

/* ------------------------------------------------------------------------- */
/* Valid-Until                                                                */
/* ------------------------------------------------------------------------- */

/* Days from 1970-01-01 to the date, in the proleptic Gregorian calendar
 * (Howard Hinnant's days_from_civil). */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    int64_t  era;
    unsigned yoe;
    unsigned doy;
    unsigned doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153 * (m + (m > 2 ? (unsigned)-3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

/* A number of at most `max` digits at *p, moving past it. */
static bool digits(const char **p, unsigned max, unsigned long *out)
{
    unsigned n = 0;

    *out = 0;
    while (**p >= '0' && **p <= '9' && n < max)
    {
        *out = *out * 10 + (unsigned long)(**p - '0');
        (*p)++;
        n++;
    }
    return n > 0;
}

/* Whether *p is `c`, moving past it if it is. */
static bool skip_char(const char **p, char c)
{
    if (**p != c)
    {
        return false;
    }
    (*p)++;
    return true;
}

bool rs_sources_valid_until(const char *release, int64_t *when)
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char       *p = release;
    unsigned long     day;
    unsigned long     year;
    unsigned long     h;
    unsigned long     mi;
    unsigned long     s;
    unsigned          month = 0;
    unsigned          i;

    /* The field, at the start of a line of the Release file's header. */
    while (p && strncmp(p, "Valid-Until:", 12) != 0)
    {
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    if (!p)
    {
        return false;
    }
    p += 12;
    p += strspn(p, " \t");
    /* "Sat, " -- the day of the week says nothing the date does not. */
    if (strchr(p, ',') && (size_t)(strchr(p, ',') - p) <= 3)
    {
        p = strchr(p, ',') + 1;
        p += strspn(p, " ");
    }
    if (!digits(&p, 2, &day) || !skip_char(&p, ' '))
    {
        return false;
    }
    for (i = 0; i < 12; i++)
    {
        if (strncmp(p, months + (size_t)3 * i, 3) == 0)
        {
            month = i + 1;
        }
    }
    if (month == 0 || p[3] != ' ')
    {
        return false;
    }
    p += 4;
    if (!digits(&p, 4, &year) || !skip_char(&p, ' ') || !digits(&p, 2, &h) ||
        !skip_char(&p, ':') || !digits(&p, 2, &mi) || !skip_char(&p, ':') || !digits(&p, 2, &s))
    {
        return false;
    }
    if (day < 1 || day > 31 || year < 1970 || h > 23 || mi > 59 || s > 60)
    {
        return false;
    }
    /* apt writes UTC, and reads "UTC", "GMT" and "+0000" alike. */
    p += strspn(p, " ");
    if (strncmp(p, "UTC", 3) != 0 && strncmp(p, "GMT", 3) != 0 && strncmp(p, "+0000", 5) != 0 &&
        strncmp(p, "Z", 1) != 0)
    {
        return false;
    }
    *when = days_from_civil((int64_t)year, month, (unsigned)day) * 86400 +
            (int64_t)(h * 3600 + mi * 60 + s);
    return true;
}

/* ------------------------------------------------------------------------- */
/* The check                                                                  */
/* ------------------------------------------------------------------------- */

/* `key`'s value in the object `obj`, to change it; NULL if it has none. */
static struct rs_jval *member(struct rs_jval *obj, const char *key)
{
    size_t i;

    for (i = 0; obj && obj->type == RS_JOBJECT && i < obj->n; i++)
    {
        if (strcmp(obj->keys[i], key) == 0)
        {
            return &obj->items[i];
        }
    }
    return NULL;
}

static bool has_word(const struct rs_jval *arr, const char *word)
{
    size_t i;

    for (i = 0; arr && arr->type == RS_JARRAY && i < arr->n; i++)
    {
        if (arr->items[i].type == RS_JSTRING && strcmp(arr->items[i].s, word) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s);
    size_t m = strlen(suffix);

    return n >= m && strcmp(s + n - m, suffix) == 0;
}

/* Whether the key at `path` is one apt trusts for a source naming none:
 * trusted.gpg, and the .gpg and .asc files in trusted.gpg.d. */
static bool trusted_by_default(const char *path)
{
    return strcmp(path, "/etc/apt/trusted.gpg") == 0 ||
           (rs_starts_with(path, "/etc/apt/trusted.gpg.d/") &&
            (ends_with(path, ".gpg") || ends_with(path, ".asc")));
}

/* Whether `signed_by` names the key file `path`, as one of its words. */
static bool names_key(const char *signed_by, const char *path)
{
    const char *p = signed_by;
    size_t      n = strlen(path);

    while (*p)
    {
        size_t len;

        p += strspn(p, " \t\n,");
        len = strcspn(p, " \t\n,");
        if (len == n && strncmp(p, path, n) == 0)
        {
            return true;
        }
        p += len;
    }
    return false;
}

static bool write_file(const char *path, const void *data, size_t len)
{
    int     fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    ssize_t w;

    if (fd < 0)
    {
        return false;
    }
    w = write(fd, data, len);
    return close(fd) == 0 && w == (ssize_t)len;
}

/* The keys a source is checked against, each written into `home` as a
 * binary keyring; their paths into *rings. False, with why, if the source
 * names a key the inventory does not have. */
static bool keyrings(const char *home, const struct rs_jval *apt, const char *signed_by,
                     char ***rings, size_t *n, struct rs_buf *why)
{
    const struct rs_jval *keys = rs_jobject_get(apt, "keys");
    /* A Signed-By of fingerprints alone narrows apt's own keys, which is
     * what they are then checked against. */
    bool                  by_path = signed_by && strchr(signed_by, '/');
    size_t                i;

    *rings = NULL;
    *n = 0;
    for (i = 0; keys && keys->type == RS_JARRAY && i < keys->n; i++)
    {
        const struct rs_jval *k = &keys->items[i];
        const char           *path = rs_jobject_str(k, "path");
        const char           *data = rs_jobject_str(k, "data");
        struct rs_buf         raw;
        struct rs_buf         bin;
        char                 *file;
        bool                  ok;

        if (!path || (by_path ? !names_key(signed_by, path) : !trusted_by_default(path)))
        {
            continue;
        }
        if (!data)
        {
            if (by_path)
            {
                rs_buf_addf(why, "its key, %s, %s", path,
                            rs_jobject_get(k, "not_a_key") ? "is not a key" : "is not there");
                return false;
            }
            continue;
        }
        rs_buf_init(&raw);
        rs_buf_init(&bin);
        ok = rs_base64_decode(data, strlen(data), &raw);
        if (ok && rs_pgp_armored(raw.data ? raw.data : "", raw.len))
        {
            ok = rs_pgp_dearmor(raw.data, raw.len, &bin);
        } else if (ok)
        {
            rs_buf_add(&bin, raw.data ? raw.data : "", raw.len);
        }
        file = rs_xasprintf("%s/key%zu.gpg", home, *n);
        if (ok && bin.len > 0 && write_file(file, bin.data, bin.len))
        {
            *rings = rs_xreallocarray(*rings, *n + 1, sizeof(**rings));
            (*rings)[(*n)++] = file;
        } else
        {
            free(file);
        }
        rs_buf_free(&raw);
        rs_buf_free(&bin);
    }
    if (by_path && *n == 0)
    {
        rs_buf_addf(why, "its key, %s, is not there", signed_by);
        return false;
    }
    return true;
}

static void free_rings(char **rings, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        (void)unlink(rings[i]);
        free(rings[i]);
    }
    free(rings);
}

/* The index apt keeps for one URI and suite, copied into `home`: its path
 * there, and for a Release the path of its detached signature too. NULL if
 * apt has none. */
static char *release_copy(const char *root, const char *home, const char *uri, const char *suite,
                          bool flat, char **detached)
{
    struct rs_buf full;
    struct rs_buf name;
    struct rs_buf data;
    char         *rel;
    char         *copy = NULL;
    bool          slash = uri[0] != '\0' && uri[strlen(uri) - 1] == '/';

    *detached = NULL;
    rs_buf_init(&full);
    rs_buf_init(&name);
    rs_buf_addf(&full, "%s%s%s%s", uri, slash ? "" : "/", flat ? "" : "dists/", suite);
    if (full.len > 0 && full.data[full.len - 1] != '/')
    {
        rs_buf_addc(&full, '/');
    }
    rs_apt_uri_file(&name, full.data);
    rel = rs_xasprintf("/var/lib/apt/lists/%sInRelease", name.data ? name.data : "");
    if (rs_read_beneath(root, rel, RELEASE_MAX, &data))
    {
        copy = rs_xasprintf("%s/InRelease", home);
        if (!write_file(copy, data.data ? data.data : "", data.len))
        {
            free(copy);
            copy = NULL;
        }
        rs_buf_free(&data);
    } else
    {
        struct rs_buf sig;
        char         *srel = rs_xasprintf("/var/lib/apt/lists/%sRelease.gpg",
                                          name.data ? name.data : "");

        free(rel);
        rel = rs_xasprintf("/var/lib/apt/lists/%sRelease", name.data ? name.data : "");
        if (rs_read_beneath(root, rel, RELEASE_MAX, &data))
        {
            copy = rs_xasprintf("%s/Release", home);
            *detached = rs_xasprintf("%s/Release.gpg", home);
            if (!write_file(copy, data.data ? data.data : "", data.len))
            {
                free(copy);
                copy = NULL;
            }
            if (rs_read_beneath(root, srel, RELEASE_MAX, &sig))
            {
                (void)write_file(*detached, sig.data ? sig.data : "", sig.len);
                rs_buf_free(&sig);
            }
            rs_buf_free(&data);
        }
        free(srel);
    }
    free(rel);
    rs_buf_free(&full);
    rs_buf_free(&name);
    return copy;
}

/* The time `when` as a date, for a message. */
static void add_date(struct rs_buf *b, int64_t when)
{
    struct rs_time t;
    char           buf[RS_TIME_STR_MAX];

    t.sec = when;
    t.nsec = 0;
    t.set = true;
    rs_time_format(&t, buf);
    rs_buf_add(b, buf, 10);
}

/* One URI and suite: why apt cannot use it, into `why`; nothing if it can. */
static void check_one(const char *root, const char *home, const struct rs_jval *apt,
                      const char *signed_by, const char *uri, const char *suite, bool flat,
                      int64_t now, struct rs_buf *why)
{
    char               **rings = NULL;
    size_t               nrings = 0;
    char                *detached = NULL;
    char                *release = release_copy(root, home, uri, suite, flat, &detached);
    struct rs_buf        status;
    struct rs_buf        err;
    struct rs_pgp_signer signer;
    bool                 ok = true;

    rs_buf_init(&status);
    rs_buf_init(&err);
    /* Each step says why it failed, into `why`, and the next is not taken. */
    if (!release)
    {
        rs_buf_addstr(why, "apt has no index of it: it has never been updated, or apt could "
                           "not fetch it");
        ok = false;
    }
    ok = ok && keyrings(home, apt, signed_by, &rings, &nrings, why);
    if (ok && !rs_pgp_gpgv(home, (const char *const *)rings, nrings, detached ? detached : release,
                           detached ? release : NULL, &status, &err))
    {
        rs_buf_addf(why, "it could not be checked: %s", err.data ? err.data : "");
        ok = false;
    }
    ok = ok && rs_pgp_verdict(status.data ? status.data : "", &signer, why);
    if (ok)
    {
        struct rs_buf text;
        int64_t       until;

        if (rs_read_beneath(home, detached ? "/Release" : "/InRelease", RELEASE_MAX, &text))
        {
            if (rs_sources_valid_until(text.data ? text.data : "", &until) && until < now)
            {
                rs_buf_addstr(why, "its index expired on ");
                add_date(why, until);
                rs_buf_addstr(why, " and has not been updated since");
            }
            rs_buf_free(&text);
        }
    }
    if (release)
    {
        (void)unlink(release);
    }
    if (detached)
    {
        (void)unlink(detached);
    }
    free(release);
    free(detached);
    free_rings(rings, nrings);
    rs_buf_free(&status);
    rs_buf_free(&err);
}

size_t rs_sources_check(const char *root, struct rs_jval *packages, int64_t now, bool *checked)
{
    struct rs_jval *apt = member(packages, "apt");
    struct rs_jval *sources = member(apt, "sources");
    struct rs_buf   err;
    char           *home;
    size_t          problems = 0;
    size_t          i;

    *checked = false;
    if (!sources || sources->type != RS_JARRAY || !rs_program_path(RS_PROG_GPGV))
    {
        return 0;
    }
    rs_buf_init(&err);
    home = rs_pgp_home(&err);
    rs_buf_free(&err);
    if (!home)
    {
        return 0;
    }
    *checked = true;
    for (i = 0; i < sources->n; i++)
    {
        struct rs_jval       *src = &sources->items[i];
        const struct rs_jval *uris = rs_jobject_get(src, "uris");
        const struct rs_jval *suites = rs_jobject_get(src, "suites");
        const struct rs_jval *comps = rs_jobject_get(src, "components");
        const char           *signed_by = rs_jobject_str(src, "signed_by");
        bool                  flat = !comps || comps->type != RS_JARRAY || comps->n == 0;
        struct rs_buf         why;
        size_t                u;
        size_t                s;

        /* Disabled, source packages only, or a key apt reads from the
         * source file itself, which the inventory does not carry. */
        if (rs_jobject_get(src, "enabled") || !has_word(rs_jobject_get(src, "types"), "deb") ||
            (signed_by && strcmp(signed_by, "the key in this file") == 0) || !uris ||
            uris->type != RS_JARRAY || !suites || suites->type != RS_JARRAY)
        {
            continue;
        }
        rs_buf_init(&why);
        for (u = 0; u < uris->n; u++)
        {
            for (s = 0; s < suites->n; s++)
            {
                struct rs_buf one;

                if (uris->items[u].type != RS_JSTRING || suites->items[s].type != RS_JSTRING)
                {
                    continue;
                }
                rs_buf_init(&one);
                check_one(root, home, apt, signed_by && *signed_by ? signed_by : NULL,
                          uris->items[u].s, suites->items[s].s, flat, now, &one);
                if (one.len > 0)
                {
                    rs_buf_addf(&why, "%s%s %s: %s", why.len ? "; " : "", uris->items[u].s,
                                suites->items[s].s, one.data);
                }
                rs_buf_free(&one);
            }
        }
        if (why.len > 0)
        {
            rs_jobj_str(src, "problem", why.data);
            problems++;
        }
        rs_buf_free(&why);
    }
    rs_pgp_home_remove(home);
    return problems;
}
