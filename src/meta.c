/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "meta.h"

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/* ------------------------------------------------------------------------- */
/* Calendar arithmetic (Howard Hinnant's days_from_civil and its inverse)    */
/* ------------------------------------------------------------------------- */

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

static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d)
{
    int64_t  era;
    unsigned doe;
    unsigned yoe;
    unsigned doy;
    unsigned mp;

    z += 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (unsigned)(z - era * 146097);
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = (int64_t)yoe + era * 400 + (*m <= 2);
}

/* Floor division, so that a time before 1970 lands on the right day. */
static int64_t floor_div(int64_t a, int64_t b)
{
    int64_t q = a / b;

    if ((a % b != 0) && ((a < 0) != (b < 0)))
    {
        q--;
    }
    return q;
}

void rs_time_format(const struct rs_time *t, char out[RS_TIME_STR_MAX])
{
    int64_t  days;
    int64_t  secs;
    int64_t  year;
    unsigned month;
    unsigned day;

    /* Beyond about +-292 billion years the day count would overflow; years
     * outside four digits are not real timestamps either way. */
    if (t->sec < -62167219200LL || t->sec > 253402300799LL)
    {
        (void)snprintf(out, RS_TIME_STR_MAX, "@%lld.%09u", (long long)t->sec,
                       (unsigned)t->nsec % 1000000000u);
        return;
    }
    days = floor_div(t->sec, 86400);
    secs = t->sec - days * 86400;
    civil_from_days(days, &year, &month, &day);
    (void)snprintf(out, RS_TIME_STR_MAX, "%04u-%02u-%02uT%02u:%02u:%02u.%09uZ",
                   (unsigned)year, month, day, (unsigned)(secs / 3600),
                   (unsigned)(secs / 60 % 60), (unsigned)(secs % 60),
                   (unsigned)t->nsec % 1000000000u);
}

/* Exactly `n` decimal digits at `s`. */
static bool digits(const char *s, size_t n, int64_t *out)
{
    int64_t v = 0;
    size_t  i;

    for (i = 0; i < n; i++)
    {
        if (s[i] < '0' || s[i] > '9')
        {
            return false;
        }
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

static bool parse_epoch(const char *s, struct rs_time *out)
{
    const char *p = s + 1;
    bool        neg = false;
    int64_t     sec = 0;
    int64_t     nsec;
    size_t      n = 0;

    if (*p == '-')
    {
        neg = true;
        p++;
    }
    while (p[n] >= '0' && p[n] <= '9')
    {
        if (n >= 18)
        {
            return false;
        }
        sec = sec * 10 + (p[n] - '0');
        n++;
    }
    if (n == 0 || p[n] != '.' || !digits(p + n + 1, 9, &nsec) || p[n + 10] != '\0')
    {
        return false;
    }
    out->sec = neg ? -sec : sec;
    out->nsec = (int32_t)nsec;
    out->set = true;
    return true;
}

bool rs_time_parse(const char *s, struct rs_time *out)
{
    int64_t y;
    int64_t mo;
    int64_t d;
    int64_t h;
    int64_t mi;
    int64_t se;
    int64_t ns;
    static const unsigned char mdays[] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    if (s[0] == '@')
    {
        return parse_epoch(s, out);
    }
    if (strlen(s) != 30 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != '.' || s[29] != 'Z')
    {
        return false;
    }
    if (!digits(s, 4, &y) || !digits(s + 5, 2, &mo) || !digits(s + 8, 2, &d) ||
        !digits(s + 11, 2, &h) || !digits(s + 14, 2, &mi) || !digits(s + 17, 2, &se) ||
        !digits(s + 20, 9, &ns))
    {
        return false;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > mdays[mo - 1] || h > 23 || mi > 59 || se > 59)
    {
        return false;
    }
    if (mo == 2 && d == 29 && !((y % 4 == 0 && y % 100 != 0) || y % 400 == 0))
    {
        return false;
    }
    out->sec = days_from_civil(y, (unsigned)mo, (unsigned)d) * 86400 + h * 3600 + mi * 60 + se;
    out->nsec = (int32_t)ns;
    out->set = true;
    return true;
}

bool rs_time_equal(const struct rs_time *a, const struct rs_time *b)
{
    if (a->set != b->set)
    {
        return false;
    }
    return !a->set || (a->sec == b->sec && a->nsec == b->nsec);
}

/* ------------------------------------------------------------------------- */
/* stat(2), per system                                                       */
/* ------------------------------------------------------------------------- */

/* macOS and NetBSD spell the POSIX.1-2008 st_atim as st_atimespec. */
#if defined(__APPLE__) || defined(__NetBSD__)
#define RS_ATIM st_atimespec
#define RS_MTIM st_mtimespec
#define RS_CTIM st_ctimespec
#else
#define RS_ATIM st_atim
#define RS_MTIM st_mtim
#define RS_CTIM st_ctim
#endif

static void from_timespec(struct rs_time *t, int64_t sec, long nsec)
{
    t->sec = sec;
    t->nsec = (nsec >= 0 && nsec < 1000000000L) ? (int32_t)nsec : 0;
    t->set = true;
}

void rs_stat_times(const struct stat *st, struct rs_time *atime,
                   struct rs_time *mtime, struct rs_time *ctime)
{
    from_timespec(atime, (int64_t)st->RS_ATIM.tv_sec, (long)st->RS_ATIM.tv_nsec);
    from_timespec(mtime, (int64_t)st->RS_MTIM.tv_sec, (long)st->RS_MTIM.tv_nsec);
    from_timespec(ctime, (int64_t)st->RS_CTIM.tv_sec, (long)st->RS_CTIM.tv_nsec);
}

void rs_birth_time_at(int dirfd, const char *name, const struct stat *st,
                      struct rs_time *out)
{
    memset(out, 0, sizeof(*out));
#if defined(__linux__) && defined(STATX_BTIME)
    {
        struct statx stx;

        (void)st;
        /* AT_STATX_DONT_SYNC: a network filesystem may otherwise go and ask
         * the server, for a timestamp that is a nice-to-have. */
        if (statx(dirfd, name, AT_SYMLINK_NOFOLLOW | AT_STATX_DONT_SYNC, STATX_BTIME,
                  &stx) == 0 && (stx.stx_mask & STATX_BTIME))
        {
            from_timespec(out, (int64_t)stx.stx_btime.tv_sec, (long)stx.stx_btime.tv_nsec);
        }
    }
#elif defined(__APPLE__) || defined(__NetBSD__)
    (void)dirfd;
    (void)name;
    from_timespec(out, (int64_t)st->st_birthtimespec.tv_sec,
                  (long)st->st_birthtimespec.tv_nsec);
#elif defined(__FreeBSD__) || defined(__DragonFly__)
    (void)dirfd;
    (void)name;
    from_timespec(out, (int64_t)st->st_birthtim.tv_sec, (long)st->st_birthtim.tv_nsec);
#elif defined(__OpenBSD__)
    (void)dirfd;
    (void)name;
    from_timespec(out, (int64_t)st->__st_birthtim.tv_sec, (long)st->__st_birthtim.tv_nsec);
#else
    (void)dirfd;
    (void)name;
    (void)st;
#endif
    /* The BSDs report a birth time of -1 (or 0) on a filesystem that does not
     * keep one; that is "unknown", not the last second of 1969. */
    if (out->set && out->sec <= 0)
    {
        out->set = false;
        out->sec = 0;
        out->nsec = 0;
    }
}

/* ------------------------------------------------------------------------- */
/* uid and gid names                                                         */
/* ------------------------------------------------------------------------- */

struct name_cache {
    uint64_t *ids;
    char    **names;   /* NULL for "looked up, has no name" */
    size_t    count;
    size_t    cap;
};

static struct name_cache users;
static struct name_cache groups;

static const char *cached(struct name_cache *c, uint64_t id, bool is_user)
{
    size_t      i;
    const char *found = NULL;

    for (i = 0; i < c->count; i++)
    {
        if (c->ids[i] == id)
        {
            return c->names[i];
        }
    }
    if (is_user)
    {
        const struct passwd *pw = getpwuid((uid_t)id);

        found = pw ? pw->pw_name : NULL;
    } else
    {
        const struct group *gr = getgrgid((gid_t)id);

        found = gr ? gr->gr_name : NULL;
    }
    if (c->count == c->cap)
    {
        c->cap = c->cap ? c->cap * 2 : 16;
        c->ids = rs_xreallocarray(c->ids, c->cap, sizeof(*c->ids));
        c->names = rs_xreallocarray(c->names, c->cap, sizeof(*c->names));
    }
    c->ids[c->count] = id;
    c->names[c->count] = found ? rs_xstrdup(found) : NULL;
    return c->names[c->count++];
}

const char *rs_user_name(uint64_t uid)
{
    return cached(&users, uid, true);
}

const char *rs_group_name(uint64_t gid)
{
    return cached(&groups, gid, false);
}

static void cache_free(struct name_cache *c)
{
    size_t i;

    for (i = 0; i < c->count; i++)
    {
        free(c->names[i]);
    }
    free(c->ids);
    free(c->names);
    memset(c, 0, sizeof(*c));
}

void rs_name_cache_free(void)
{
    cache_free(&users);
    cache_free(&groups);
}
