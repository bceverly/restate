/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * File metadata that every system has, spelled differently on each.
 *
 * Timestamps with nanoseconds (st_atim on Linux and the BSDs, st_atimespec on
 * macOS), the birth time (statx(2) on Linux, st_birthtim or st_birthtimespec
 * on the BSDs and macOS, and nothing at all on some filesystems), and the
 * names behind a uid and gid. One module, so the rest of the program never has
 * an #ifdef for any of it.
 *
 * Times are written as ISO 8601 UTC with nine fractional digits,
 * "2026-10-03T14:05:09.123456789Z", converted with pure arithmetic rather
 * than gmtime(3) so the answer is the same on every system and every year.
 */
#ifndef RESTATE_META_H
#define RESTATE_META_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>

struct rs_time {
    int64_t sec;    /* seconds since 1970-01-01T00:00:00Z */
    int32_t nsec;   /* 0 .. 999999999 */
    bool    set;    /* false: the system did not say (a birth time, usually) */
};

/* "YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ". Years outside 0000-9999 -- which a hostile
 * or broken filesystem can report -- are written "@SECONDS.NNNNNNNNN" instead,
 * which the parser accepts too. */
#define RS_TIME_STR_MAX 64
void rs_time_format(const struct rs_time *t, char out[RS_TIME_STR_MAX]);
bool rs_time_parse(const char *s, struct rs_time *out);
bool rs_time_equal(const struct rs_time *a, const struct rs_time *b);

/* The access, modification and status-change times from a stat. */
void rs_stat_times(const struct stat *st, struct rs_time *atime,
                   struct rs_time *mtime, struct rs_time *ctime);

/*
 * The birth time of `name` relative to `dirfd`, without following a symlink.
 * Sets out->set to false where the system or the filesystem does not record
 * one; that is an answer, not an error.
 */
void rs_birth_time_at(int dirfd, const char *name, const struct stat *st,
                      struct rs_time *out);

/* The names behind an id, or NULL where there is none. Cached: a scan asks the
 * same handful of questions a million times, and each uncached answer may be a
 * trip to LDAP. The strings belong to the cache. */
const char *rs_user_name(uint64_t uid);
const char *rs_group_name(uint64_t gid);
void        rs_name_cache_free(void);

#endif /* RESTATE_META_H */
