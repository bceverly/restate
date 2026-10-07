/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Merging the old machine's accounts into the new one's.
 *
 * A file's owner is a number, and the number means whatever the system's
 * /etc/passwd says. On a rebuilt machine the packages installed before the
 * restore have created their own system users, numbered in the order the
 * packages went in -- postgres may be 128 where it was 125 -- and the
 * installer has made an account of its own. Laying the old /etc/passwd over
 * that would give those packages' files to whoever has their numbers in the
 * old file. So the account files are merged, not replaced:
 *
 *   - a user or group both have keeps the new system's number, since the new
 *     packages' files already carry it; a person (root, and uids 1000 up)
 *     keeps the old account's name, home directory and shell
 *   - every password, and its aging, is the old shadow's and gshadow's
 *   - a group's members are both systems' members
 *   - a user or group only the old system had keeps its old number if it is
 *     free, or takes the next free one in its range (a system id counting
 *     down from 999, a person's up from 1000)
 *
 * and every restored file's owner is then mapped by the user and group
 * names the index records, through the merged accounts.
 */
#ifndef RESTATE_ACCOUNTS_H
#define RESTATE_ACCOUNTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

/* The four account files of one system, as text; NULL for one that is not
 * there. */
struct rs_account_files {
    const char *passwd;
    const char *group;
    const char *shadow;
    const char *gshadow;
};

struct rs_id {
    char    *name;
    uint64_t id;
};

struct rs_accounts {
    char         *passwd;    /* the merged files */
    char         *group;
    char         *shadow;    /* NULL if neither system had one */
    char         *gshadow;
    struct rs_id *uids;      /* every user, by name */
    size_t        nuids;
    struct rs_id *gids;
    size_t        ngids;
};

/*
 * Merges `old` (the image's) into `now` (the system being restored onto).
 * False, with the reason in `err`, if `old` has no passwd or group.
 */
bool rs_accounts_merge(const struct rs_account_files *now, const struct rs_account_files *old,
                       struct rs_accounts *out, struct rs_buf *err);
void rs_accounts_free(struct rs_accounts *a);

/* The number the merged accounts give `name`; false if they have no such
 * user (or group). */
bool rs_accounts_uid(const struct rs_accounts *a, const char *name, uint64_t *out);
bool rs_accounts_gid(const struct rs_accounts *a, const char *name, uint64_t *out);

#endif /* RESTATE_ACCOUNTS_H */
