/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Which package put each file there, and what it put there.
 *
 * The baseline is the vendor's files for the packages installed now, and
 * the package manager already knows what those are. dpkg keeps, for every
 * package installed:
 *
 *   /var/lib/dpkg/info/NAME.list      every path the package installed
 *   /var/lib/dpkg/info/NAME.md5sums   "DIGEST  PATH" for each regular file
 *                                     (relative, the leading slash dropped)
 *   /var/lib/dpkg/status              "Conffiles:" lines, " PATH DIGEST", for
 *                                     the configuration files it shipped,
 *                                     "obsolete" after one it no longer does
 *   /var/lib/dpkg/diversions          FROM, TO and the diverting package, in
 *                                     threes: a file another package (or the
 *                                     administrator, ":") moved aside
 *
 * (NAME is "name:arch" for a package installed for several architectures.)
 * From those a scan knows, for any path, whether a package owns it and what
 * its content was when the package put it there: a file that still matches
 * is the package's and need not be kept; one that does not has been changed
 * and must be; and a file no package owns, where only packages put files,
 * was put there by hand.
 *
 * Everything is read beneath the scanned root, one directory at a time and
 * never through a symlink, and every file is text from the tree being
 * scanned: a line that is not what dpkg writes is passed over.
 */
#ifndef RESTATE_PKGDB_H
#define RESTATE_PKGDB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "md5.h"

#define RS_PKGFILE_MD5      0x01u   /* md5 holds the digest it was installed with */
#define RS_PKGFILE_CONFFILE 0x02u
#define RS_PKGFILE_OBSOLETE 0x04u   /* a conffile its package no longer ships */

struct rs_pkgfile {
    char         *path;
    uint32_t      pkg;               /* an index into names */
    unsigned char flags;
    unsigned char md5[RS_MD5_SIZE];
};

struct rs_diversion {
    char *from;
    char *to;
    char *by;                        /* the diverting package; ":" the administrator */
};

struct rs_pkgdb {
    char               **names;      /* "name" or "name:arch", as dpkg names its files */
    size_t               nnames;
    struct rs_pkgfile   *files;      /* sorted by path once loaded */
    size_t               nfiles;
    size_t               cap;
    struct rs_diversion *div;
    size_t               ndiv;
};

void rs_pkgdb_init(struct rs_pkgdb *db);
void rs_pkgdb_free(struct rs_pkgdb *db);

/*
 * Reads dpkg's database beneath `root`. False if there is none -- not a
 * Debian system, or not one dpkg has installed anything on -- which is not an
 * error: the scan then classifies by its rules alone.
 */
bool rs_pkgdb_load(struct rs_pkgdb *db, const char *root);

/*
 * The packaged files at `path`: how many, the first at *out, all of them
 * adjacent. Several packages can own one path -- a directory, or a file a
 * package for each architecture ships the same -- and a path under /bin,
 * /sbin or /lib* is found under /usr as well, and the other way round, as
 * merged /usr has them.
 */
size_t rs_pkgdb_lookup(const struct rs_pkgdb *db, const char *path,
                       const struct rs_pkgfile **out);

/* The package that owns `f`, as dpkg names it, without any ":arch". */
const char *rs_pkgdb_package(const struct rs_pkgdb *db, const struct rs_pkgfile *f,
                             size_t *len);

/* The parts rs_pkgdb_load is made of, exposed for the unit tests and the
 * fuzzer. Each takes the text of one file; rs_pkgdb_sort finishes. */
void rs_pkgdb_parse_diversions(struct rs_pkgdb *db, const char *text);
/* Adds every installed package's conffiles, and the name of each package
 * with files installed to `names`; returns how many names it added. */
size_t rs_pkgdb_parse_status(struct rs_pkgdb *db, const char *text);
void rs_pkgdb_parse_md5sums(struct rs_pkgdb *db, uint32_t pkg, const char *text);
void rs_pkgdb_parse_list(struct rs_pkgdb *db, uint32_t pkg, const char *text);
void rs_pkgdb_sort(struct rs_pkgdb *db);

#endif /* RESTATE_PKGDB_H */
