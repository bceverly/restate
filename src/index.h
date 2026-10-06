/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The index: everything restate knows about every recorded path, as JSON.
 *
 *   {
 *     "format": "restate-index",
 *     "version": 1,
 *     "restate": "0.1.0.0",
 *     "root": "/",
 *     "os": "linux",
 *     "host": "web01",
 *     "created": "2026-10-03T14:00:00.000000000Z",
 *     "hash": "sha256",
 *     "hashed": true,
 *     "content": "state",
 *     "count": 2,
 *     "machine": { ...disks, partitions, firmware; see machine.h... },
 *     "entries": [
 *       {"path": "/etc", "name": "etc", "type": "directory", ...},
 *       {"path": "/etc/hosts", "name": "hosts", "type": "file", ...}
 *     ]
 *   }
 *
 * One entry per line, sorted by path byte by byte, so the file is readable,
 * greppable, and comparable with the ordinary diff(1) as well as with
 * `restate diff`. Each entry carries:
 *
 *   path, name        the full path in the scanned tree, and its last part
 *   type              file, directory, symlink, char, block, fifo
 *   class             ephemeral, expendable, baseline, state
 *   mode              the permission bits as an octal string, "0644"
 *   uid, gid          numbers, and user, group: the names behind them, which
 *                     is what a restore onto a reinstalled system has to map by
 *   size, nlink       bytes (files and symlinks), and the hard link count
 *   device, inode     which file this is: two entries with the same pair are
 *                     hard links to one file
 *   rdev              a device node's device number
 *   atime, mtime,     access, modification and status-change times, and the
 *   ctime, btime      birth (creation) time where the system records one --
 *                     null where it does not. Nanoseconds throughout.
 *   sha256            a regular file's content digest, or null; with
 *                     "unreadable": true where the file could not be read
 *   target            a symlink's target
 *   stored            where the file's content is inside the image, if it is
 *
 * JSON strings must be UTF-8 and a file name need not be. A path or target
 * that is not valid UTF-8 is written twice: lossily in "path" (so it can be
 * read) and exactly in "path_base64" (which is what is read back).
 */
#ifndef RESTATE_INDEX_H
#define RESTATE_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "json.h"
#include "meta.h"
#include "rules.h"
#include "sha256.h"
#include "util.h"

#define RS_INDEX_FORMAT  "restate-index"
#define RS_INDEX_VERSION 1

enum rs_hash_state {
    RS_HASH_NONE = 0,     /* not a regular file, or not hashed */
    RS_HASH_PRESENT,      /* a digest */
    RS_HASH_UNREADABLE    /* a regular file that could not be read */
};

/* How copying a file's content into an image went; not written to the index. */
enum rs_copy {
    RS_COPY_OK = 0,
    RS_COPY_GREW,         /* written to while read: kept as it was at the start */
    RS_COPY_SHRANK,       /* cut short while read: what is stored is not the file */
    RS_COPY_READ_ERROR    /* a read failed: copy_errno says how */
};

struct rs_entry {
    char              *path;     /* absolute in the scanned tree */
    char              *target;   /* a symlink's target, else NULL */
    char              *user;     /* NULL where the uid has no name */
    char              *group;
    char              *stored;   /* member name inside the image, or NULL */
    char               type;     /* f d l c b p */
    uint32_t           mode;     /* permission bits, at most 07777 */
    uint64_t           uid;
    uint64_t           gid;
    uint64_t           size;
    uint64_t           nlink;
    uint64_t           dev;
    uint64_t           ino;
    uint64_t           rdev;
    struct rs_time     atime;
    struct rs_time     mtime;
    struct rs_time     ctime;
    struct rs_time     btime;
    enum rs_class      cls;
    enum rs_hash_state hash_state;
    char               hash[RS_SHA256_HEX_SIZE];
    enum rs_copy       copy;       /* see rs_copy; transient */
    int                copy_errno;
};

struct rs_index {
    struct rs_entry *entries;
    size_t           count;
    size_t           cap;
    char            *root;
    char            *os;
    char            *host;
    char            *created;
    char            *version;   /* the restate that wrote it */
    char            *content;   /* "none", "state" or "state+baseline" */
    bool             hashed;
    struct rs_jval   machine;   /* the machine underneath, or null; see machine.h */
};

void rs_index_init(struct rs_index *ix);
void rs_index_free(struct rs_index *ix);
void rs_entry_free(struct rs_entry *e);

/* Appends `e`, taking ownership of every string in it. */
void rs_index_add(struct rs_index *ix, const struct rs_entry *e);
/* Sorts by path; false, naming the path in `err`, on a duplicate. */
bool rs_index_sort(struct rs_index *ix, struct rs_buf *err);
/* Binary search; the index must be sorted. */
const struct rs_entry *rs_index_find(const struct rs_index *ix, const char *path);

bool rs_index_write(const struct rs_index *ix, FILE *out);

bool rs_index_parse(struct rs_index *ix, const char *text, size_t len,
                    const char *name, struct rs_buf *err);

/* "file", "directory", ... and back. */
const char *rs_type_name(char type);
bool        rs_type_parse(const char *name, char *out);

/* For showing a path to a person on one line: control characters, a backslash
 * and a tab become \t, \n, \\ and \xHH. Nothing else is touched. */
void rs_escape(struct rs_buf *out, const char *s);

/*
 * A clean absolute path: "/" or "/" followed by non-empty components, none of
 * them "." or "..". Every path read from an index must be one, because an
 * index is input -- and a restore that trusted "/etc/../../x" would write
 * wherever that pointed.
 */
bool rs_path_is_clean(const char *path);

#endif /* RESTATE_INDEX_H */
