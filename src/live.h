/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * What is running that writes to files a capture keeps: database servers,
 * virtual machines and containers, found from /proc (Linux) and nothing else.
 * A file copied while one of these writes to it can be copied half old and
 * half new -- a database's pages from two different moments, a VM's disk in
 * the middle of a write -- and come back unusable. So capture names each one
 * it finds, and with --quiesce pauses it while its own files are copied.
 *
 *   postgresql   a postmaster:      its data directory (-D, or where it runs)
 *                                   and the tablespaces linked from it
 *   mysql        mysqld, mariadbd:  --datadir, or where it runs
 *   mongodb      mongod:            --dbpath, the dbPath in its --config, or
 *                                   /var/lib/mongodb
 *   redis        redis-server:      where it runs, which is its "dir"
 *   libvirt      a QEMU VM:         every regular file it holds open for
 *                                   writing -- its disks and its NVRAM
 *   lxd          an LXD container:  the container's directory
 *   docker       dockerd, with containers running: its volumes
 *
 * Every path is the real one, with no symlink in it, because the walk that
 * copies it never follows one.
 */
#ifndef RESTATE_LIVE_H
#define RESTATE_LIVE_H

#include <stdbool.h>
#include <stddef.h>

#include "util.h"

struct rs_live {
    const char    *kind;    /* "postgresql": also the name of its hook */
    char          *name;    /* "18-main", a VM's or a container's name */
    long           pid;
    unsigned long  uid;     /* whose it is: a VM may be a user's own */
    char         **paths;   /* sorted, none beneath another */
    size_t         npaths;
};

/*
 * Everything running under `proc` (normally "/proc"), sorted by kind and
 * name. None, and no error, where there is no /proc.
 */
void rs_live_detect(const char *proc, struct rs_live **out, size_t *n);

void rs_live_free(struct rs_live *l, size_t n);

/* "PostgreSQL", "a QEMU VM", for messages. */
const char *rs_live_what(const struct rs_live *l);

/* The command that would stop or pause it by hand, into `out`. */
void rs_live_hint(const struct rs_live *l, struct rs_buf *out);

/*
 * The pieces read from /proc, exposed for the tests and the fuzzer:
 *
 * a process's cmdline (arguments separated by NUL) split into *argv, each a
 * copy, *argc of them; the uid and parent pid from its status file (false if
 * either is missing); and the "flags:" from an fdinfo file, in octal.
 */
void rs_live_split_args(const char *buf, size_t len, char ***argv, size_t *argc);
bool rs_live_parse_status(const char *text, unsigned long *uid, long *ppid);
bool rs_live_parse_fdflags(const char *text, unsigned long *flags);

/* The storage.dbPath in a mongod configuration file's text, or NULL. */
char *rs_live_mongo_dbpath(const char *text);

#endif /* RESTATE_LIVE_H */
