/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Where a repository's files are kept, and the few things repo.c does with
 * them.
 *
 * Every file a repository has is named here relative to its top --
 * "restate-repository", "packs/NAME.idx", "snapshots/NAME/kit" -- and every
 * read, write, listing and lock of one goes through a store. The local store
 * is a directory: a disk, or a share mounted as one (NFS, SMB, exFAT, FAT),
 * and what it does is exactly what restate has always done there. Another
 * kind of store -- a repository behind restate-proxy -- does the same things
 * some other way, or says it cannot: what repo.c asks of one is all a store
 * has to do.
 *
 * A file is written beside the name it will have, under a name of its own
 * (".NAME.tmp"), and renamed into place once it is whole: a reader sees a
 * file there whole or not at all. Messages name a file by rs_store_path(),
 * which is where it is: "DIR/packs/NAME.idx".
 *
 * There is one kind of store so far, the local one, and these functions are
 * it; a second kind dispatches from them.
 */
#ifndef RESTATE_STORE_H
#define RESTATE_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "util.h"

struct rs_store;

/* The store a repository's name on the command line, `where`, names: a
 * directory, so far, always. */
struct rs_store *rs_store_at(const char *where);
/* A repository in the directory `dir`, which need not exist yet. "" is a
 * store whose names are paths, as given: a file anywhere on this machine. */
struct rs_store *rs_store_local(const char *dir);
void rs_store_free(struct rs_store *st);

/*
 * From now on, every path at or below one of `dirs` -- each opened now -- is
 * reached through a descriptor open on it, with openat(2) and the rest, and
 * not by its path: for a process about to enter FreeBSD's capability mode,
 * where a path is nothing and a descriptor is all there is. Paths elsewhere
 * are reached as they always are. False, saying why, if one of `dirs`
 * cannot be opened. rs_store_unconfine forgets them, for the tests.
 */
bool rs_store_confine(const char *const *dirs, size_t n, struct rs_buf *err);
void rs_store_unconfine(void);

/* Where the store is, for messages: the directory, for a local one. */
const char *rs_store_where(const struct rs_store *st);
/* Where `name` is, for messages: "DIR/NAME" -- or "DIR", for "", which names
 * the top itself wherever a name is asked for. Freed by the caller. */
char *rs_store_path(const struct rs_store *st, const char *name);
/* The directory a local store is, for what only a directory can do (protect's
 * flags and ACLs); NULL for a store that is not one. */
const char *rs_store_local_dir(const struct rs_store *st);

/* What is at a name, not following a symbolic link there. */
enum rs_store_kind {
    RS_STORE_FILE,    /* a regular file */
    RS_STORE_DIR,     /* a directory */
    RS_STORE_OTHER    /* anything else: a link, a device, ... */
};

struct rs_store_stat {
    enum rs_store_kind kind;
    uint64_t           size;
    int64_t            mtime;    /* seconds since the epoch */
};

/* 0, or -1 with errno -- ENOENT where there is nothing. */
int rs_store_stat(const struct rs_store *st, const char *name, struct rs_store_stat *out);
/* Whether `name` is a regular file. */
bool rs_store_is_file(const struct rs_store *st, const char *name);

/* The entries of the directory `name` that `keep` accepts -- each of which it
 * may give another name, into *out, which the list then holds -- sorted; NULL
 * with *n 0 if it has none, or cannot be listed, which errno then says (it is
 * 0 for an empty one). */
typedef bool (*rs_store_keep)(const struct rs_store *st, const char *dir, const char *name,
                              void *ctx, char **out);
char **rs_store_list(const struct rs_store *st, const char *name, rs_store_keep keep, void *ctx,
                     size_t *n);
/* rs_store_list's keep that takes every entry but "." and "..", as it is. */
bool rs_store_keep_all(const struct rs_store *st, const char *dir, const char *name, void *ctx,
                       char **out);

/* `name` open for reading, from its start: a descriptor, or -1 with errno.
 * Never through a symbolic link. */
int rs_store_open(const struct rs_store *st, const char *name);
/* The same from `offset` on, for what reads a pack from a segment's start. */
int rs_store_open_at(const struct rs_store *st, const char *name, uint64_t offset);
/* Up to `max` bytes from the start of `name`, without waiting on anything
 * there that would make an open wait (a FIFO): how many, or -1 with errno. */
ssize_t rs_store_peek(const struct rs_store *st, const char *name, void *buf, size_t max);
/* The whole of `name`, up to `max` bytes, into `out` -- which is always
 * initialized, and NUL-terminated -- or false, and why into `err`. */
bool rs_store_read(const struct rs_store *st, const char *name, size_t max, struct rs_buf *out,
                   struct rs_buf *err);

/* A new file `name`, 0600, open for writing: a descriptor, or -1 with errno
 * (EEXIST if something is there). */
int rs_store_create(const struct rs_store *st, const char *name);
/* `len` bytes into a new file `name`, flushed to disk; on failure, nothing
 * is left there. */
bool rs_store_write_new(const struct rs_store *st, const char *name, const void *data, size_t len,
                        struct rs_buf *err);
/* The same into a directory protect may have made immutable: through its
 * flags, where it set them, as root. */
bool rs_store_write_new_thawed(const struct rs_store *st, const char *name, const void *data,
                               size_t len, struct rs_buf *err);
/* `len` bytes as the file `name`, in place of whatever was there: written
 * beside it and renamed over it -- through protect's flags, where it set
 * them. */
bool rs_store_replace(const struct rs_store *st, const char *name, const void *data, size_t len,
                      struct rs_buf *err);
/* `from` renamed to `to`, replacing what is there: 0, or -1 with errno. With
 * `thawed`, through protect's flags, where it set them. */
int rs_store_rename(const struct rs_store *st, const char *from, const char *to, bool thawed);
/* `from` put in place as `to` unless something is there already, which is
 * kept: 1 if it was put there, 0 if something was there, -1 with errno if
 * neither. Until it is in place, `to` may be an empty file. */
int rs_store_place_new(const struct rs_store *st, const char *from, const char *to);
/* `name` removed: 0, or -1 with errno. With `thawed`, through protect's
 * flags, where it set them. */
int rs_store_remove(const struct rs_store *st, const char *name, bool thawed);
/* The empty directory `name` removed, as rs_store_remove. */
int rs_store_remove_dir(const struct rs_store *st, const char *name, bool thawed);
/* The directory `name` made, `mode`: 0, or -1 with errno -- or, with
 * `there_ok`, there already. Either way it is given the owner a file made
 * there would be. */
int rs_store_make_dir(const struct rs_store *st, const char *name, unsigned mode, bool there_ok);
/* A new directory whose name begins with `prefix`, beside it (prefix
 * "snapshots/.X." gives "snapshots/.X.AbC123"): its name, or NULL with
 * errno. */
char *rs_store_make_temp_dir(const struct rs_store *st, const char *prefix);
/* The directory `name`'s entries flushed, so a rename into it survives a
 * crash. */
void rs_store_sync_dir(const struct rs_store *st, const char *name);

/* The lock file `name`, taken shared or not, without waiting: a handle to
 * release with rs_store_unlock, or -1. Where something else holds it, *busy
 * is set, and nothing put in `err`; where an NFS server refused it with an
 * I/O error, as it says a program on the server holds it, *refused as well.
 * Anything else, `err` says. */
int rs_store_lock(const struct rs_store *st, const char *name, bool shared, bool *busy,
                  bool *refused, struct rs_buf *err);
void rs_store_unlock(const struct rs_store *st, int lock);

/* With `always`, what a local store makes is given the owner and group of
 * the directory it is made in as it is when run as root, for the unit tests'
 * benefit: they are not root. Nothing in restate itself calls it. */
void rs_store_set_adopting(bool always);
/* With `refuse`, each new file a local store makes is made and then its open
 * refused, as a Linux client older than 6.x refuses it in a sticky directory
 * on a share that maps root to another user -- for the unit tests' benefit,
 * which have no such share. Nothing in restate itself calls it. */
void rs_store_set_refusing_creates(bool refuse);
/* Replaces how a lock file is locked, how NFS is told, and the pause between
 * asking again where NFS says EIO, for the unit tests' benefit: they cannot
 * make a file server refuse. NULL and a negative pause restore the defaults.
 * Nothing in restate itself calls it. */
void rs_store_set_locking(int (*lock)(int fd, bool shared), bool (*nfs)(int fd), long nap_ms);

#endif /* RESTATE_STORE_H */
