/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * A repository: captures kept together, each file's content stored once.
 *
 * An image holds everything it keeps, so a nightly capture writes the whole
 * machine every night, and a week of them is seven copies of it. A
 * repository is a directory instead, made by `restate init`, which capture
 * -o adds a snapshot to:
 *
 *   restate-repository           "restate-repository 1": what this is
 *   lock                         held by a capture, or a prune, while it runs
 *   readers                      held shared by whatever reads a snapshot's
 *                                content, and by a prune alone
 *   packs/NAME.tar.gz            content: a gzip'd tar of files named 1, 2,
 *                                3, ... in the order they were written
 *   packs/NAME.idx               which of them is which: "restate-pack 1",
 *                                then "MEMBER SHA256 SIZE" per file, or
 *                                "MEMBER - SIZE" for one stored for nothing
 *   snapshots/NAME/index.json.gz the capture's index, exactly as an image's
 *   snapshots/NAME/index.sig     its signature, if it is signed
 *   snapshots/NAME/kit           the paths in the kit, one per line
 *   snapshots/NAME/info          a summary, for `restate snapshots`
 *
 * A file's content goes into a pack only if no pack has its digest already.
 * Members are numbered rather than named by digest because a file is written
 * into the pack as it is read -- once, as an image does it -- and its digest
 * is only known at the end; a file whose content turns out to be there
 * already is left in the pack as dead weight, marked so in the .idx, for
 * prune to reclaim.
 *
 * Incremental runs: a file whose size, mtime, ctime and inode are what the
 * last snapshot recorded is not read at all (scan.h), as `git status` and
 * rsync trust the same things, so a capture after the first takes as long as
 * what changed.
 *
 * Every step is written beside its final name and renamed into place: a pack
 * is not counted until its .idx is there, and a snapshot is not there until
 * its directory is renamed into place, last, once its content is all on
 * disk. A capture that is interrupted leaves temporary files, which prune
 * clears, and nothing that looks finished.
 *
 * A snapshot is named "REPO::NAME" -- or "REPO" alone for the newest -- and
 * everything that reads an image reads one (image.c): its index, its kit,
 * its files, its signature. The content comes from the packs pack by pack,
 * as a tar stream like an image's files part, so a restore reads each pack
 * once.
 */
#ifndef RESTATE_REPO_H
#define RESTATE_REPO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "index.h"
#include "json.h"
#include "pgp.h"
#include "util.h"

#define RS_REPO_MARKER   "restate-repository"
/* A pack is closed once this much has been written into it, before gzip. */
#define RS_REPO_PACK_SIZE ((uint64_t)256 * 1024 * 1024)
/* What separates a repository from a snapshot's name in a reference. */
#define RS_REPO_SEP      "::"

/* How a repository is opened: to read a snapshot's content, to add one, or
 * to prune -- which nothing else may be doing. */
enum rs_repo_lock {
    RS_REPO_LOOK = 0,   /* the index and the list of snapshots only */
    RS_REPO_READ,
    RS_REPO_WRITE,
    RS_REPO_PRUNE
};

struct rs_repo;

/* Makes an empty repository at `dir`, which must not exist or be empty. */
bool rs_repo_init(const char *dir, struct rs_buf *err);

/* Whether `dir` is a repository. */
bool rs_repo_is(const char *dir);

/*
 * Whether `ref` names a snapshot: "REPO::NAME", or a repository alone for its
 * newest. The repository's directory into *dir and the name into *name --
 * NULL for the newest -- both the caller's to free.
 */
bool rs_repo_ref(const char *ref, char **dir, char **name);

/* Whether `name` is one a snapshot could have: letters, digits, '.', '-' and
 * '_', not starting with '.', at most 64 of them. */
bool rs_repo_name_valid(const char *name);

/* Opens the repository at `dir`, locked as `lock` says. NULL on failure, with
 * *busy set if something else holds the lock. */
struct rs_repo *rs_repo_open(const char *dir, enum rs_repo_lock lock, bool *busy,
                             struct rs_buf *err);
void            rs_repo_close(struct rs_repo *r);
const char     *rs_repo_dir(const struct rs_repo *r);

/* The snapshots, oldest first; the caller frees them with rs_repo_free_names. */
char **rs_repo_snapshots(struct rs_repo *r, size_t *n);
void   rs_repo_free_names(char **names, size_t n);

/* `name`, or the newest snapshot if it is NULL, as a snapshot that exists;
 * NULL, saying why, if there is none. */
char *rs_repo_resolve(struct rs_repo *r, const char *name, struct rs_buf *err);

/* A snapshot's index as stored -- what its signature covers -- and its
 * signature, left empty if it has none. */
bool rs_repo_index_bytes(const struct rs_repo *r, const char *name, struct rs_buf *gz,
                         struct rs_buf *sig, struct rs_buf *err);
/* A snapshot's index, read; ix->part_sha256 is the digest of its bytes. */
bool rs_repo_load_index(struct rs_repo *r, const char *name, struct rs_index *ix,
                        struct rs_buf *err);
/* Signs a snapshot that is not signed yet. */
bool rs_repo_add_signature(struct rs_repo *r, const char *name, const void *sig, size_t len,
                           struct rs_buf *err);
/* The paths in a snapshot's kit. */
bool rs_repo_kit(const struct rs_repo *r, const char *name, char ***paths, size_t *n,
                 struct rs_buf *err);
/* A snapshot's summary: what capture wrote in its info file. */
bool rs_repo_info(const struct rs_repo *r, const char *name, struct rs_jval *info,
                  struct rs_buf *err);

/* ------------------------------------------------------------------------- */
/* Adding a snapshot                                                         */
/* ------------------------------------------------------------------------- */

struct rs_repo_writer;

/* What a snapshot added. */
struct rs_repo_written {
    char                *name;
    uint64_t             objects;   /* new content, stored */
    uint64_t             bytes;     /* and its size, before gzip */
    struct rs_pgp_signer signer;    /* who signed it, if it was */
};

struct rs_repo_writer *rs_repo_writer_begin(struct rs_repo *r, struct rs_buf *err);
/* The paths that are the snapshot's kit, as for an image (image.h). */
void rs_repo_writer_kit(struct rs_repo_writer *w, const char *const *kit, size_t n);
/* The rs_store_fn for rs_scan; `ctx` is the writer. A regular file with `fd`
 * -1 is one whose content the repository has already (rs_repo_have). */
bool rs_repo_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                   struct rs_buf *err);
/* Whether the repository holds content with the digest `hash`. */
bool rs_repo_have(const void *ctx, const char hash[RS_SHA256_HEX_SIZE]);
/* Writes the snapshot, signed with the secret key in `sign_with` if it is
 * not NULL, and releases the writer whatever happens. */
bool rs_repo_writer_finish(struct rs_repo_writer *w, const struct rs_index *ix,
                           const char *sign_with, struct rs_repo_written *out,
                           struct rs_buf *err);
/* Discards everything written, and releases the writer. */
void rs_repo_writer_abort(struct rs_repo_writer *w);

/* ------------------------------------------------------------------------- */
/* Reading a snapshot's content                                              */
/* ------------------------------------------------------------------------- */

struct rs_repo_stream;

/*
 * The content of the snapshot whose index is `ix`, as a tar stream of
 * members named as an image's files part names them: the directories,
 * symlinks and FIFOs, then the files pack by pack, then the end of the
 * archive. With `only` not NULL, just the entries at or beneath those paths
 * (as the kit is chosen). A file the packs do not have is left out, for
 * whoever reads the stream to find missing.
 */
struct rs_repo_stream *rs_repo_stream_open(struct rs_repo *r, const struct rs_index *ix,
                                           const char *const *only, size_t nonly,
                                           struct rs_buf *err);
/* Up to `n` bytes of the stream: how many, 0 at its end, -1 on an error. */
ssize_t rs_repo_stream_read(struct rs_repo_stream *s, void *buf, size_t n);
/* True if every pack read was read cleanly. */
bool    rs_repo_stream_close(struct rs_repo_stream *s, struct rs_buf *err);

/* ------------------------------------------------------------------------- */
/* Pruning                                                                   */
/* ------------------------------------------------------------------------- */

/* How many to keep, counting back from the newest: the newest `last`, and
 * the newest of each of the most recent `daily` days, `weekly` ISO weeks and
 * `monthly` months that have one. */
struct rs_repo_keep {
    unsigned last;
    unsigned daily;
    unsigned weekly;
    unsigned monthly;
};

/* Which of the snapshots `names` (oldest first, as rs_repo_snapshots gives
 * them) to keep, into kept[i]. A name that is not a time is always kept. */
void rs_repo_choose(char *const *names, size_t n, const struct rs_repo_keep *keep, bool *kept);

struct rs_repo_pruned {
    char   **dropped;         /* the snapshots dropped, or that would be */
    size_t   ndropped;
    size_t   packs_removed;
    size_t   packs_rewritten;
    uint64_t bytes_freed;     /* on disk */
};

/* Drops the snapshots `keep` does not keep, then the content no remaining
 * one refers to; with `dry_run`, only says which. */
bool rs_repo_prune(struct rs_repo *r, const struct rs_repo_keep *keep, bool dry_run,
                   struct rs_repo_pruned *out, struct rs_buf *err);
void rs_repo_pruned_free(struct rs_repo_pruned *p);

/* ------------------------------------------------------------------------- */
/* Exposed for the tests and the fuzzer                                      */
/* ------------------------------------------------------------------------- */

/* One line of a pack's .idx. */
struct rs_repo_member {
    uint64_t member;
    uint64_t size;
    bool     live;
    char     hash[RS_SHA256_HEX_SIZE];
};

/* Parses a pack's .idx; members must be numbered upward. */
bool rs_repo_parse_idx(const char *text, size_t len, struct rs_repo_member **out, size_t *n);

/* Replaces RS_REPO_PACK_SIZE, for the unit tests' benefit: they need packs
 * that fill up. 0 restores the default. Nothing in restate itself calls it. */
void rs_repo_set_pack_size(uint64_t bytes);

/* The name a snapshot taken at `created` (an index's "created") is given:
 * "20261011T030000Z". */
char *rs_repo_snapshot_name(const char *created);

#endif /* RESTATE_REPO_H */
