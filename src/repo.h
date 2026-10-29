/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * A repository: captures kept together, each piece of content stored once.
 *
 * An image holds everything it keeps, so a nightly capture writes the whole
 * machine every night, and a week of them is seven copies of it. A
 * repository is a directory instead, made by `restate init`, which capture
 * -o adds a snapshot to:
 *
 *   restate-repository           "restate-repository 2", "id HEX" -- which
 *                                names this machine's cache of it -- and
 *                                "encrypted" for one that is
 *   chunk-key                    an encrypted repository's: the key its chunk
 *                                boundaries follow, encrypted to its keys
 *   chunk-key.TIME-N             the same key, sealed to newer keys by a capture
 *                                given them; a prune keeps only the newest copy
 *   lock                         held by a capture, or a prune, while it runs
 *   readers                      held shared by whatever reads a snapshot's
 *                                content, and by a prune alone
 *   packs/NAME.tar.gz            content: a gzip'd tar of chunks named 1, 2,
 *                                3, ... in the order they were written
 *   packs/NAME.idx               which of them is which: "restate-pack 2",
 *                                then "MEMBER SHA256 SIZE" per chunk, or
 *                                "MEMBER - SIZE" for one stored for nothing;
 *                                and "= SHA256 SIZE CHUNK CHUNK ..." for a
 *                                file of more than one chunk
 *   snapshots/NAME/index.json.gz the capture's index, exactly as an image's
 *   snapshots/NAME/index.sig     its signature, if it is signed
 *   snapshots/NAME/kit           the paths in the kit, one per line
 *   snapshots/NAME/info          a summary, for `restate snapshots`
 *
 * Chunks: a file is cut where its content says to -- a rolling hash over it,
 * FastCDC's, cut where the hash's top bits are zero, so chunks average a
 * mebibyte -- and each chunk is stored only if no pack has it already. A
 * file that changes a little, a disk image, then costs the chunks around
 * what changed, not the file again: an insertion moves only the cuts near
 * it. A file smaller than a chunk's minimum is a chunk itself, whose digest
 * is the file's, and a pack written by restate 1.3.0 -- whole files, a
 * chunk each, under "restate-pack 1" -- is read as one.
 *
 * Encrypted: `restate init --encrypt-to KEY` makes a repository whose packs,
 * their .idx files and each snapshot's files are encrypted to the OpenPGP
 * public keys given -- gpg after gzip, as an image's parts are -- so it can
 * sit on storage that is not trusted. The keys are never taken from the
 * repository, where whoever holds the storage could swap in their own: a
 * capture or prune into it is given them with --encrypt-to each time. A
 * capture needs no secret key: what it needs to know of what is already
 * there -- the .idx files, and the last snapshot's index -- it keeps in this
 * machine's cache of the repository (/var/cache/restate/repositories/ID),
 * as it writes them, and decrypts only what it does not have, if it can.
 * Restoring, and pruning what the cache does not cover, need the secret key.
 * Its chunks are cut where a key of its own says (chunk-key), not where
 * anyone could work out: the sizes of encrypted chunks then say nothing
 * about which known files it holds.
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
 * its files, its signature. The content comes as a tar stream like an
 * image's files part, made from the chunks: files in the order their first
 * chunk was written, from a few packs open at once, each read forward, so
 * a restore reads each pack about once.
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
#define RS_REPO_CHUNK_KEY "chunk-key"
/* A pack is closed once this much has been written into it, before gzip:
 * small enough that reading one for a single chunk is quick. */
#define RS_REPO_PACK_SIZE ((uint64_t)32 * 1024 * 1024)
/* gzip begins again at the first member after each this much, and the pack's
 * .seek says where in the file each such member starts: so a pack can be read
 * from near the member wanted, not only from its start. */
#define RS_REPO_SEGMENT_SIZE ((uint64_t)2 * 1024 * 1024)
/* Chunks: at least, about, and at most this many bytes. */
#define RS_REPO_CHUNK_MIN ((size_t)256 * 1024)
#define RS_REPO_CHUNK_AVG ((size_t)1024 * 1024)
#define RS_REPO_CHUNK_MAX ((size_t)4 * 1024 * 1024)
/* What separates a repository from a snapshot's name in a reference. */
#define RS_REPO_SEP      "::"

/* How a repository is opened: to read a snapshot's content, to add one, or
 * to prune -- which nothing else may be doing. */
enum rs_repo_lock {
    RS_REPO_LOOK = 0,   /* the index and the list of snapshots only */
    RS_REPO_READ,
    RS_REPO_WRITE,
    RS_REPO_PRUNE,
    /* As RS_REPO_WRITE, for capture --append-only: refused where adding a
     * snapshot would mean changing a file already there (making a version 1
     * repository version 2). A capture otherwise only ever adds files. */
    RS_REPO_APPEND
};

struct rs_repo;

/* Makes an empty repository at `dir`, which must not exist or be empty;
 * encrypted if `encrypted`. */
bool rs_repo_init(const char *dir, bool encrypted, struct rs_buf *err);

/* Whether `dir` is a repository, and whether it is an encrypted one. */
bool rs_repo_is(const char *dir);
bool rs_repo_dir_encrypted(const char *dir);

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
bool            rs_repo_encrypted(const struct rs_repo *r);
/* This machine's cache of an encrypted repository: its directory, NULL for a
 * repository that is not encrypted (or a user with nowhere to keep one), and
 * the bytes of the files in it, 0 while it has none. */
const char     *rs_repo_cache_path(const struct rs_repo *r);
uint64_t        rs_repo_cache_bytes(const struct rs_repo *r);
/* The public key files what is written is encrypted to, for an encrypted
 * repository: borrowed, and needed by a writer and by a prune's rewrites. */
void            rs_repo_set_recipients(struct rs_repo *r, const char *const *recips, size_t n);
/* What a prune asks, at each point it could stop and leave the repository
 * whole, whether to stop there: NULL, the default, for never. */
void            rs_repo_set_stop(struct rs_repo *r, bool (*stop)(void));

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
/* The same from this machine's cache, where it has it -- for a capture and a
 * prune, which trust it: the index it wrote, kept as it wrote it -- else as
 * rs_repo_load_index reads it. */
bool rs_repo_load_index_cached(struct rs_repo *r, const char *name, struct rs_index *ix,
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
    uint64_t             objects;   /* files with content that was new */
    uint64_t             bytes;     /* the new content's size, before gzip */
    struct rs_pgp_signer signer;    /* who signed it, if it was */
};

/* NULL, saying why, where the keys given (rs_repo_set_recipients) do not
 * suit the repository: none for an encrypted one, or some for one that is
 * not. */
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
 * symlinks and FIFOs, then the files in the order their content was
 * written, then the end of the archive. With `only` not NULL, just the
 * entries at or beneath those paths (as the kit is chosen). A file the packs
 * do not have all of is left out, for whoever reads the stream to find
 * missing; one whose pack cannot be read, found only on the way, is sent as
 * zeros after what could be read, with a warning, for restore to refuse.
 */
struct rs_repo_stream *rs_repo_stream_open(struct rs_repo *r, const struct rs_index *ix,
                                           const char *const *only, size_t nonly,
                                           struct rs_buf *err);
/* The same, with only the files `include`'s patterns cover (rs_glob_covers)
 * read from the packs, and none when `ninclude` is 0 means every file; every
 * directory, symlink and FIFO is in the stream whatever the patterns, so the
 * ones above a file are there to be put back with it. */
struct rs_repo_stream *rs_repo_stream_open_matching(struct rs_repo *r, const struct rs_index *ix,
                                                    const char *const *only, size_t nonly,
                                                    const char *const *include,
                                                    size_t ninclude, struct rs_buf *err);
/* Up to `n` bytes of the stream: how many, 0 at its end, -1 on an error. */
ssize_t rs_repo_stream_read(struct rs_repo_stream *s, void *buf, size_t n);
/* True if every pack read was read cleanly. */
bool    rs_repo_stream_close(struct rs_repo_stream *s, struct rs_buf *err);

/* ------------------------------------------------------------------------- */
/* Pruning                                                                   */
/* ------------------------------------------------------------------------- */

/* How many to keep, counting back from the newest: the newest `last`, and
 * the newest of each of the most recent `daily` days, `weekly` ISO weeks,
 * `monthly` months and `yearly` years that have one. */
struct rs_repo_keep {
    unsigned last;
    unsigned daily;
    unsigned weekly;
    unsigned monthly;
    unsigned yearly;
};

/* Which of the snapshots `names` (oldest first, as rs_repo_snapshots gives
 * them) to keep, into kept[i]. A name that is not a time is always kept. */
void rs_repo_choose(char *const *names, size_t n, const struct rs_repo_keep *keep, bool *kept);

struct rs_repo_pruned {
    char   **dropped;         /* the snapshots dropped, or that would be */
    size_t   ndropped;
    size_t   packs_removed;
    size_t   packs_rewritten;
    size_t   packs_left;      /* worth rewriting, but encrypted, and no keys given */
    uint64_t bytes_freed;     /* on disk */
    bool     stopped;         /* asked to stop (rs_repo_set_stop) before the end */
};

/* Drops the snapshots `keep` does not keep, then the content no remaining
 * one refers to; with `dry_run`, only says which. A pack whose .idx cannot
 * be read stops it removing any content. It writes each remaining snapshot's
 * pack list again, and a .sum for each pack that has none. Asked to stop, it
 * stops between one snapshot or pack and the next, with out->dropped saying
 * only what went; it still writes again the lists that a pack it rewrote
 * changed, and leaves the rest for the next prune. */
bool rs_repo_prune(struct rs_repo *r, const struct rs_repo_keep *keep, bool dry_run,
                   struct rs_repo_pruned *out, struct rs_buf *err);
/*
 * The same without reading any index -- so without the secret key of an
 * encrypted repository, or this machine's cache of it: the snapshots are
 * dropped, and then each pack that no snapshot left lists in its pack list,
 * whole. A pack only partly needed is kept as it is. Refused, with nothing
 * removed, if a snapshot that is kept has no pack list. It stops as
 * rs_repo_prune does, and removes no pack once a snapshot it drops is left.
 */
bool rs_repo_prune_whole(struct rs_repo *r, const struct rs_repo_keep *keep, bool dry_run,
                         struct rs_repo_pruned *out, struct rs_buf *err);
void rs_repo_pruned_free(struct rs_repo_pruned *p);

/*
 * Writes again each pack that has no .seek -- every pack restate wrote before
 * 2.0.0.8 -- so it can be read from the middle; what no snapshot needs is
 * dropped on the way, as rs_repo_prune drops it, and every snapshot is kept.
 * With `dry_run`, only counts them, into out->packs_rewritten. Refused for
 * an encrypted repository, whose packs gpg reads only from their start. It
 * stops as rs_repo_prune does; what it has written by then is kept, and the
 * next repack goes on from there.
 */
bool rs_repo_repack(struct rs_repo *r, bool dry_run, struct rs_repo_pruned *out,
                    struct rs_buf *err);

/* ------------------------------------------------------------------------- */
/* Protecting what is finished                                               */
/* ------------------------------------------------------------------------- */

struct rs_repo_protected {
    size_t files;        /* finished files made the owner's, 0440 */
    size_t snapshots;    /* snapshots with anything made so, each 0550 */
    size_t dirs;         /* the repository, packs and snapshots made shared */
    size_t unchanged;    /* files and directories that were so already */
    size_t waited_for;   /* files the file server had lent out, waited for */
    char **failed;       /* "PATH: why", for each that could not be made so */
    size_t nfailed;
};

/*
 * Makes what is finished in the repository at `dir` -- each pack whose .idx
 * is there, each snapshot under its own name, the chunk key -- `owner`'s and
 * `group`'s and read-only: files 0440, a snapshot's directory 0550, and on
 * Linux immutable. The repository, packs/ and snapshots/ become `owner`'s
 * and `group`'s, so that the group adds to them, and removes only what is
 * its own: what it has not finished. On Linux they are 0770, the repository
 * append-only; with NFSv4 ACLs, 0770 and an ACL; otherwise 1770, sticky. The
 * marker, the lock and readers, which a capture or a restore opens as its
 * own, are left as they are, and so is anything being written. Run as root
 * on the storage, with `owner` 0, it leaves the machines a share maps into
 * `group` able to add snapshots, and to read them, and unable to change or
 * remove any that are there.
 *
 * Only what is not so already is changed. Never through a symlink, and never
 * a file with a second name: what the machines could plant there, root
 * would otherwise give away. False, saying why, only if `dir` is not a
 * repository that can be opened, or on Linux cannot be made append-only (not
 * as root, or on a filesystem without the flag), with nothing changed; each
 * thing that could not be protected is in out->failed.
 */
bool rs_repo_protect(const char *dir, uid_t owner, gid_t group, struct rs_repo_protected *out,
                     struct rs_buf *err);
void rs_repo_protected_free(struct rs_repo_protected *p);

/* ------------------------------------------------------------------------- */
/* Usage, and copying                                                        */
/* ------------------------------------------------------------------------- */

struct rs_repo_snapshot_usage {
    char    *name;
    bool     listed;         /* it has a pack list; without one, nothing below is known */
    uint64_t bytes;          /* the packs it needs, on disk */
    uint64_t unique_bytes;   /* of those, the packs no other snapshot needs: what dropping it
                              * frees */
    uint64_t new_bytes;      /* of those, the packs no older snapshot needs: what it added */
};

struct rs_repo_usage {
    uint64_t                       bytes;        /* everything in the repository, on disk */
    uint64_t                       pack_bytes;   /* of that, the packs */
    size_t                         packs;
    struct rs_repo_snapshot_usage *snapshots;    /* oldest first */
    size_t                         nsnapshots;
};

/* What the repository holds, and what each snapshot needs of it, from the
 * sizes of its files and the snapshots' pack lists alone: no pack or index
 * is read, so no key is needed. */
void rs_repo_du(struct rs_repo *r, struct rs_repo_usage *out);
void rs_repo_usage_free(struct rs_repo_usage *u);

/* A key the repository's files are encrypted to, and which files. */
struct rs_repo_key_use {
    char     id[17];        /* its key id: 16 upper-case hex digits, all zeros for
                             * a recipient a file leaves anonymous */
    size_t   packs;         /* the packs with a file encrypted to it */
    uint64_t bytes;         /* those packs, on disk */
    char   **snapshots;     /* the snapshots with a file of their own encrypted to it */
    size_t   nsnapshots;
    bool     chunk_key;     /* the chunking key is encrypted to it */
};

struct rs_repo_keys {
    struct rs_repo_key_use *keys;     /* in the order they are first met */
    size_t                  nkeys;
    size_t                  files;    /* files encrypted to a key named here */
    size_t                  unreadable; /* encrypted files whose keys could not be read */
};

/* The keys the repository's packs, snapshots and chunking key are encrypted
 * to, read from the session keys at the head of each file, which say so in
 * the clear: no key is needed. A key no file is encrypted to any more is one
 * nothing in the repository needs to be read. */
void rs_repo_keys(struct rs_repo *r, struct rs_repo_keys *out);
void rs_repo_keys_free(struct rs_repo_keys *k);

struct rs_repo_copied {
    char    *name;            /* the snapshot */
    bool     already;         /* the destination had it, the same */
    bool     made;            /* the destination was made, as a repository like the source */
    size_t   packs_copied;
    size_t   packs_there;     /* the destination had them already */
    uint64_t bytes;           /* copied */
};

/*
 * Copies the snapshot `name` (NULL: the newest) of `r` into the repository
 * at `dest` -- made, encrypted or not as `r` is, if it is not there -- with
 * the packs it needs that `dest` has not got: every file as it is, so an
 * encrypted one stays encrypted and nothing is decrypted. `dest` is locked
 * as a capture locks it. The packs are those the snapshot's pack list
 * names, or, for a snapshot without one, those its index needs, which then
 * has to be readable here.
 */
bool rs_repo_copy(struct rs_repo *r, const char *name, const char *dest,
                  struct rs_repo_copied *out, bool *busy, struct rs_buf *err);
void rs_repo_copied_free(struct rs_repo_copied *c);

/* ------------------------------------------------------------------------- */
/* Checking                                                                  */
/* ------------------------------------------------------------------------- */

/* How to check. */
struct rs_repo_check_opts {
    bool        metadata_only;  /* no index read, no key needed: each pack against its .sum,
                                 * each snapshot's files and the packs its list names */
    const char *record;         /* a file of what was there at the last check, to report
                                 * what has been removed or changed since; then updated */
};

struct rs_repo_checked {
    size_t   packs;          /* read through */
    size_t   packs_bad;      /* not what their indexes say, or unreadable */
    uint64_t chunks;         /* checked against their digests */
    uint64_t bytes;          /* of content read */
    size_t   leftovers;      /* packs with no index: an interrupted capture's, which prune clears */
    size_t   snapshots;
    size_t   snapshots_bad;  /* an index or kit unreadable, or content not all there */
    uint64_t files;          /* the files with content the snapshots need */
    uint64_t missing;        /* of those, not whole in the repository */
    size_t   unsummed;       /* packs with no .sum: written before restate 2.0 */
    size_t   unlisted;       /* snapshots with no pack list: likewise */
    char   **changed;        /* with a record: "removed PATH" or "changed PATH" */
    size_t   nchanged;
};

void rs_repo_checked_free(struct rs_repo_checked *c);

/*
 * Reads every pack through and checks every chunk in it against the digest
 * its .idx gives -- the repository's own .idx, not this machine's copy --
 * then every snapshot's index and kit, and that the content of every file
 * each needs is whole among the chunks found good. What is wrong is warned
 * of as it is found, and counted in `out`. False, with `err` set, only if it
 * could not check at all: an encrypted repository it has no key for.
 */
bool rs_repo_check(struct rs_repo *r, const struct rs_repo_check_opts *opts,
                   struct rs_repo_checked *out, struct rs_buf *err);

/* With a record (rs_repo_check_opts), prune updates it too: what prune
 * removes is no longer expected, and what it writes is. */
bool rs_repo_record_update(struct rs_repo *r, const char *record, struct rs_buf *err);

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

/* One list in a pack's .idx: a file, and its chunks -- chunks[first] on. */
struct rs_repo_list {
    char     hash[RS_SHA256_HEX_SIZE];
    uint64_t size;
    size_t   first;
    size_t   n;
};

struct rs_repo_idx {
    struct rs_repo_member *members;
    size_t                 nmembers;
    struct rs_repo_list   *lists;
    size_t                 nlists;
    char                 (*chunks)[RS_SHA256_HEX_SIZE];
    size_t                 nchunks;
};

/* A pack's .sum: its content file's digest and size. */
bool rs_repo_parse_sum(const char *text, size_t len, char hex[RS_SHA256_HEX_SIZE], uint64_t *size);
/* A snapshot's pack list: the names, in order, each once. */
bool rs_repo_parse_pack_list(const char *text, size_t len, char ***names, size_t *n);
/* A check's record: "restate-record 1", then "PATH SHA256 SIZE" per file,
 * each path once and in order; freed with rs_repo_record_free. */
struct rs_repo_record_entry {
    char    *path;                       /* relative to the repository */
    char     hash[RS_SHA256_HEX_SIZE];
    uint64_t size;
};

struct rs_repo_record {
    struct rs_repo_record_entry *entries;   /* by path */
    size_t                       n;
};
bool rs_repo_parse_record(const char *text, size_t len, struct rs_repo_record *out);
void rs_repo_record_free(struct rs_repo_record *rec);

/* A pack's .seek: "restate-seek 1", then "MEMBER OFFSET" per segment -- the
 * first member in it, and where in the pack's file it begins. The first is
 * "1 0"; both go up from line to line. */
struct rs_repo_seek {
    uint64_t member;
    uint64_t offset;
};
bool rs_repo_parse_seek(const char *text, size_t len, struct rs_repo_seek **out, size_t *n);

/* Parses a pack's .idx, version 1 or 2; members must be numbered upward, and
 * a list has two chunks at least. */
bool rs_repo_parse_idx(const char *text, size_t len, struct rs_repo_idx *out);
void rs_repo_idx_free(struct rs_repo_idx *x);

/* Where a chunk that starts at `p`, with `n` bytes there, ends: n itself if
 * that is no more than RS_REPO_CHUNK_MIN, and never past RS_REPO_CHUNK_MAX. */
size_t rs_repo_chunk_cut(const unsigned char *p, size_t n);
/* The same with the boundaries an encrypted repository's key gives. */
size_t rs_repo_chunk_cut_keyed(const unsigned char key[32], const unsigned char *p, size_t n);

/* Parses a repository's marker: its format's version, and whether it is
 * encrypted; false, with *newer set if a later restate made it, when it is
 * not one this restate reads. */
bool rs_repo_parse_marker(const char *text, int *version, bool *encrypted, bool *newer);

/* Replaces where the caches of encrypted repositories go, for the unit
 * tests' benefit; NULL restores the default. Nothing in restate calls it. */
void rs_repo_set_cache_dir(const char *dir);

/* Replaces RS_REPO_PACK_SIZE, for the unit tests' benefit: they need packs
 * that fill up. 0 restores the default. Nothing in restate itself calls it. */
void rs_repo_set_pack_size(uint64_t bytes);
/* The same for RS_REPO_SEGMENT_SIZE. */
void rs_repo_set_segment_size(uint64_t bytes);
/* With `always`, what restate makes in a repository is given the owner and
 * group of the directory it is made in as it is when run as root, for the
 * unit tests' benefit: they are not root. Nothing in restate itself calls it. */
void rs_repo_set_adopting(bool always);
/* With `refuse`, each new file restate makes in a repository is made and then
 * its open refused, as a Linux client older than 6.x refuses it in a sticky
 * directory on a share that maps root to another user -- for the unit tests'
 * benefit, which have no such share. Nothing in restate itself calls it. */
void rs_repo_set_refusing_creates(bool refuse);
/* Replaces how long protect waits for files the file server has lent out
 * (180 seconds), and makes the next `lent` files' opens refused as lent, for
 * the unit tests' benefit: they have no NFS server. A negative wait restores
 * the default. Nothing in restate itself calls it. */
void rs_repo_set_protect_wait(long wait_ms, int lent);

/* Replaces how a lock file is locked, how NFS is told, and the pause between
 * asking again where NFS says EIO, for the unit tests' benefit: they cannot
 * make a file server refuse. NULL and a negative pause restore the defaults.
 * Nothing in restate itself calls it. */
void rs_repo_set_locking(int (*lock)(int fd, bool shared), bool (*nfs)(int fd), long nap_ms);

/* The name a snapshot taken at `created` (an index's "created") is given:
 * "20261011T030000Z". */
char *rs_repo_snapshot_name(const char *created);

#endif /* RESTATE_REPO_H */
