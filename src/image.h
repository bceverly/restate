/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * An image: a tar archive of three parts, each compressed on its own -- and,
 * with --encrypt-to, encrypted on its own, with ".gpg" after its name -- so
 * that each can be read without reading the others:
 *
 *   restate/index.json.gz     the index, first: what verify, diff, buildsheet
 *                             and autoinstall read, without touching the rest
 *   restate/kit.tar.gz        what a reinstall needs before anything else --
 *                             /etc/apt, and the packages no repository has --
 *                             small, so it is had in seconds
 *   restate/files.tar.gz      every kept file, directory, symlink and FIFO,
 *                             with its owner, mode and times, as
 *                             restate/files/etc/hosts, ... (the kit's
 *                             members are here too)
 *
 * The outer archive is not compressed, so tar finds a part by skipping past
 * the others' bytes rather than decompressing them:
 *
 *   tar -xOf IMAGE restate/files.tar.gz | tar -xzpf - --numeric-owner \
 *       -C / --strip-components=2
 *
 * An image written before 1.1 is one gzip'd tar with index.json first and
 * the files after it; it is still read.
 *
 * index.json has to come first and has to describe the content exactly, and
 * those pull in opposite directions: the digests are only known once every
 * file has been read. So the content is written during the walk to an
 * unlinked temporary file beside the destination -- each file read once, the
 * same bytes hashed and stored -- and the image is assembled afterwards: the
 * index, then that content copied in, through gzip, into a 0600 file that is
 * renamed over the destination only once it is complete.
 *
 * The temporary file costs disk space equal to the uncompressed content. For
 * the machine state restate keeps, that is small; it is the price of an index
 * that is both first and true.
 */
#ifndef RESTATE_IMAGE_H
#define RESTATE_IMAGE_H

#include <stdbool.h>
#include <sys/stat.h>

#include "gzip.h"
#include "index.h"
#include "pgp.h"
#include "tar.h"

#define RS_IMAGE_INDEX_NAME "restate/index.json"      /* before 1.1 */
#define RS_IMAGE_INDEX_PART "restate/index.json.gz"
#define RS_IMAGE_KIT_PART   "restate/kit.tar.gz"
#define RS_IMAGE_FILES_PART "restate/files.tar.gz"
#define RS_IMAGE_FILES_DIR  "restate/files"

/*
 * The kit carries the image's account files for restore to merge with the
 * system's (see accounts.h); unpacking the kit by hand must leave them out,
 * or it lays the old accounts over the new system's before its packages
 * are installed -- and dpkg stops at the first system group it cannot find.
 * These are tar's arguments for that.
 */
#define RS_IMAGE_KIT_KEEP_ACCOUNTS                                             \
    "--exclude=restate/files/etc/passwd --exclude=restate/files/etc/group "   \
    "--exclude=restate/files/etc/shadow --exclude=restate/files/etc/gshadow"
/* An index larger than this is not one restate wrote. */
#define RS_IMAGE_INDEX_MAX  ((size_t)2 * 1024 * 1024 * 1024 - 1)

struct rs_image_writer {
    int                  content_fd;   /* the unlinked temporary */
    struct rs_tar_writer tar;
    char                *dest;
    const char *const   *recipients;   /* public key files to encrypt to; see pgp.h */
    size_t               nrecipients;
    /* Paths that go into the kit as well as the files: each exactly, or, if
     * it ends in a slash, everything beneath it. */
    const char *const   *kit;
    size_t               nkit;
    struct {
        uint64_t offset;   /* in the content, where a kit member starts */
        uint64_t length;
    }                   *spans;
    size_t               nspans;
};

/* Creates the temporary content file beside `dest`. */
bool rs_image_begin(struct rs_image_writer *iw, const char *dest, struct rs_buf *err);

/* The rs_store_fn for rs_scan; `ctx` is the rs_image_writer. */
bool rs_image_store(void *ctx, struct rs_entry *e, int fd, const struct stat *st,
                    struct rs_buf *err);

/* Writes the image: the index, then the content. Discards everything on
 * failure, and in every case releases the writer. */
bool rs_image_finish(struct rs_image_writer *iw, const struct rs_index *ix,
                     struct rs_buf *err);
void rs_image_abort(struct rs_image_writer *iw);

/*
 * An image's files, as a tar stream to read member by member: from an image
 * in parts, the files part alone -- its bytes, and no more, written into
 * gzip (or gpg) as reading makes room for them, so neither ever reads past
 * it -- and from an image made before 1.1, the one stream, index.json first.
 * No process but gzip and gpg: the part is fed from the reading loop itself.
 */
struct rs_image_stream {
    int            fd;         /* gzip's output: the tar stream */
    int            image_fd;
    struct rs_gzip gz;
    struct rs_pgp  pg;
    bool           sealed;
    int            feed;       /* the pipe into gzip or gpg, or -1 */
    uint64_t       feed_at;    /* where the part's next bytes are in the image */
    uint64_t       feed_left;
    bool           feed_failed;
    unsigned char  chunk[65536];
    size_t         chunk_len;
    size_t         chunk_pos;
};

bool rs_image_open_files(const char *path, struct rs_image_stream *s, struct rs_buf *err);
/* The kit, the same way; an image from before 1.1 has none. */
bool rs_image_open_kit(const char *path, struct rs_image_stream *s, struct rs_buf *err);
/* Up to `n` bytes of the tar stream: how many, 0 at its end, -1 on error. */
ssize_t rs_image_read_files(struct rs_image_stream *s, void *buf, size_t n);
/* Stops everything, and with `abandon` does not mind how: true if gzip and
 * gpg finished cleanly and the whole part was fed to them. */
bool rs_image_close_files(struct rs_image_stream *s, bool abandon, struct rs_buf *err);

/*
 * The shell command that unpacks one part of `image` (RS_IMAGE_KIT_PART or
 * RS_IMAGE_FILES_PART) into `dest`, as it was: "tar -xOf IMAGE PART | tar
 * -xzpf - --numeric-owner -C DEST --strip-components=2", then `extra`, if any,
 * as further arguments to the second tar.
 */
void rs_image_part_command(struct rs_buf *out, const char *image, const char *part,
                           const char *dest, const char *extra);

/*
 * The shell command that puts `image`'s files back under `dest` ("/" on the
 * system itself, "/target" from an installer): `restate restore`, as the
 * image's kit put it back under `dest` -- in /usr/local/sbin, /usr/local/bin,
 * /usr/sbin or /usr/bin -- or, if none is there, the files part unpacked with
 * tar, as rs_image_part_command does it, without restore's checks or its
 * merging of the accounts, and saying so. `fstab` leaves
 * /etc/fstab and /etc/crypttab out, for an installer that formatted the
 * volumes itself. An incomplete restore (some files refused, exit 3) is
 * said, not taken as failure; anything worse fails the command.
 */
void rs_image_restore_command(struct rs_buf *out, const char *image, const char *dest,
                              bool fstab);

/*
 * Reads an index from `path`: an image -- in parts, or from before 1.1 one
 * gzip'd stream -- or a bare index.json, and sets ix->in_parts for an image
 * in parts. "-" is standard input, which must be a bare index -- a stream
 * cannot be handed to gzip after its first bytes are read.
 */
bool rs_index_load(struct rs_index *ix, const char *path, struct rs_buf *err);

#endif /* RESTATE_IMAGE_H */
