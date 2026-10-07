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

#include "index.h"
#include "tar.h"

#define RS_IMAGE_INDEX_NAME "restate/index.json"      /* before 1.1 */
#define RS_IMAGE_INDEX_PART "restate/index.json.gz"
#define RS_IMAGE_KIT_PART   "restate/kit.tar.gz"
#define RS_IMAGE_FILES_PART "restate/files.tar.gz"
#define RS_IMAGE_FILES_DIR  "restate/files"
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
 * The shell command that unpacks one part of `image` (RS_IMAGE_KIT_PART or
 * RS_IMAGE_FILES_PART) into `dest`, as it was: "tar -xOf IMAGE PART | tar
 * -xzpf - --numeric-owner -C DEST --strip-components=2", then `extra`, if any,
 * as further arguments to the second tar.
 */
void rs_image_part_command(struct rs_buf *out, const char *image, const char *part,
                           const char *dest, const char *extra);

/*
 * Reads an index from `path`: an image -- in parts, or from before 1.1 one
 * gzip'd stream -- or a bare index.json, and sets ix->in_parts for an image
 * in parts. "-" is standard input, which must be a bare index -- a stream
 * cannot be handed to gzip after its first bytes are read.
 */
bool rs_index_load(struct rs_index *ix, const char *path, struct rs_buf *err);

#endif /* RESTATE_IMAGE_H */
