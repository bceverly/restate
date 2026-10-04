/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * An image: a gzip'd tar of the index and the content worth keeping.
 *
 *   restate/index.json            first, so it can be read without the rest
 *   restate/files/etc/hosts       every kept file, directory, symlink and FIFO,
 *   restate/files/etc/ssh/...     with its owner, mode and times
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

#define RS_IMAGE_INDEX_NAME "restate/index.json"
#define RS_IMAGE_FILES_DIR  "restate/files"
/* An index larger than this is not one restate wrote. */
#define RS_IMAGE_INDEX_MAX  ((size_t)2 * 1024 * 1024 * 1024 - 1)

struct rs_image_writer {
    int                  content_fd;   /* the unlinked temporary */
    struct rs_tar_writer tar;
    char                *dest;
    const char *const   *recipients;   /* public key files to encrypt to; see pgp.h */
    size_t               nrecipients;
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
 * Reads an index from `path`: an image (gzip'd, recognized by its first two
 * bytes) or a bare index.json. "-" is standard input, which must be a bare
 * index -- a stream cannot be handed to gzip after its first bytes are read.
 */
bool rs_index_load(struct rs_index *ix, const char *path, struct rs_buf *err);

#endif /* RESTATE_IMAGE_H */
