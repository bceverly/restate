/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Writing a POSIX pax tar stream, and reading the first member back out.
 *
 * Every member gets a pax extended header ('x') carrying its full path, its
 * owner by number and by name, its size and its access and modification times
 * to the nanosecond -- the ustar header alone cannot hold a path over 100
 * bytes, a file over 8 GiB, a uid over 2097151 or a fraction of a second. GNU
 * tar, bsdtar and every libarchive reader understand pax, so an image is also
 * ordinary tar that `tar` can unpack by hand.
 *
 * The reader exists to pull index.json out of the front of an image without
 * reading the rest. Its input is a file somebody hands restate, so it checks
 * every header checksum, bounds every size before allocating, and is fuzzed.
 */
#ifndef RESTATE_TAR_H
#define RESTATE_TAR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "meta.h"
#include "util.h"

#define RS_TAR_BLOCK 512

/* A destination: write all of `n` bytes or fail with errno set. */
typedef bool (*rs_tar_write_fn)(void *ctx, const void *data, size_t n);
/* A source: read up to `n` bytes; 0 at the end, -1 with errno on error. */
typedef ssize_t (*rs_tar_read_fn)(void *ctx, void *data, size_t n);

struct rs_tar_member {
    const char    *name;       /* member path, relative, no leading '/' */
    char           typeflag;   /* '0' file, '5' directory, '2' symlink, '6' FIFO */
    uint32_t       mode;
    uint64_t       uid;
    uint64_t       gid;
    const char    *uname;      /* NULL if none */
    const char    *gname;
    uint64_t       size;       /* bytes of data that follow ('0' only) */
    struct rs_time mtime;
    struct rs_time atime;
    const char    *linkname;   /* a symlink's target */
};

struct rs_tar_writer {
    rs_tar_write_fn write;
    void           *ctx;
    uint64_t        offset;    /* bytes written so far */
};

void rs_tar_writer_init(struct rs_tar_writer *w, rs_tar_write_fn fn, void *ctx);
/* The pax header and the ustar header for `m`; the data is the caller's. */
bool rs_tar_header(struct rs_tar_writer *w, const struct rs_tar_member *m);
bool rs_tar_data(struct rs_tar_writer *w, const void *data, size_t n);
/* Pads the data just written out to the next 512-byte boundary. */
bool rs_tar_pad(struct rs_tar_writer *w);
/* The two zero blocks that end an archive. */
bool rs_tar_finish(struct rs_tar_writer *w);

/* Builds one pax record, "LEN key=value\n", where LEN counts itself. */
void rs_tar_pax_record(struct rs_buf *out, const char *key, const char *value, size_t vlen);

/*
 * Reads the first real member of a tar stream: its name (from a pax header
 * if there is one) and its content, which must be at most `max` bytes. Only
 * what precedes and makes up that member is read.
 */
bool rs_tar_read_first(rs_tar_read_fn fn, void *ctx, size_t max,
                       struct rs_buf *name, struct rs_buf *content, struct rs_buf *err);

#endif /* RESTATE_TAR_H */
