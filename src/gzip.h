/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * gzip, as a separate process, the way tar(1) does it.
 *
 * Linking zlib would make restate depend on a library, and writing a deflate
 * compressor here would be a few hundred lines of exactly the kind of code
 * that should not be written twice. gzip is in the base system of every
 * platform restate runs on, and running it as its own process keeps its code
 * out of this address space.
 *
 * It is found at a fixed absolute path -- /usr/bin/gzip, then /bin/gzip --
 * and never through $PATH: restate runs as root, and a PATH that reaches a
 * user-writable directory would hand that user root. It is run with
 * posix_spawn(3), no shell, and an environment of PATH and LC_ALL only.
 */
#ifndef RESTATE_GZIP_H
#define RESTATE_GZIP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "util.h"

struct rs_gzip {
    pid_t pid;
    int   fd;      /* write uncompressed data here, or read it from here */
};

/* The gzip this system has, or NULL. */
const char *rs_gzip_path(void);

/*
 * Replaces the fixed list of paths tried -- for gzip and pigz both -- for the
 * unit tests' benefit: they need a gzip that is missing and one that fails.
 * NULL restores the default.
 * Nothing in restate itself calls it, and no option or variable reaches it.
 */
void rs_gzip_set_paths(const char *const *list, size_t n);

/*
 * Starts compressing to `out_fd`: with pigz where it is installed -- the same
 * gzip format, on every core, several times faster on a large image -- and
 * with `gzip -c -n` where it is not.
 */
bool rs_gzip_compress(int out_fd, struct rs_gzip *gz, struct rs_buf *err);
/* Whether compressing will use pigz. */
bool rs_gzip_parallel(void);
/* Starts `gzip -d -c` reading compressed input from `in_fd`. */
bool rs_gzip_decompress(int in_fd, struct rs_gzip *gz, struct rs_buf *err);

/*
 * Closes our end and waits for gzip. Returns true if it exited 0. With
 * `abandon`, it is a reader we stopped reading from early: it is told to stop
 * and how it ends does not matter.
 */
bool rs_gzip_finish(struct rs_gzip *gz, bool abandon, struct rs_buf *err);

#endif /* RESTATE_GZIP_H */
