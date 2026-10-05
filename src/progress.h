/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Progress for the long operations, when it is asked for (--progress).
 *
 * A capture of a whole machine reads hundreds of gigabytes and can take an
 * hour, and without this it says nothing until the end. With it, a line on
 * standard error says what it is doing -- like `dd status=progress`:
 *
 *   walking  812345 paths  143 GiB  209 MiB/s  0:11:40  .../src/main.c
 *   writing   62%  89 GiB of 143 GiB  305 MiB/s  0:03:01 left
 *
 * Walking has no total to measure against -- nothing says how much of the
 * tree is left until it has been walked -- so it shows how much so far and
 * how fast. Writing the image does know its total, so it shows a percentage
 * and the time left at the current rate.
 *
 * On a terminal the line is rewritten in place a few times a second; anywhere
 * else (a log file, a pipe) a whole line is written every ten seconds, so the
 * log stays readable. Off, every call here does nothing.
 */
#ifndef RESTATE_PROGRESS_H
#define RESTATE_PROGRESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* What one progress line is made from. */
struct rs_progress_state {
    const char *phase;     /* "walking", "writing" */
    uint64_t    total;     /* bytes, or 0 if not known */
    uint64_t    bytes;
    uint64_t    paths;
    uint64_t    start_ns;
    const char *current;   /* the path being read, or NULL */
};

/* Turns progress on or off; off by default. */
void rs_progress_enable(bool on);
bool rs_progress_enabled(void);

/* Starts a phase with `total` bytes to go, or 0 if that is not known. */
void rs_progress_phase(const char *phase, uint64_t total);
/* Counts bytes read or written. */
void rs_progress_bytes(uint64_t n);
/* Counts a path, and names it as the one being read. */
void rs_progress_path(const char *path);
/* Ends the phase with a last, final line. */
void rs_progress_done(void);

/* One progress line for `s` at time `now_ns`, at most `width` characters. */
void rs_progress_format(const struct rs_progress_state *s, uint64_t now_ns, size_t width,
                        char *out, size_t len);

/* For the tests: where the lines go, whether that is a terminal, and the
 * clock. NULL `now` restores the real clock. */
void rs_progress_set_output(FILE *fp, bool tty, uint64_t (*now)(void));

#endif /* RESTATE_PROGRESS_H */
