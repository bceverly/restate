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
 *   counting  812345 paths  184 GiB to read  0:00:41
 *   walking [########............]  45%  83 GiB of 184 GiB  91 MiB/s  0:21:13 left
 *     .../src/main.c
 *   writing [##############......]  70%  129 GiB of 184 GiB  305 MiB/s  0:03:01 left
 *
 * A walk that will read files first counts them -- metadata only, no file
 * read -- so that the walk itself has a total, and a percentage and a time
 * left like the writing of the image does.
 *
 * On a terminal the bar and the path under it are redrawn in place a few
 * times a second, the bar as wide as the terminal allows. Progress is drawn
 * on the terminal even when standard error goes to a log, and each phase's
 * last line is written to standard error too, so the log has a record of it.
 * With no terminal at all (cron) a whole line goes to standard error every
 * ten seconds. Off, every call here does nothing.
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
/* Counts bytes found to read, while counting rather than reading. */
void rs_progress_found(uint64_t n);
/* Ends the phase with a last, final line. */
void rs_progress_done(void);
/* Takes the bar off the terminal, so a message can be printed where it was;
 * it is drawn again at the next update. */
void rs_progress_clear(void);

/* One progress line for `s` at time `now_ns`, at most `width` characters. */
void rs_progress_format(const struct rs_progress_state *s, uint64_t now_ns, size_t width,
                        char *out, size_t len);

/* For the tests: where the lines go, whether that is a terminal, and the
 * clock. NULL `now` restores the real clock. */
void rs_progress_set_output(FILE *fp, bool tty, uint64_t (*now)(void));

#endif /* RESTATE_PROGRESS_H */
