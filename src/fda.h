/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * macOS's Full Disk Access. macOS keeps what it counts as private -- Mail,
 * Messages, Safari, Time Machine's settings, other apps' containers, the
 * privacy database itself -- from every program it has not been told to
 * trust, root's included: open(2) says EPERM, "Operation not permitted",
 * whatever the file's mode. A capture of a Mac by a program without it is
 * missing all of that, and a restore from it puts none of it back.
 *
 * It is granted in System Settings, Privacy & Security, Full Disk Access, to
 * the program macOS holds responsible for restate: the terminal it is run
 * from (Terminal, iTerm), or restate itself where launchd runs it. Nothing
 * restate can do grants it, so all it does is tell: before a capture of
 * this machine, if it has not been granted, and after it, how many of the
 * paths it could not read macOS refused.
 *
 * Whether it has been is found by opening the privacy database, which is
 * there on every macOS since 10.14 and is the first file it keeps from a
 * program without it.
 */
#ifndef RESTATE_FDA_H
#define RESTATE_FDA_H

#include <stdbool.h>
#include <stdint.h>

enum rs_fda {
    RS_FDA_NONE = 0,   /* not macOS, or not this machine's own root */
    RS_FDA_GRANTED,
    RS_FDA_DENIED,
    RS_FDA_UNKNOWN     /* macOS, but the database could not tell */
};

/* Whether a walk of `root` is kept from what macOS protects. */
enum rs_fda rs_fda_state(const char *root);

/* Warns, once a capture of `root` is about to begin, that it will be missing
 * what macOS protects and how to grant Full Disk Access. */
void rs_fda_warn(void);

/* Says, after the walk, how many paths macOS refused it for want of Full
 * Disk Access; nothing for none. */
void rs_fda_summary(uint64_t refused);

/* For the tests: the database's path in place of macOS's, and any system
 * taken for macOS while one is given. NULL for the system's own again. */
void rs_fda_pretend(const char *database);

#endif /* RESTATE_FDA_H */
