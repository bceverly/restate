/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Running another program: the one place restate does.
 *
 * restate runs four programs, each for something it should not do itself:
 * gzip (compression), curl (HTTPS), gpgv (OpenPGP signature checks) and gpg
 * (encrypting and decrypting images). Writing a compressor, a TLS stack or an OpenPGP implementation
 * here would be hundreds of lines of exactly the code that should not be
 * written twice; linking a library for them would end "links nothing but
 * libc". As separate processes their code stays out of this address space.
 *
 * Each is found at a fixed absolute path -- never through $PATH, because
 * restate runs as root and a PATH reaching a user-writable directory would
 * hand that user root -- and used only if it and its directory belong to root
 * and are writable by nobody else. It is started with posix_spawn: no shell,
 * nothing run in the child before the exec, and an environment of PATH and
 * LC_ALL plus what that one program needs: the proxy variables for curl, and
 * for gpg the home, terminal and display it finds a key and asks for its
 * passphrase with.
 */
#ifndef RESTATE_RUN_H
#define RESTATE_RUN_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "util.h"

enum rs_program {
    RS_PROG_GZIP = 0,
    RS_PROG_CURL,
    RS_PROG_GPGV,
    RS_PROG_GPG,
    RS_PROG_COUNT
};

/* "gzip", "curl", "gpgv", "gpg". */
const char *rs_program_name(enum rs_program p);

/* The first of the program's fixed paths that is an executable file, or
 * NULL: for messages, and for deciding whether a feature is available. */
const char *rs_program_path(enum rs_program p);

/*
 * Replaces a program's fixed paths, for the unit tests' benefit -- they need a
 * program that is missing and one that fails. NULL restores the default.
 * Nothing in restate itself calls it, and no option or variable reaches it.
 */
void rs_program_set_paths(enum rs_program p, const char *const *list, size_t n);

/*
 * Starts the program with `in_fd`, `out_fd` and `err_fd` as its standard
 * input, output and error; -1 leaves that one as restate's own. A path that is
 * not an executable file is skipped before it is tried, because not every
 * posix_spawn can say an exec failed: OpenBSD's, and glibc's under valgrind,
 * report success and leave the child to exit 127 -- which rs_wait reports.
 */
bool rs_spawn(enum rs_program p, char *const argv[], int in_fd, int out_fd, int err_fd,
              pid_t *pid, struct rs_buf *err);

/* Waits for `pid`. *code is its exit status, or 128 + the signal that
 * killed it. */
bool rs_wait(pid_t pid, int *code, struct rs_buf *err);

/*
 * Runs the program to completion. Its standard output and error are captured
 * into `out` and `errtext` when those are not NULL, and left as restate's own
 * when they are. *code as rs_wait's.
 */
bool rs_run(enum rs_program p, char *const argv[], struct rs_buf *out, struct rs_buf *errtext,
            int *code, struct rs_buf *err);

#endif /* RESTATE_RUN_H */
