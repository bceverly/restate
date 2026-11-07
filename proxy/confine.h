/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * What a connection's processes may reach, once its token is checked: that
 * client's repository and its staging, and nothing of any other client's --
 * so that a fault in the parser, or in what reads an upload, still cannot
 * reach another client's.
 *
 * Two processes serve a connection from then on (server.c), each confined
 * as tightly as what it does allows:
 *
 *   the connection   TLS, the requests, the reading, the uploads: reads the
 *                    repository, writes the client's staging; runs nothing,
 *                    makes no socket
 *   the committer    the commits, by restate's own ingest: reads the
 *                    staging, writes the repository, and runs gzip, which
 *                    reads what a pack holds; makes no socket
 *
 * How, by system:
 *
 *   OpenBSD    unveil(2) the repository and the staging (and gzip, for the
 *              committer), and pledge(2) no more than those calls need
 *   Linux      Landlock (5.13 and later), the same paths and, for the
 *              committer, the system's programs and libraries, read and run
 *              only; no TCP bind or connect, and, from Landlock's 6th ABI,
 *              no signal or abstract socket outside; and a seccomp filter
 *              that refuses making sockets, ptrace, mounts, modules, BPF,
 *              namespaces and the rest a server has no use for (and running
 *              a program, for the connection)
 *   FreeBSD    Capsicum: the connection enters capability mode, with the
 *              repository and the staging reached through descriptors only
 *              (rs_store_confine). The committer cannot -- a program is
 *              never run in capability mode -- and is left as it is
 *
 * Where the system has none of it (an older Linux kernel, macOS, NetBSD),
 * nothing is confined, and rs_confine_how says so, for the proxy's log as it
 * starts.
 */
#ifndef RESTATE_CONFINE_H
#define RESTATE_CONFINE_H

#include <stdbool.h>

#include "util.h"

enum rs_confine_role {
    RS_CONFINE_CONNECTION,
    RS_CONFINE_COMMITTER
};

/* How this system confines, for the log: "pledge, unveil", "landlock (ABI
 * 6), seccomp", "capsicum", or "none". */
const char *rs_confine_how(void);

/*
 * This process confined as `role` says, to the repository at `repository`
 * and the staging at `staging` (NULL for none), directories that are there.
 * True -- also where the system has nothing to confine with -- or false,
 * saying why, where it has and it failed: the caller then serves nothing
 * more.
 */
bool rs_confine(enum rs_confine_role role, const char *repository, const char *staging,
                struct rs_buf *why);

#endif /* RESTATE_CONFINE_H */
