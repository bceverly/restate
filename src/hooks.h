/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Hooks: the scripts capture --quiesce runs to pause what is live (live.h)
 * while its files are copied, and to resume it after. restate runs no
 * administration tool itself -- no systemctl, no virsh -- so pausing anything
 * is a hook's job, and a site decides what its hooks do.
 *
 * A hook is named for the kind of thing it pauses ("postgresql", "libvirt",
 * "lxd" -- the list is in live.h) and looked for first in
 * /etc/restate/hooks.d, the site's own, and then among those restate ships, in
 * libexec/restate/hooks beside the sbin it is installed in. Either is used
 * only if it and its directory are root's and writable by no one else.
 *
 * It is run as
 *
 *   HOOK pause NAME        before the thing's files are copied
 *   HOOK resume NAME       after, always -- even if pausing failed
 *
 * with, in its environment:
 *
 *   RESTATE_ACTION     pause or resume
 *   RESTATE_KIND       postgresql, libvirt, ...
 *   RESTATE_NAME       the cluster's, VM's or container's name
 *   RESTATE_PID        the process found running
 *   RESTATE_UID        whose it is, and RESTATE_USER that user's name
 *   RESTATE_PATHS      the paths about to be copied, one to a line
 *   RESTATE_DUMP_DIR   a directory, root's and 0700, for a dump to go into
 *                      the image beside the files (pg_dumpall's, say): it is
 *                      copied along with them, after "pause" returns
 *
 * Exiting 0 means done. A pause that fails is warned about and the files are
 * copied as they are; resume is run anyway. Pausing may take up to 30
 * minutes (a large dump) and resuming 10, after which the hook is stopped.
 */
#ifndef RESTATE_HOOKS_H
#define RESTATE_HOOKS_H

#include <stdbool.h>
#include <stddef.h>

#include "live.h"
#include "util.h"

#define RS_HOOKS_SITE_DIR "/etc/restate/hooks.d"
/* Where the dumps go, a directory per thing paused, beneath the root. */
#define RS_HOOKS_DUMPS    "/var/lib/restate/dumps"

/*
 * Replaces the directories hooks are looked for in, for the tests' benefit.
 * NULL restores the default. No option or variable reaches it.
 */
void rs_hooks_set_dirs(const char *const *dirs, size_t n);

/* The hook for `kind`, or NULL if there is none restate would run. */
char *rs_hook_find(const char *kind);

/*
 * The dump directory for `l` beneath `root`, made if it is not there, as a
 * directory root's alone; NULL, with the reason in `err`, if it cannot be.
 * Its path as the walk sees it ("/var/lib/restate/dumps/postgresql-18-main")
 * goes into *tree_path.
 */
bool rs_hook_dump_dir(const char *root, const struct rs_live *l, char **tree_path,
                      struct rs_buf *err);

/* Runs `hook` for `action` ("pause", "resume") on `l`. True if it exited 0. */
bool rs_hook_run(const char *hook, const char *action, const struct rs_live *l,
                 const char *dump_dir, struct rs_buf *err);

#endif /* RESTATE_HOOKS_H */
