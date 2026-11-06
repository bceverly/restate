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
 * only if it and its directory are root's and writable by no one else. A
 * program no kind covers is paused by a hook of its own name, in
 * /etc/restate/hooks.d alone (rs_hook_for_program).
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
 *   RESTATE_QUIESCE    yes if the capture is --quiesce's, which pauses the
 *                      databases it finds running, and no if it is not
 *   RESTATE_SETTINGS   what --hook-option (a job's hook_option) gives this
 *                      hook, by its name: "KEY=VALUE" a line, in the order
 *                      given. A hook reads them over its own configuration
 *                      file, so that a job can say what a site's file need
 *                      not ("stop = never" for one server's PostgreSQL)
 *   RESTATE_REPLY      for pause, a file, empty and root's alone, the hook
 *                      may write one line to. "leave-out" (RS_HOOK_LEAVE_OUT)
 *                      says that its paths are not to be copied at all: it
 *                      did not stop what writes them, and the dump directory
 *                      holds the copy that counts. The capture records none
 *                      of them, and its result says so. Read whether the
 *                      pause succeeded or not.
 *
 * Each dump directory holds RS_HOOKS_MARKER too, restate's own: the kind
 * and the name, a line each. A restore that puts one back runs
 *
 *   HOOK restored NAME     after the files are back, to put right what the
 *                          pause left in them (Nextcloud's maintenance mode)
 *
 * with RESTATE_ACTION, RESTATE_KIND and RESTATE_NAME as before, RESTATE_ROOT
 * the root restored into, and RESTATE_DUMP_DIR the dump directory as it was
 * put back beneath it -- the hook installed on the machine restored onto,
 * never one from the image. A hook that exits 2, as one does for an action
 * it does not know, has nothing to do; any other failure leaves the restore
 * incomplete.
 *
 * It is asked too, as
 *
 *   HOOK present NAME      whether what it pauses is on this host
 *
 * which looks and changes nothing, and prints "present" or "absent": one
 * that prints neither, or fails, does not know (rs_hook_present).
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
/* In each, which hook it is for: "KIND\nNAME\n". */
#define RS_HOOKS_MARKER   ".restate-hook"
#define RS_HOOKS_MARKER_WORD 255

/*
 * Replaces the directories hooks are looked for in, for the tests' benefit.
 * NULL restores the default. No option or variable reaches it.
 */
void rs_hooks_set_dirs(const char *const *dirs, size_t n);

/* The hook for `kind`, or NULL if there is none restate would run. */
char *rs_hook_find(const char *kind);
/*
 * The hook for a running program `program` (rs_live_programs) that no kind
 * covers: RS_HOOKS_SITE_DIR/PROGRAM, root's and writable by no one else, and
 * nowhere else -- a hook restate ships is never run for a program's name, nor
 * one named as a kind or a shipped hook is. NULL if there is none.
 */
char *rs_hook_for_program(const char *program);
/* The names of every hook restate would run here, sorted, but for one that
 * says what it pauses is absent (rs_hook_present); the caller frees each,
 * and the array. */
char **rs_hooks_list(size_t *n);

/*
 * The dump directory for `l` beneath `root`, made if it is not there, as a
 * directory root's alone; NULL, with the reason in `err`, if it cannot be.
 * Its path as the walk sees it ("/var/lib/restate/dumps/postgresql-18-main")
 * goes into *tree_path.
 */
bool rs_hook_dump_dir(const char *root, const struct rs_live *l, char **tree_path,
                      struct rs_buf *err);

/* What the capture gives every hook it runs, beyond the thing itself. */
struct rs_hook_call {
    const char        *dump_dir;    /* RESTATE_DUMP_DIR, or NULL */
    bool               quiescing;   /* a capture with --quiesce */
    const char *const *settings;    /* --hook-option's, "HOOK.KEY=VALUE" each */
    size_t             nsettings;
};

/* The one reply a pause can give in RESTATE_REPLY. */
#define RS_HOOK_LEAVE_OUT "leave-out"

/*
 * Runs `hook` for `action` ("pause", "resume") on `l`. True if it exited 0.
 * With `leave_out`, the hook is given RESTATE_REPLY, and *leave_out says
 * whether it replied RS_HOOK_LEAVE_OUT.
 */
bool rs_hook_run(const char *hook, const char *action, const struct rs_live *l,
                 const struct rs_hook_call *c, bool *leave_out, struct rs_buf *err);

/* True if `path` is a dump directory's RS_HOOKS_MARKER, as the walk sees it. */
bool rs_hook_is_marker(const char *path);
/* A marker's kind and name, which the caller frees; false, with both NULL, if
 * it is not "KIND\nNAME\n" with a kind a hook could be named. */
bool rs_hook_marker_parse(const char *text, size_t len, char **kind, char **name);
/* Runs `HOOK restored NAME` (above). True if it ran; its status in *code. */
bool rs_hook_restored(const char *hook, const char *kind, const char *name, const char *root,
                      const char *dump_dir, int *code, struct rs_buf *err);

enum rs_hook_presence {
    RS_HOOK_UNKNOWN, /* it prints neither word, fails or cannot be run */
    RS_HOOK_PRESENT,
    RS_HOOK_ABSENT
};

/*
 * Whether what `hook` pauses is on this host, as `HOOK present NAME` says.
 * A hook that does not know the question is RS_HOOK_UNKNOWN, and is treated
 * as there: only RS_HOOK_ABSENT leaves one out.
 */
enum rs_hook_presence rs_hook_present(const char *hook, const char *name);

/*
 * For a hook named by --quiesce-with: the paths it pauses what it covers
 * for, as `HOOK paths NAME` prints them, one absolute path a line, each
 * resolved to its real path (one that is not there is left out). None -- a
 * hook that prints nothing, or does not know the question and fails -- means
 * it is paused for the whole walk. False only if it could not be run.
 */
bool rs_hook_paths(const char *hook, const char *name, char ***paths, size_t *n,
                   struct rs_buf *err);

#endif /* RESTATE_HOOKS_H */
