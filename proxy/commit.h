/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * A commit (docs/proxy-protocol.md, "Commits"): what an append session
 * uploaded into its staging, put into its repository by `restate ingest`'s
 * own code (rs_repo_ingest), and the answer the protocol gives for it.
 *
 * The repository is opened without its lock (RS_REPO_HELD): the session
 * holds that, in the listening process, for as long as the commit runs.
 */
#ifndef RESTATE_COMMIT_H
#define RESTATE_COMMIT_H

#include <stdbool.h>
#include <stdint.h>

#include "util.h"

/* What a commit came to. */
struct rs_proxy_committed {
    int           status;     /* 201, 200, 409, 422, 507 or 500 */
    const char   *reason;     /* Restate-Reason: NULL for 200 and 201 */
    /* What is wrong, in a line: for the client, for a 422 and a 409, with
     * no path of the storage host's in it; for the log, for a 500 and a
     * 507, as it is. */
    struct rs_buf message;
    bool          pack_added;     /* 201 for a pack: a pack the session put there */
    bool          snapshot_added; /* 201 for a snapshot */
    uint64_t      bytes;          /* copied into the repository */
};

void rs_proxy_committed_init(struct rs_proxy_committed *c);
void rs_proxy_committed_free(struct rs_proxy_committed *c);

/*
 * The commit of `name` -- "packs/NAME", "snapshots/NAME", "chunk-key" or
 * "chunk-key.NAME", as a route names it, already checked -- from `staging`,
 * the session's staging directory, into the repository at `repository`.
 * Once it is in (201) or was there (200), what was staged for it is removed.
 */
void rs_proxy_commit(const char *repository, const char *staging, const char *name,
                     struct rs_proxy_committed *out);

#endif /* RESTATE_COMMIT_H */
