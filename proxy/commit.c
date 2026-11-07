/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "commit.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "repo.h"
#include "store.h"

void rs_proxy_committed_init(struct rs_proxy_committed *c)
{
    memset(c, 0, sizeof(*c));
    rs_buf_init(&c->message);
}

void rs_proxy_committed_free(struct rs_proxy_committed *c)
{
    rs_buf_free(&c->message);
    memset(c, 0, sizeof(*c));
}

/* `text` with every `what` in it replaced by `with`, into `out`. */
static void replace_all(const char *text, const char *what, const char *with, struct rs_buf *out)
{
    size_t      wl = strlen(what);
    const char *p = text;
    const char *hit;

    while (wl > 0 && (hit = strstr(p, what)) != NULL)
    {
        rs_buf_add(out, p, (size_t)(hit - p));
        rs_buf_addstr(out, with);
        p = hit + wl;
    }
    rs_buf_addstr(out, p);
}

/*
 * `why`, as the client is told it: one line, with the storage host's paths
 * taken out -- the session's staging, where an upload is, and the
 * repository's own directory -- so that what is named is named as the
 * protocol names it ("packs/NAME.tar.gz: ...").
 */
static void for_client(const char *why, const char *repository, const char *staging,
                       struct rs_buf *out)
{
    struct rs_buf a;
    struct rs_buf b;
    char         *with_slash;
    size_t        i;

    rs_buf_init(&a);
    rs_buf_init(&b);
    with_slash = rs_xasprintf("%s/", staging);
    replace_all(why, with_slash, "", &a);
    free(with_slash);
    with_slash = rs_xasprintf("%s/", repository);
    replace_all(a.data ? a.data : "", with_slash, "", &b);
    free(with_slash);
    rs_buf_reset(&a);
    replace_all(b.data ? b.data : "", repository, "the repository", &a);
    for (i = 0; a.data && i < a.len; i++)
    {
        if (a.data[i] == '\n' || a.data[i] == '\r')
        {
            a.data[i] = ' ';
        }
    }
    rs_buf_addstr(out, a.data ? a.data : "");
    rs_buf_free(&a);
    rs_buf_free(&b);
}

/* The commit failed, as `in` says: its status, and what to say of it. */
static void failed(const struct rs_repo_ingested *in, const char *why, const char *repository,
                   const char *staging, struct rs_proxy_committed *out)
{
    if (in->sys_errno == ENOSPC
#ifdef EDQUOT
        || in->sys_errno == EDQUOT
#endif
    )
    {
        out->status = 507;
        out->reason = "storage-full";
        rs_buf_addstr(&out->message, why);
        return;
    }
    if (in->sys_errno != 0)
    {
        out->status = 500;
        out->reason = "proxy-failed";
        rs_buf_addstr(&out->message, why);
        return;
    }
    out->status = in->taken ? 409 : 422;
    out->reason = in->taken ? "name-taken" : "invalid";
    for_client(why, repository, staging, &out->message);
}

/* What the commit of `name` staged, removed: a pack's files, a snapshot's
 * directory, a chunk key. */
static void unstage(const char *staging, const char *name)
{
    static const char *const pack_ext[] = { "tar.gz", "sum", "idx", "seek" };
    static const char *const snap[] = { "index.json.gz", "index.sig", "kit", "info", "packs" };
    struct rs_store         *st = rs_store_local(staging);
    size_t                   i;

    if (strncmp(name, "packs/", 6) == 0)
    {
        for (i = 0; i < sizeof(pack_ext) / sizeof(pack_ext[0]); i++)
        {
            char *file = rs_xasprintf("%s.%s", name, pack_ext[i]);

            (void)rs_store_remove(st, file, false);
            free(file);
        }
    } else if (strncmp(name, "snapshots/", 10) == 0)
    {
        for (i = 0; i < sizeof(snap) / sizeof(snap[0]); i++)
        {
            char *file = rs_xasprintf("%s/%s", name, snap[i]);

            (void)rs_store_remove(st, file, false);
            free(file);
        }
        (void)rs_store_remove_dir(st, name, false);
    } else
    {
        (void)rs_store_remove(st, name, false);
    }
    rs_store_free(st);
}

void rs_proxy_commit(const char *repository, const char *staging, const char *name,
                     struct rs_proxy_committed *out)
{
    struct rs_repo_ingested in;
    struct rs_store        *st = rs_store_local(staging);
    struct rs_store_stat    is;
    struct rs_buf           err;
    struct rs_repo         *r;
    char                   *staged;
    char                   *path;
    bool                    busy = false;
    bool                    is_pack = strncmp(name, "packs/", 6) == 0;
    bool                    is_snapshot = strncmp(name, "snapshots/", 10) == 0;
    bool                    placed = false;
    bool                    ok;

    memset(&in, 0, sizeof(in));
    rs_buf_init(&err);
    /* What it names has to have been uploaded: a pack's content, a
     * snapshot's directory, the chunk key. */
    staged = is_pack ? rs_xasprintf("%s.tar.gz", name) : rs_xstrdup(name);
    if (rs_store_stat(st, staged, &is) != 0 ||
        is.kind != (is_snapshot ? RS_STORE_DIR : RS_STORE_FILE))
    {
        out->status = 422;
        out->reason = "invalid";
        rs_buf_addf(&out->message, "%s: not uploaded in this session", staged);
        free(staged);
        rs_store_free(st);
        rs_buf_free(&err);
        return;
    }
    path = rs_store_path(st, staged);
    rs_store_free(st);
    free(staged);
    r = rs_repo_open(repository, RS_REPO_HELD, &busy, &err);
    if (!r)
    {
        out->status = 500;
        out->reason = "proxy-failed";
        rs_buf_addstr(&out->message, err.data ? err.data : repository);
        free(path);
        rs_buf_free(&err);
        return;
    }
    if (is_pack || is_snapshot)
    {
        ok = rs_repo_ingest(r, path, &in, &err);
    } else
    {
        ok = rs_repo_ingest_chunk_key(r, path, name, &placed, &in, &err);
    }
    rs_repo_close(r);
    free(path);
    if (!ok)
    {
        failed(&in, err.data ? err.data : "it could not be put in", repository, staging, out);
        rs_buf_free(&err);
        return;
    }
    rs_buf_free(&err);
    out->pack_added = is_pack && in.packs_added > 0;
    out->snapshot_added = is_snapshot && in.snapshots_added > 0;
    out->status = out->pack_added || out->snapshot_added || placed ? 201 : 200;
    out->bytes = in.bytes;
    unstage(staging, name);
}
