/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The fuzz target: everything in restate that reads bytes somebody else wrote.
 *
 * Three things are input. An image -- a tar stream with a JSON index at the
 * front -- is read back by `diff` and `verify`, and it may have been carried
 * on a USB stick, copied off a dead machine, or edited by hand. A rules file
 * is written by an administrator, but it is still a parser. And the patterns
 * in it are run against every path on the machine, so a pattern that makes
 * the matcher allocate, loop or recurse without bound is a denial of service
 * on the scan.
 *
 * The first byte of each input chooses which of them it is fed to, so one
 * corpus and one run cover all of them:
 *
 *   0  an index (JSON): parsed, written back out, parsed again and diffed
 *      against itself -- the round trip must be lossless
 *   1  a rules file: parsed, then used to classify a fixed set of paths
 *   2  a pattern and a path, separated by a NUL: matched both ways
 *   3  a tar stream: its first member read, and fed to the index parser
 *   4  a timestamp: parsed, and if it parses, formatted back identically
 *   5  base64: decoded, re-encoded, and compared
 *   6  LVM metadata, as /etc/lvm/backup holds it: parsed, and if it parses,
 *      written out as JSON and parsed again
 *   7  a LUKS1 or LUKS2 header, as the start of a block device holds it
 *   8  a SHA256SUMS file, as a vendor's mirror serves it: an image is picked
 *      from it, and what is picked must be a plain file name with a digest
 *   9  the package inventories: dpkg's status, apt's sources, snapd's state
 *  10  account files, the system's and the image's, merged
 *  11  dpkg's record of the files it installed -- diversions, status,
 *      md5sums and list, between NULs -- loaded, and every path looked up
 *  12  what /proc says of a process -- its status, an fdinfo and a mongod
 *      configuration between NULs, then its command line -- parsed
 *  13  a repository's pack index, its marker and snapshot names, and the
 *      chunker
 *  14  OpenPGP as text: ASCII armor taken off, gpgv's status lines read, and
 *      a Release file's Valid-Until, all from the same input
 *  15  an apt repository as baseline fetch reads it -- an InRelease file, a
 *      Packages list, an origin and a URI, between NULs -- the signed text
 *      split out, the list's entries read, the origin split and the URI
 *      mapped to the archive's snapshot; the origin read as apt's
 *      credentials too
 *  16  a list of copies, as autoinstall --clones reads it, and an /etc/hosts
 *      given a copy's name: each name the copies parse to must be one --as
 *      takes, and the hosts file given its own name back must be unchanged
 *  17  a job file, as restate run reads it: what is accepted names a command,
 *      with its arguments and every path in it absolute
 *  18  what the storage checks a repository by without its keys -- a pack's
 *      .sum, a snapshot's pack list and a check's record, between NULs --
 *      each, accepted, holding what it says: lowercase digests, names in
 *      order and each once
 *
 * It is reached two ways:
 *
 *   libFuzzer (clang)  LLVMFuzzerTestOneInput, coverage-guided
 *   the built-in loop  a mutation fuzzer over a seed corpus, in-process, which
 *                      needs nothing but the compiler already in use
 *
 * Either way it runs under AddressSanitizer and UndefinedBehaviorSanitizer,
 * and they do the judging. The round-trip checks below abort() on their own
 * when an invariant fails, which both engines treat as a crash.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "accounts.h"
#include "baseline.h"
#include "clones.h"
#include "diff.h"
#include "glob.h"
#include "identity.h"
#include "index.h"
#include "installer.h"
#include "jobs.h"
#include "json.h"
#include "live.h"
#include "machine.h"
#include "meta.h"
#include "packages.h"
#include "pgp.h"
#include "pkgdb.h"
#include "repo.h"
#include "rules.h"
#include "sha256.h"
#include "sources.h"
#include "tar.h"
#include "util.h"

/* Patterns and paths longer than this say nothing a shorter one does not, and
 * the matcher is O(pattern x path), so cap them to keep the run fast. */
#define GLOB_MAX 2048

/* dpkg's database, its four kinds of file between NULs, then a BSD package's
 * +CONTENTS and pkgsrc's +INSTALL. Every path loaded is found again, under
 * its own name and its merged-/usr one. */
static void fuzz_pkgdb(const char *text, size_t len)
{
    char           *parts[10];
    const char     *p = text;
    const char     *end = text + len;
    struct rs_pkgdb db;
    size_t          i;

    for (i = 0; i < 10; i++)
    {
        const char *nul = p < end ? memchr(p, '\0', (size_t)(end - p)) : NULL;
        size_t      n = p < end ? (nul ? (size_t)(nul - p) : (size_t)(end - p)) : 0;

        parts[i] = rs_xstrndup(p, n);
        p += n + (nul ? 1 : 0);
    }
    rs_pkgdb_init(&db);
    rs_pkgdb_parse_diversions(&db, parts[0]);
    (void)rs_pkgdb_parse_status(&db, parts[1]);
    for (i = 0; i < db.nnames; i++)
    {
        rs_pkgdb_parse_md5sums(&db, (uint32_t)i, parts[2]);
        rs_pkgdb_parse_list(&db, (uint32_t)i, parts[3]);
    }
    rs_pkgdb_parse_md5sums(&db, (uint32_t)db.nnames, parts[2]);
    if (rs_pkgdb_parse_contents(&db, parts[4]))
    {
        rs_pkgdb_parse_install(&db, (uint32_t)(db.nnames - 1), "/usr/pkg", parts[5]);
    }
    rs_pkgdb_parse_install(&db, (uint32_t)db.nnames, "/usr/pkg", parts[5]);
    (void)rs_pkgdb_parse_pkg(&db, parts[6]);
    (void)rs_pkgdb_parse_rpm(&db, parts[7]);
    (void)rs_pkgdb_parse_apk(&db, parts[8]);
    rs_pkgdb_parse_mtree(&db, (uint32_t)(db.nnames > 0 ? db.nnames - 1 : 0), parts[9]);
    rs_pkgdb_parse_mtree(&db, (uint32_t)db.nnames, parts[9]);
    rs_pkgdb_sort(&db);
    for (i = 0; i < db.nfiles; i++)
    {
        const struct rs_pkgfile *f;
        size_t                   n = rs_pkgdb_lookup(&db, db.files[i].path, &f);
        size_t                   blen;
        char                    *other;

        if (n == 0 || f > &db.files[i] || &db.files[i] >= f + n ||
            !rs_path_is_clean(db.files[i].path))
        {
            abort();
        }
        (void)rs_pkgdb_package(&db, f, &blen);
        if (blen == 0 || blen > strlen(db.names[f->pkg]))
        {
            abort();
        }
        if (rs_pkgdigest_size(db.files[i].digest_kind) > sizeof(db.files[i].digest))
        {
            abort();
        }
        (void)rs_pkgdb_scoped(&db, db.files[i].path);
        other = rs_xasprintf("/usr%s", db.files[i].path);
        (void)rs_pkgdb_lookup(&db, other, &f);
        free(other);
    }
    rs_pkgdb_free(&db);
    for (i = 0; i < 10; i++)
    {
        free(parts[i]);
    }
}

/* /proc's files for one process: three between NULs, then the command line,
 * whose own NULs separate its arguments. */
static void fuzz_live(const char *text, size_t len)
{
    char         *parts[3];
    const char   *p = text;
    const char   *end = text + len;
    char        **argv;
    size_t        argc;
    size_t        nuls = 0;
    size_t        i;
    unsigned long uid;
    unsigned long flags;
    long          ppid;
    char         *db;

    for (i = 0; i < 3; i++)
    {
        const char *nul = p < end ? memchr(p, '\0', (size_t)(end - p)) : NULL;
        size_t      n = p < end ? (nul ? (size_t)(nul - p) : (size_t)(end - p)) : 0;

        parts[i] = rs_xstrndup(p, n);
        p += n + (nul ? 1 : 0);
    }
    if (rs_live_parse_status(parts[0], &uid, &ppid) && ppid < 0)
    {
        abort();
    }
    (void)rs_live_parse_fdflags(parts[1], &flags);
    db = rs_live_mongo_dbpath(parts[2]);
    if (db && (db[0] == '\0' || strchr(db, '\n')))
    {
        abort();
    }
    free(db);
    if (p > end)
    {
        p = end;
    }
    rs_live_split_args(p, (size_t)(end - p), &argv, &argc);
    for (i = 0; i < (size_t)(end - p); i++)
    {
        nuls += p[i] == '\0';
    }
    /* One argument per NUL, and one more if the last is not terminated. */
    if (argc != nuls + (end > p && end[-1] != '\0' ? 1 : 0))
    {
        abort();
    }
    for (i = 0; i < argc; i++)
    {
        free(argv[i]);
    }
    free(argv);
    for (i = 0; i < 3; i++)
    {
        free(parts[i]);
    }
}

/* Armor, gpgv's verdict and a Valid-Until, each read from the same text. */
static void fuzz_openpgp(const char *text, size_t len)
{
    char                *s = rs_xstrndup(text, len);
    struct rs_buf        out;
    struct rs_buf        why;
    struct rs_pgp_signer signer;
    int64_t              when;

    rs_buf_init(&out);
    if (rs_pgp_dearmor(text, len, &out) && out.len > len)
    {
        abort();
    }
    rs_buf_free(&out);
    rs_buf_init(&why);
    if (rs_pgp_verdict(s, &signer, &why))
    {
        /* Good: a fingerprint of 40 hex digits, and no reason given. */
        if (strlen(signer.fpr) != 40 || strspn(signer.fpr, "0123456789ABCDEFabcdef") != 40 ||
            why.len != 0 || strlen(signer.who) >= sizeof(signer.who))
        {
            abort();
        }
    } else if (why.len == 0)
    {
        abort();
    }
    rs_buf_free(&why);
    if (rs_sources_valid_until(s, &when) && when < 0)
    {
        abort();
    }
    free(s);
}

static bool all_hex(const char *s, size_t n)
{
    return strlen(s) == n && strspn(s, "0123456789abcdef") == n;
}

static void apt_entry(void *ctx, const struct rs_baseline_entry *e)
{
    (void)ctx;
    if (!e->name || !e->version || !e->arch || !e->filename || !all_hex(e->sha256, 64))
    {
        abort();
    }
}

/* What baseline fetch reads of a repository, NUL-separated. */
static void fuzz_clones(const char *text, size_t len)
{
    struct rs_clones c;
    struct rs_buf    err;
    struct rs_buf    out;

    rs_buf_init(&err);
    if (rs_clones_parse(&c, text, len, "fuzz", &err))
    {
        size_t i;

        for (i = 0; i < c.count; i++)
        {
            if (!rs_identity_name_ok(c.items[i].name) || (!c.items[i].mac && !c.items[i].serial))
            {
                abort();
            }
        }
    }
    rs_clones_free(&c);
    rs_buf_free(&err);
    rs_buf_init(&out);
    (void)rs_identity_hosts(text, len, "web1", "web1", &out);
    if (out.len != len || (len > 0 && memcmp(out.data, text, len) != 0))
    {
        abort();
    }
    rs_buf_reset(&out);
    (void)rs_identity_hosts(text, len, "a", "longer-name", &out);
    rs_buf_free(&out);
}

/* A job file: what is accepted names a command, its arguments are where the
 * command wants them, and every path in it is absolute. */
static void fuzz_jobs(const char *text, size_t len)
{
    struct rs_job job;
    struct rs_buf err;

    rs_job_init(&job);
    rs_buf_init(&err);
    if (rs_job_parse(text, len, "fuzz", &job, &err))
    {
        const struct rs_options *o = &job.opts;
        size_t                   i;

        if (o->command == CMD_NONE ||
            (o->command == CMD_CAPTURE && (!o->output || o->output[0] != '/')))
        {
            abort();
        }
        for (i = 0; i < o->nargs; i++)
        {
            if (!o->args[i] || o->args[i][0] != '/')
            {
                abort();
            }
        }
        for (i = 0; i < o->nrules_files; i++)
        {
            if (o->rules_files[i][0] != '/' || strstr(o->rules_files[i], "/../"))
            {
                abort();
            }
        }
        for (i = 0; i < o->nquiesce_with; i++)
        {
            if (strchr(o->quiesce_with[i], '/'))
            {
                abort();
            }
        }
    } else if (!err.data || !*err.data)
    {
        abort();   /* a job refused says why */
    }
    rs_job_free(&job);
    rs_buf_free(&err);
}

/* A pack's .sum, a snapshot's pack list, a check's record and a pack's
 * .seek, NUL-separated: what each accepts is what it says it is -- digests
 * in lowercase hex, names in order and each once, segments going up from the
 * pack's start. */
static void fuzz_storage(const char *text, size_t len)
{
    const char           *parts[4] = { "", "", "", "" };
    size_t                lens[4] = { 0, 0, 0, 0 };
    struct rs_repo_seek  *at;
    size_t                k = 0;
    size_t                i;
    char                  hex[RS_SHA256_HEX_SIZE];
    uint64_t              size;
    char                **names;
    size_t                n;
    struct rs_repo_record rec;

    parts[0] = text;
    for (i = 0; i < len && k < 3; i++)
    {
        if (text[i] == '\0')
        {
            lens[k] = (size_t)(text + i - parts[k]);
            parts[++k] = text + i + 1;
        }
    }
    lens[k] = (size_t)(text + len - parts[k]);
    if (rs_repo_parse_seek(parts[3], lens[3], &at, &n))
    {
        if (n == 0 || at[0].member != 1 || at[0].offset != 0)
        {
            abort();
        }
        for (i = 1; i < n; i++)
        {
            if (at[i].member <= at[i - 1].member || at[i].offset <= at[i - 1].offset)
            {
                abort();
            }
        }
        free(at);
    } else if (at || n)
    {
        abort();
    }
    if (rs_repo_parse_sum(parts[0], lens[0], hex, &size) && !all_hex(hex, 64))
    {
        abort();
    }
    if (rs_repo_parse_pack_list(parts[1], lens[1], &names, &n))
    {
        for (i = 0; i < n; i++)
        {
            if (!rs_repo_name_valid(names[i]) || (i > 0 && strcmp(names[i - 1], names[i]) >= 0))
            {
                abort();
            }
        }
        rs_repo_free_names(names, n);
    }
    if (rs_repo_parse_record(parts[2], lens[2], &rec))
    {
        for (i = 0; i < rec.n; i++)
        {
            if (!all_hex(rec.entries[i].hash, 64) || rec.entries[i].path[0] == '/' ||
                strstr(rec.entries[i].path, "..") ||
                (i > 0 && strcmp(rec.entries[i - 1].path, rec.entries[i].path) >= 0))
            {
                abort();
            }
        }
        rs_repo_record_free(&rec);
    }
}

static void fuzz_apt(const char *text, size_t len)
{
    const char   *parts[4] = { "", "", "", "" };
    size_t        lens[4] = { 0, 0, 0, 0 };
    char         *copy[4];
    struct rs_buf out;
    char          sha[RS_SHA256_HEX_SIZE];
    uint64_t      size;
    char         *uri;
    char         *suite;
    char         *comp;
    char         *deb;
    size_t        k = 0;
    size_t        i;

    parts[0] = text;
    for (i = 0; i < len && k < 3; i++)
    {
        if (text[i] == '\0')
        {
            lens[k] = (size_t)(text + i - parts[k]);
            parts[++k] = text + i + 1;
        }
    }
    lens[k] = (size_t)(text + len - parts[k]);
    for (i = 0; i < 4; i++)
    {
        copy[i] = rs_xstrndup(parts[i], lens[i]);
    }
    rs_buf_init(&out);
    if (rs_sources_signed_part(parts[0], lens[0], &out) && out.len > lens[0])
    {
        abort();
    }
    rs_buf_free(&out);
    if (rs_baseline_release_entry(copy[0], "main/binary-amd64/Packages.gz", sha, &size) &&
        !all_hex(sha, 64))
    {
        abort();
    }
    rs_baseline_parse_packages(parts[1], lens[1], apt_entry, NULL);
    if (rs_baseline_label(copy[2], &uri, &suite, &comp))
    {
        if (uri[0] == '\0' || strchr(uri, ' ') || strchr(comp, '/'))
        {
            abort();
        }
        free(uri);
        free(suite);
        free(comp);
    }
    rs_buf_init(&out);
    if (rs_baseline_snapshot_uri(copy[3], "20261010T000000Z", &out) &&
        !rs_starts_with(out.data, "https://snapshot."))
    {
        abort();
    }
    rs_buf_free(&out);
    /* The origin's text read as apt's credentials, against sources that
     * reach two hosts over https and one over http: whatever comes out is
     * whole "machine ... login ... password ..." lines. */
    {
        static const char      sources[] = "{\"sources\": [{\"uris\": [\"https://a.example/x\", "
                                           "\"https://esm.ubuntu.com/apps/ubuntu\", "
                                           "\"http://b.example\"]}]}";
        struct rs_jval         apt;
        struct rs_json_parser  jp;
        struct rs_buf          jerr;
        const char            *line;

        memset(&apt, 0, sizeof(apt));
        rs_buf_init(&jerr);
        rs_json_init(&jp, sources, sizeof(sources) - 1, &jerr);
        if (!rs_json_value(&jp, &apt))
        {
            abort();
        }
        rs_buf_free(&jerr);
        rs_buf_init(&out);
        if (rs_baseline_netrc(copy[2], &apt, &out) != (out.len > 0))
        {
            abort();
        }
        for (line = out.data; line && *line; line = strchr(line, '\n') + 1)
        {
            if (!rs_starts_with(line, "machine a.example login ") &&
                !rs_starts_with(line, "machine esm.ubuntu.com login "))
            {
                abort();
            }
        }
        rs_buf_free(&out);
        rs_jval_free(&apt);
    }
    deb = rs_baseline_deb_name(copy[2], copy[3], "amd64");
    if (deb && (strchr(deb, '/') || strlen(deb) < 5 || strcmp(deb + strlen(deb) - 4, ".deb") != 0))
    {
        abort();
    }
    free(deb);
    for (i = 0; i < 4; i++)
    {
        free(copy[i]);
    }
}

/* A pack's .idx, and the names prune chooses between, from the same text. */
static void fuzz_repo(const char *text, size_t len)
{
    struct rs_repo_idx     x;
    struct rs_repo_keep    keep;
    char                 **names = NULL;
    bool                  *kept;
    char                  *copy = rs_xstrndup(text, len);
    char                  *line;
    char                  *next;
    size_t                 n = 0;
    size_t                 i;
    size_t                 cut;
    int                    version;
    bool                   encrypted;
    bool                   newer;

    if (rs_repo_parse_idx(text, len, &x))
    {
        const struct rs_repo_member *m = x.members;

        for (i = 0; i < x.nmembers; i++)
        {
            if ((i > 0 && m[i].member <= m[i - 1].member) ||
                (m[i].live && !rs_sha256_valid_hex(m[i].hash)))
            {
                abort();
            }
        }
        for (i = 0; i < x.nlists; i++)
        {
            size_t c;

            if (x.lists[i].n < 2 || x.lists[i].first + x.lists[i].n > x.nchunks ||
                !rs_sha256_valid_hex(x.lists[i].hash))
            {
                abort();
            }
            for (c = 0; c < x.lists[i].n; c++)
            {
                if (!rs_sha256_valid_hex(x.chunks[x.lists[i].first + c]))
                {
                    abort();
                }
            }
        }
    } else if (x.members || x.nmembers || x.lists || x.nlists || x.chunks || x.nchunks)
    {
        abort();
    }
    rs_repo_idx_free(&x);
    /* A chunk ends inside what it was given, and no later than its maximum. */
    cut = rs_repo_chunk_cut((const unsigned char *)text, len);
    if (cut > len || cut > RS_REPO_CHUNK_MAX || (len > 0 && cut == 0) ||
        (len <= RS_REPO_CHUNK_MIN && cut != len))
    {
        abort();
    }
    if (rs_repo_parse_marker(copy, &version, &encrypted, &newer))
    {
        if ((version != 1 && version != 2) || newer || (version == 1 && encrypted))
        {
            abort();
        }
    } else if (version != 0 || encrypted)
    {
        abort();
    }
    n = 0;
    for (line = copy; line; line = next)
    {
        next = strchr(line, '\n');
        if (next)
        {
            *next++ = '\0';
        }
        names = rs_xreallocarray(names, n + 1, sizeof(*names));
        names[n++] = line;
    }
    kept = rs_xcalloc(n + 1, sizeof(*kept));
    memset(&keep, 0, sizeof(keep));
    keep.daily = (unsigned)(len % 5);
    keep.weekly = (unsigned)(len % 3);
    keep.monthly = 1;
    keep.last = (unsigned)(len % 2);
    rs_repo_choose(names, n, &keep, kept);
    for (i = 0; i < n; i++)
    {
        /* What is not a time is never dropped. */
        if (!kept[i] && strlen(names[i]) < 9)
        {
            abort();
        }
        (void)rs_repo_name_valid(names[i]);
    }
    free(kept);
    free(names);
    free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void fuzz_index(const char *text, size_t len)
{
    struct rs_index ix;
    struct rs_buf   err;

    rs_index_init(&ix);
    rs_buf_init(&err);
    if (rs_index_parse(&ix, text, len, "fuzz", &err))
    {
        /* Whatever parses must write out and parse back to the same thing. */
        char  *copy = NULL;
        size_t n = 0;
        FILE  *fp = open_memstream(&copy, &n);

        if (fp)
        {
            struct rs_index      back;
            struct rs_diff_stats st;
            FILE                *sink = fopen("/dev/null", "w");

            (void)rs_index_write(&ix, fp);
            (void)fclose(fp);
            rs_index_init(&back);
            rs_buf_reset(&err);
            if (!rs_index_parse(&back, copy, n, "back", &err))
            {
                abort();   /* we wrote something we cannot read */
            }
            if (back.count != ix.count)
            {
                abort();
            }
            if (sink)
            {
                if (!rs_diff_write(&ix, &back, sink, &st) ||
                    st.added || st.deleted || st.modified)
                {
                    abort();   /* the round trip lost something */
                }
                (void)fclose(sink);
            }
            rs_index_free(&back);
            free(copy);
        }
        /* What is in each directory: every name a child of it, and each
         * entry's own name where it has one. */
        {
            size_t i;

            for (i = 0; i < ix.count && i < 64; i++)
            {
                size_t           nkids;
                size_t           k;
                struct rs_child *c = rs_index_children(&ix, ix.entries[i].path, &nkids);

                for (k = 0; k < nkids; k++)
                {
                    if (c[k].name[0] == '\0' || strchr(c[k].name, '/') ||
                        (c[k].entry && strcmp(strrchr(c[k].entry->path, '/') + 1, c[k].name) != 0))
                    {
                        abort();
                    }
                }
                rs_index_children_free(c, nkids);
            }
        }
    }
    rs_index_free(&ix);
    rs_buf_free(&err);
}

static void fuzz_rules(const char *text, size_t len)
{
    static const char *const paths[] = {
        "/", "/etc/passwd", "/usr/local/bin/x", "/var/lib/a/b.pid", "/tmp",
        "/home/u/.cache/z", "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p"
    };
    struct rs_rules rs;
    struct rs_buf   err;

    rs_rules_init(&rs);
    rs_buf_init(&err);
    (void)rs_rules_parse(&rs, text, len, "fuzz", &err);
    /* Only a handful of rules: classification is rules x depth x pattern, and
     * a ten-thousand-rule input is a slow input, not an interesting one. */
    if (rs.count <= 64)
    {
        size_t i;

        for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        {
            long          which;
            enum rs_class cls = rs_rules_classify(&rs, paths[i], &which);

            if (which >= (long)rs.count || (which >= 0 && rs.rules[which].cls != cls))
            {
                abort();
            }
        }
    }
    rs_rules_free(&rs);
    rs_buf_free(&err);
}

/* Whether rs_glob_below may say yes for `pattern`: anchored, no escapes to
 * hide a '/', and no "**" in its first component. */
static bool reaches(const char *pattern)
{
    size_t first = strcspn(pattern + (pattern[0] != '\0'), "/");
    size_t i;

    if (pattern[0] != '/' || strchr(pattern, '\\'))
    {
        return false;
    }
    for (i = 1; i < first; i++)
    {
        if (pattern[i] == '*' && pattern[i + 1] == '*')
        {
            return false;
        }
    }
    return true;
}

static void fuzz_glob(const char *text, size_t len)
{
    const char *nul = memchr(text, '\0', len);
    char       *pattern;
    char       *path;

    if (!nul)
    {
        return;
    }
    pattern = rs_xstrndup(text, (size_t)(nul - text));
    path = rs_xstrndup(nul + 1, len - (size_t)(nul - text) - 1);
    if (strlen(pattern) <= GLOB_MAX && strlen(path) <= GLOB_MAX)
    {
        bool matched = rs_glob_match(pattern, path);
        bool covered = rs_glob_covers(pattern, path);

        bool   ancestor = false;
        char  *copy = rs_xstrdup(path);
        size_t i;

        /* Covering is matching the path or an ancestor -- the path up to any
         * '/' after its first character -- however it is worked out. */
        for (i = 1; copy[0] != '\0' && copy[i] != '\0' && !ancestor; i++)
        {
            if (copy[i] == '/')
            {
                copy[i] = '\0';
                ancestor = rs_glob_match(pattern, copy);
                copy[i] = '/';
            }
        }
        free(copy);
        if (covered != (matched || ancestor))
        {
            abort();
        }
        if (matched && rs_path_is_clean(path) && strcmp(path, "/") != 0 && reaches(pattern))
        {
            /* A walk goes into each directory on the way to whatever such a
             * pattern matches: nothing it matches is out of its reach. */
            char *dir = rs_xstrdup(path);
            char *slash;

            while ((slash = strrchr(dir, '/')) != NULL)
            {
                bool top = slash == dir;

                slash[top ? 1 : 0] = '\0';
                if (!rs_glob_below(pattern, dir))
                {
                    abort();
                }
                if (top)
                {
                    break;
                }
            }
            free(dir);
        }
    }
    free(pattern);
    free(path);
}

struct mem_reader {
    const char *p;
    size_t      len;
    size_t      pos;
};

static ssize_t mem_read(void *ctx, void *data, size_t n)
{
    struct mem_reader *r = ctx;

    if (n > r->len - r->pos)
    {
        n = r->len - r->pos;
    }
    memcpy(data, r->p + r->pos, n);
    r->pos += n;
    return (ssize_t)n;
}

static void fuzz_tar(const char *text, size_t len)
{
    struct mem_reader r = { text, len, 0 };
    struct rs_buf     name;
    struct rs_buf     content;
    struct rs_buf     err;

    rs_buf_init(&name);
    rs_buf_init(&content);
    rs_buf_init(&err);
    if (rs_tar_read_first(mem_read, &r, 1u << 20, &name, &content, &err))
    {
        fuzz_index(content.data, content.len);
    }
    rs_buf_free(&name);
    rs_buf_free(&content);

    /* Member by member, as restore reads an image's files: every header,
     * and every member's data, to the end or the first thing wrong. */
    {
        struct mem_reader    again = { text, len, 0 };
        struct rs_tar_reader tr;
        struct rs_tar_entry  e;
        unsigned char        chunk[512];
        int                  members = 0;

        rs_tar_reader_init(&tr, mem_read, &again);
        rs_tar_entry_init(&e);
        rs_buf_reset(&err);
        while (members++ < 64 && rs_tar_next(&tr, &e, &err) == 1)
        {
            /* Every other member read, the rest left for rs_tar_next to skip. */
            while (members % 2 == 0 && rs_tar_read(&tr, chunk, sizeof(chunk), &err) > 0)
            {
            }
        }
        rs_tar_entry_free(&e);
    }
    rs_buf_free(&err);
}

static void fuzz_time(const char *text, size_t len)
{
    char           *s = rs_xstrndup(text, len < 64 ? len : 64);
    struct rs_time  t;

    if (rs_time_parse(s, &t))
    {
        struct rs_time again;
        char           back[RS_TIME_STR_MAX];

        rs_time_format(&t, back);
        if (!rs_time_parse(back, &again) || !rs_time_equal(&t, &again))
        {
            abort();
        }
    }
    free(s);
}

static void fuzz_base64(const char *text, size_t len)
{
    struct rs_buf raw;
    struct rs_buf enc;

    rs_buf_init(&raw);
    rs_buf_init(&enc);
    if (rs_base64_decode(text, len, &raw))
    {
        rs_base64_encode(&enc, raw.data, raw.len);
        /* Decoding then encoding may only normalize unused padding bits. */
        if (enc.len != len)
        {
            abort();
        }
    }
    rs_buf_free(&raw);
    rs_buf_free(&enc);
}

static void fuzz_lvm(const char *text, size_t len)
{
    struct rs_jval tree;
    struct rs_buf  err;

    memset(&tree, 0, sizeof(tree));
    rs_buf_init(&err);
    if (rs_lvm_parse(text, len, &tree, &err))
    {
        /* Whatever parses must be expressible as JSON that parses back. */
        struct rs_buf         json;
        struct rs_json_parser jp;
        struct rs_jval        back;
        struct rs_buf         jerr;

        rs_buf_init(&json);
        rs_buf_init(&jerr);
        rs_json_write(&json, &tree, 2, 0);
        rs_json_init(&jp, json.data, json.len, &jerr);
        memset(&back, 0, sizeof(back));
        if (!rs_json_value(&jp, &back) || back.type != RS_JOBJECT)
        {
            /* Deeper than JSON allows is the one legitimate refusal. */
            if (!strstr(jerr.data ? jerr.data : "", "nested too deeply"))
            {
                abort();
            }
        }
        rs_jval_free(&back);
        rs_buf_free(&json);
        rs_buf_free(&jerr);
    }
    rs_jval_free(&tree);
    rs_buf_free(&err);
}

static void fuzz_luks(const char *data, size_t len)
{
    struct rs_jval out;

    memset(&out, 0, sizeof(out));
    (void)rs_luks_parse((const unsigned char *)data, len, &out);
    rs_jval_free(&out);
}

/* Downloaded before its signature is checked, so it is read as hostile. */
static void fuzz_sums(const char *data, size_t len)
{
    static char         release[] = "26.04";
    static char         point[] = "26.04.1";
    static char         flavor[] = "live-server";
    static char         arch[] = "amd64";
    struct rs_installer in;
    char               *name = NULL;
    char                hash[RS_SHA256_HEX_SIZE];

    memset(&in, 0, sizeof(in));
    in.release = release;
    in.point = (len % 2) ? point : NULL;
    in.flavor = flavor;
    in.arch = arch;
    if (rs_installer_pick(&in, data, len, &name, hash))
    {
        if (strchr(name, '/') || strstr(name, "..") || strncmp(name, "ubuntu-26.04", 12) != 0 ||
            !rs_sha256_valid_hex(hash))
        {
            abort();
        }
    }
    free(name);
}

/*
 * The package inventory reads files from the tree it describes, and a tree
 * mounted from another machine says whatever it likes. So the input is laid
 * out as such a tree -- its parts, between NULs, become dpkg's status, apt's
 * extended states, a sources.list, a deb822 .sources file, a package list,
 * snapd's state, /etc/passwd, an alternatives entry and a cargo record -- and
 * the whole inventory is taken of it. The tree is made once and rewritten for
 * each input.
 */
static const char *const pkg_files[] = {
    "var/lib/dpkg/status",
    "var/lib/apt/extended_states",
    "etc/apt/sources.list",
    "etc/apt/sources.list.d/fuzz.sources",
    "var/lib/apt/lists/deb.example.com_dists_s_main_binary-amd64_Packages",
    "var/lib/snapd/state.json",
    "etc/passwd",
    "var/lib/dpkg/alternatives/editor",
    "home/u/.cargo/.crates2.json",
};
static const char *const pkg_dirs[] = {
    "var", "var/lib", "var/lib/dpkg", "var/lib/dpkg/alternatives", "var/lib/apt",
    "var/lib/apt/lists", "var/lib/snapd", "etc", "etc/apt", "etc/apt/sources.list.d",
    "home", "home/u", "home/u/.cargo",
};
static char *pkg_root;

static void pkg_cleanup(void)
{
    size_t i;

    for (i = 0; pkg_root && i < sizeof(pkg_files) / sizeof(pkg_files[0]); i++)
    {
        char *path = rs_xasprintf("%s/%s", pkg_root, pkg_files[i]);

        (void)remove(path);
        free(path);
    }
    for (i = sizeof(pkg_dirs) / sizeof(pkg_dirs[0]); pkg_root && i > 0; i--)
    {
        char *path = rs_xasprintf("%s/%s", pkg_root, pkg_dirs[i - 1]);

        (void)remove(path);
        free(path);
    }
    if (pkg_root)
    {
        (void)remove(pkg_root);
    }
    free(pkg_root);
    pkg_root = NULL;
}

static bool pkg_tree(void)
{
    const char *tmp = getenv("TMPDIR"); /* Flawfinder: ignore */
    size_t      i;

    if (pkg_root)
    {
        return true;
    }
    pkg_root = rs_xasprintf("%s/restate-fuzz.XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(pkg_root))
    {
        free(pkg_root);
        pkg_root = NULL;
        return false;
    }
    for (i = 0; i < sizeof(pkg_dirs) / sizeof(pkg_dirs[0]); i++)
    {
        char *path = rs_xasprintf("%s/%s", pkg_root, pkg_dirs[i]);

        (void)mkdir(path, 0700);
        free(path);
    }
    (void)atexit(pkg_cleanup);
    return true;
}

static void fuzz_packages(const char *text, size_t len)
{
    struct rs_jval inv;
    struct rs_buf  missing;
    const char    *p = text;
    const char    *end = text + len;
    size_t         i;
    size_t         n;
    char         **kept;

    if (!pkg_tree())
    {
        return;
    }
    for (i = 0; i < sizeof(pkg_files) / sizeof(pkg_files[0]); i++)
    {
        const char *nul = p < end ? memchr(p, '\0', (size_t)(end - p)) : NULL;
        size_t      part = p < end ? (nul ? (size_t)(nul - p) : (size_t)(end - p)) : 0;
        char       *path = rs_xasprintf("%s/%s", pkg_root, pkg_files[i]);
        FILE       *fp = fopen(path, "w");

        if (fp)
        {
            if (part > 0)
            {
                (void)fwrite(p, 1, part, fp);
            }
            (void)fclose(fp);
        }
        free(path);
        p += part + (nul ? 1 : 0);
    }
    memset(&inv, 0, sizeof(inv));
    rs_packages_describe(pkg_root, &inv);
    rs_buf_init(&missing);
    kept = rs_packages_keep(pkg_root, &inv, NULL, 0, &n, &missing);
    for (i = 0; i < n; i++)
    {
        free(kept[i]);
    }
    free(kept);
    kept = rs_packages_apt_words(&inv, NULL, true, &n);
    for (i = 0; i < n; i++)
    {
        free(kept[i]);
    }
    free(kept);
    rs_buf_free(&missing);
    rs_jval_free(&inv);
}

/* The account merge restore does before any file goes back: the input's
 * parts, between NULs, are the system's passwd, group, shadow and gshadow,
 * then the image's. Every name the merge produced is looked up again. */
static void fuzz_accounts(const char *text, size_t len)
{
    char                   *parts[8];
    const char             *p = text;
    const char             *end = text + len;
    struct rs_account_files now;
    struct rs_account_files old;
    struct rs_accounts      a;
    struct rs_buf           err;
    size_t                  i;

    for (i = 0; i < 8; i++)
    {
        const char *nul = p < end ? memchr(p, '\0', (size_t)(end - p)) : NULL;
        size_t      n = p < end ? (nul ? (size_t)(nul - p) : (size_t)(end - p)) : 0;

        parts[i] = rs_xstrndup(p, n);
        p += n + (nul ? 1 : 0);
    }
    now.passwd = parts[0];
    now.group = parts[1];
    now.shadow = parts[2];
    now.gshadow = parts[3];
    old.passwd = parts[4];
    old.group = parts[5];
    old.shadow = parts[6];
    old.gshadow = parts[7];
    rs_buf_init(&err);
    if (rs_accounts_merge(&now, &old, &a, &err))
    {
        uint64_t id;

        for (i = 0; i < a.nuids; i++)
        {
            (void)rs_accounts_uid(&a, a.uids[i].name, &id);
        }
        for (i = 0; i < a.ngids; i++)
        {
            (void)rs_accounts_gid(&a, a.gids[i].name, &id);
        }
        rs_accounts_free(&a);
    }
    rs_buf_free(&err);
    for (i = 0; i < 8; i++)
    {
        free(parts[i]);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const char *text;

    if (size < 1)
    {
        return 0;
    }
    text = (const char *)(data + 1);
    switch (data[0] % 19)
    {
    case 0:
        fuzz_index(text, size - 1);
        break;
    case 1:
        fuzz_rules(text, size - 1);
        break;
    case 2:
        fuzz_glob(text, size - 1);
        break;
    case 3:
        fuzz_tar(text, size - 1);
        break;
    case 4:
        fuzz_time(text, size - 1);
        break;
    case 5:
        fuzz_base64(text, size - 1);
        break;
    case 6:
        fuzz_lvm(text, size - 1);
        break;
    case 7:
        fuzz_luks(text, size - 1);
        break;
    case 8:
        fuzz_sums(text, size - 1);
        break;
    case 9:
        fuzz_packages(text, size - 1);
        break;
    case 10:
        fuzz_accounts(text, size - 1);
        break;
    case 11:
        fuzz_pkgdb(text, size - 1);
        break;
    case 12:
        fuzz_live(text, size - 1);
        break;
    case 13:
        fuzz_repo(text, size - 1);
        break;
    case 14:
        fuzz_openpgp(text, size - 1);
        break;
    case 15:
        fuzz_apt(text, size - 1);
        break;
    case 16:
        fuzz_clones(text, size - 1);
        break;
    case 17:
        fuzz_jobs(text, size - 1);
        break;
    default:
        fuzz_storage(text, size - 1);
        break;
    }
    return 0;
}

#ifndef RESTATE_LIBFUZZER
/* ------------------------------------------------------------------------- */
/* The built-in mutation loop                                                */
/* ------------------------------------------------------------------------- */

static uint64_t rng_state;

static uint64_t rng(void)
{
    /* xorshift64*: small, fast, and reproducible from a seed, which is all a
     * fuzzer's dice need to be. */
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1DULL;
}

static size_t rnd(size_t n)
{
    return n ? (size_t)(rng() % n) : 0;
}

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE          *fp = fopen(path, "rb");
    struct rs_buf  b;
    char           chunk[4096];
    size_t         n;

    *len = 0;
    if (!fp)
    {
        return NULL;
    }
    rs_buf_init(&b);
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0)
    {
        rs_buf_add(&b, chunk, n);
    }
    (void)fclose(fp);
    *len = b.len;
    return (unsigned char *)rs_buf_detach(&b);
}

static void save(const char *path, const unsigned char *data, size_t len)
{
    FILE *fp = fopen(path, "wb");

    if (fp)
    {
        (void)fwrite(data, 1, len, fp);
        (void)fclose(fp);
    }
}

/* Interesting bytes: JSON syntax, escapes, pattern syntax, digits. */
static const char magic[] = "{}[]\":,\\u/*?#-.0f7Z@=\n";

static void mutate(struct rs_buf *b, const unsigned char *other, size_t other_len)
{
    size_t rounds = 1 + rnd(8);

    while (rounds-- > 0)
    {
        size_t pos = rnd(b->len + 1);

        switch (rnd(7))
        {
        case 0:   /* flip a bit */
            if (b->len > 1)
            {
                pos = 1 + rnd(b->len - 1);
                b->data[pos] = (char)(b->data[pos] ^ (char)(1u << rnd(8)));
            }
            break;
        case 1:   /* a random byte */
            if (b->len > 1)
            {
                b->data[1 + rnd(b->len - 1)] = (char)rnd(256);
            }
            break;
        case 2:   /* an interesting byte, inserted */
        {
            struct rs_buf n;

            rs_buf_init(&n);
            rs_buf_add(&n, b->data, pos);
            rs_buf_addc(&n, magic[rnd(sizeof(magic) - 1)]);
            rs_buf_add(&n, b->data + pos, b->len - pos);
            rs_buf_free(b);
            *b = n;
            break;
        }
        case 3:   /* delete a run */
            if (b->len > 2)
            {
                size_t at = 1 + rnd(b->len - 1);
                size_t n = 1 + rnd(b->len - at < 16 ? b->len - at : 16);

                memmove(b->data + at, b->data + at + n, b->len - at - n);
                b->len -= n;
                b->data[b->len] = '\0';
            }
            break;
        case 4:   /* duplicate a run */
            if (b->len > 2 && b->len < 1u << 16)
            {
                size_t at = 1 + rnd(b->len - 1);
                size_t n = 1 + rnd(b->len - at < 64 ? b->len - at : 64);
                char  *copy = rs_xmalloc(n);

                /* Copied out first: the add may move the buffer it reads. */
                memcpy(copy, b->data + at, n);
                rs_buf_add(b, copy, n);
                free(copy);
            }
            break;
        case 5:   /* splice in a piece of another input */
            if (other_len > 1)
            {
                size_t at = 1 + rnd(other_len - 1);
                size_t n = 1 + rnd(other_len - at < 128 ? other_len - at : 128);

                rs_buf_add(b, other + at, n);
            }
            break;
        default:  /* change which parser it goes to */
            if (b->len > 0)
            {
                b->data[0] = (char)rnd(19);
            }
            break;
        }
    }
}

int main(int argc, char **argv)
{
    const char     *replay = NULL;
    const char     *crash = ".fuzz/crash.bin";
    unsigned        seconds = 30;
    uint64_t        seed = 0;
    unsigned char **corpus = NULL;
    size_t         *lens = NULL;
    size_t          ncorpus = 0;
    unsigned long   cases = 0;
    time_t          deadline;
    int             i;

    for (i = 1; i < argc; i++)
    {
        if (strncmp(argv[i], "--seconds=", 10) == 0)
        {
            seconds = (unsigned)strtoul(argv[i] + 10, NULL, 10);
        } else if (strncmp(argv[i], "--seed=", 7) == 0)
        {
            seed = strtoull(argv[i] + 7, NULL, 10);
        } else if (strncmp(argv[i], "--crash-file=", 13) == 0)
        {
            crash = argv[i] + 13;
        } else if (strncmp(argv[i], "--replay=", 9) == 0)
        {
            replay = argv[i] + 9;
        } else
        {
            size_t         len;
            unsigned char *d = read_file(argv[i], &len);

            if (d)
            {
                corpus = rs_xreallocarray(corpus, ncorpus + 1, sizeof(*corpus));
                lens = rs_xreallocarray(lens, ncorpus + 1, sizeof(*lens));
                corpus[ncorpus] = d;
                lens[ncorpus] = len;
                ncorpus++;
            }
        }
    }

    if (replay)
    {
        size_t         len;
        unsigned char *d = read_file(replay, &len);

        if (!d)
        {
            (void)fprintf(stderr, "cannot read %s\n", replay);
            return 2;
        }
        (void)LLVMFuzzerTestOneInput(d, len);
        free(d);
        (void)printf("replayed %s without a crash\n", replay);
        return 0;
    }
    if (ncorpus == 0)
    {
        (void)fprintf(stderr, "no seed corpus given\n");
        return 2;
    }

    rng_state = seed ? seed : (uint64_t)time(NULL) ^ 0x9E3779B97F4A7C15ULL;
    (void)printf("  seed %llu; reproduce with --seed=%llu\n",
                 (unsigned long long)rng_state, (unsigned long long)rng_state);
    deadline = time(NULL) + (time_t)seconds;

    /* Every seed once as it is, then mutations until the time is up. */
    for (i = 0; i < (int)ncorpus; i++)
    {
        save(crash, corpus[i], lens[i]);
        (void)LLVMFuzzerTestOneInput(corpus[i], lens[i]);
        cases++;
    }
    while (time(NULL) < deadline)
    {
        int k;

        for (k = 0; k < 256; k++)
        {
            size_t        pick = rnd(ncorpus);
            size_t        other = rnd(ncorpus);
            struct rs_buf b;

            rs_buf_init(&b);
            rs_buf_add(&b, corpus[pick], lens[pick]);
            if (b.len == 0)
            {
                rs_buf_addc(&b, (char)rnd(8));
            }
            mutate(&b, corpus[other], lens[other]);
            /* Written before it runs: if this one kills the process, the file
             * left behind is the input that did it. */
            save(crash, (const unsigned char *)b.data, b.len);
            (void)LLVMFuzzerTestOneInput((const uint8_t *)b.data, b.len);
            rs_buf_free(&b);
            cases++;
        }
    }
    (void)remove(crash);
    for (i = 0; i < (int)ncorpus; i++)
    {
        free(corpus[i]);
    }
    free(corpus);
    free(lens);
    (void)printf("  %lu cases, no crashes\n", cases);
    return 0;
}
#endif /* RESTATE_LIBFUZZER */
