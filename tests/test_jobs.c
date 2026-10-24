/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "jobs.h"
#include "test.h"

/* Parses `text`; on failure, what was said, in `why` (freed by the caller). */
static bool parse(struct rs_job *job, const char *text, char **why)
{
    struct rs_buf err;
    bool          ok;

    rs_buf_init(&err);
    ok = rs_job_parse(text, strlen(text), "j.conf", job, &err);
    *why = err.data ? rs_buf_detach(&err) : rs_xstrdup("");
    return ok;
}

/* Whether `text` is refused, saying `needle`. */
static void refused(const char *text, const char *needle)
{
    struct rs_job job;
    char         *why;

    rs_job_init(&job);
    CHECK(!parse(&job, text, &why));
    CHECK_CONTAINS(why, needle);
    free(why);
    rs_job_free(&job);
}

static void capture_job(void)
{
    struct rs_job job;
    char         *why;

    TEST_CASE("jobs: a capture, every key it takes");
    rs_job_init(&job);
    CHECK(parse(&job,
                "# nightly\n"
                "\n"
                "  command = capture  \r\n"
                "repository=/mnt/nas/restate/web01\n"
                "root = /\n"
                "rules = /etc/restate/site.rules\n"
                "rules = /etc/restate/more.rules\n"
                "all = yes\n"
                "baseline_content = false\n"
                "one_file_system = true\n"
                "quiesce = true\n"
                "quiesce_with = unifi\n"
                "quiesce_with = nextcloud\n"
                "encrypt_to = /etc/restate/keys/a.asc\n"
                "sign_with = /etc/restate/keys/s.gpg\n"
                "append_only = true\n"
                "tmpdir = /var/tmp\n"
                "syslog = true\n"
                "result = /var/lib/restate/nightly.json\n"
                "progress = /var/lib/restate/nightly.progress\n"
                "report_group = restate-report\n",
                &why));
    CHECK_STR(why, "");
    free(why);
    CHECK_INT(job.opts.command, CMD_CAPTURE);
    CHECK_STR(job.opts.output, "/mnt/nas/restate/web01");
    CHECK_STR(job.opts.root, "/");
    CHECK_INT(job.opts.nrules_files, 2);
    CHECK_STR(job.opts.nrules_files == 2 ? job.opts.rules_files[1] : NULL,
              "/etc/restate/more.rules");
    CHECK(job.opts.all && !job.opts.baseline_content && job.opts.one_fs && job.opts.quiesce);
    CHECK_INT(job.opts.nquiesce_with, 2);
    CHECK_INT(job.opts.nrecipients, 1);
    CHECK_STR(job.opts.sign_with, "/etc/restate/keys/s.gpg");
    CHECK(job.opts.append_only && job.opts.log_outcome);
    CHECK_STR(job.opts.tmpdir, "/var/tmp");
    CHECK_STR(job.opts.result, "/var/lib/restate/nightly.json");
    CHECK_STR(job.opts.progress_file, "/var/lib/restate/nightly.progress");
    CHECK_STR(job.opts.report_group, "restate-report");
    CHECK_INT(job.opts.nargs, 0);
    rs_job_free(&job);
}

static void other_jobs(void)
{
    struct rs_job job;
    char         *why;

    TEST_CASE("jobs: prune, check, snapshots, du, repack and protect take the repository as "
              "their argument");
    rs_job_init(&job);
    CHECK(parse(&job, "command = prune\nrepository = /r\nkeep_last = 3\nkeep_daily = 7\n"
                      "keep_weekly = 4\nkeep_monthly = 12\nwhole_packs = true\ndry_run = no\n"
                      "record = /var/lib/r.record\nencrypt_to = /k.asc\n",
                &why));
    free(why);
    CHECK_INT(job.opts.command, CMD_PRUNE);
    CHECK_INT(job.opts.nargs, 1);
    CHECK_STR(job.opts.args[0], "/r");
    CHECK(job.opts.keep_last == 3 && job.opts.keep_daily == 7 && job.opts.keep_weekly == 4 &&
          job.opts.keep_monthly == 12 && job.opts.whole_packs && !job.opts.dry_run);
    CHECK_STR(job.opts.record, "/var/lib/r.record");
    CHECK(parse(&job, "command = check\nrepository = /r\nread_all = true\n"
                      "trusted_key = /k.asc\n", &why));
    free(why);
    CHECK(job.opts.command == CMD_CHECK && job.opts.read_all && job.opts.ntrusted == 1);
    CHECK(parse(&job, "command = check\nrepository = /r\nmetadata_only = true\n", &why));
    free(why);
    CHECK(job.opts.metadata_only);
    CHECK(parse(&job, "command = snapshots\nrepository = /r\n", &why));
    free(why);
    CHECK(job.opts.command == CMD_SNAPSHOTS && job.opts.nargs == 1);
    CHECK(parse(&job, "command = du\nrepository = /r\n", &why));
    free(why);
    CHECK(job.opts.command == CMD_DU && job.opts.nargs == 1);
    CHECK(parse(&job, "command = repack\nrepository = /r\ndry_run = true\n"
                      "record = /var/lib/r.record\nsyslog = true\n", &why));
    free(why);
    CHECK(job.opts.command == CMD_REPACK && job.opts.nargs == 1 && job.opts.dry_run);
    CHECK_STR(job.opts.args[0], "/r");
    refused("command = repack\nrepository = /r\nkeep_last = 3\n", "keep_last");
    CHECK(parse(&job, "command = protect\nrepository = /r\ngroup = backup\nsyslog = true\n"
                      "result = /var/lib/r.json\n", &why));
    free(why);
    CHECK(job.opts.command == CMD_PROTECT && job.opts.nargs == 1 && job.opts.log_outcome);
    CHECK_STR(job.opts.args[0], "/r");
    CHECK_STR(job.opts.group, "backup");
    refused("command = protect\nrepository = /r\ngroup = ../x\n", "group: not");
    refused("command = protect\nrepository = /r\ndry_run = true\n", "dry_run");
    refused("command = capture\nrepository = /r\ngroup = backup\n", "group");

    TEST_CASE("jobs: estimate needs no repository");
    CHECK(parse(&job, "command = estimate\nroot = /srv\nall = true\n", &why));
    free(why);
    CHECK(job.opts.command == CMD_ESTIMATE && job.opts.nargs == 0 && job.opts.all);
    CHECK_STR(job.opts.root, "/srv");

    TEST_CASE("jobs: copy and restore name a snapshot, in either spelling");
    CHECK(parse(&job, "command = copy\nrepository = /r\nsnapshot = 20261020T030000Z\n"
                      "copy_to = /offsite\n", &why));
    free(why);
    CHECK_INT(job.opts.nargs, 2);
    CHECK_STR(job.opts.args[0], "/r::20261020T030000Z");
    CHECK_STR(job.opts.args[1], "/offsite");
    CHECK(parse(&job, "command = copy\nrepository = /r\ncopy_to = /offsite\n", &why));
    free(why);
    CHECK_STR(job.opts.args[0], "/r");
    CHECK(parse(&job, "command = restore\nsnapshot = /r::20261020T030000Z\n"
                      "restore_root = /var/tmp/restore\ninclude = /home/bob\ninclude = /etc\n"
                      "exclude = /etc/fstab\ndry_run = true\ncheck_first = yes\n"
                      "trusted_key = /k.asc\nallow_unverified = false\nrules = /x.rules\n",
                &why));
    free(why);
    CHECK_INT(job.opts.command, CMD_RESTORE);
    CHECK_STR(job.opts.args[0], "/r::20261020T030000Z");
    CHECK_STR(job.opts.root, "/var/tmp/restore");
    CHECK_INT(job.opts.nincludes, 2);
    CHECK_INT(job.opts.nexcludes, 1);
    CHECK(job.opts.dry_run && job.opts.check_first && !job.opts.allow_unverified);
    CHECK(!job.opts.plan_only);
    rs_job_free(&job);
    /* A plan is a dry run; "plan = no" is no plan, and no dry run of itself. */
    CHECK(parse(&job, "command = restore\nrepository = /r\nplan = true\n", &why));
    free(why);
    CHECK(job.opts.plan_only && job.opts.dry_run);
    rs_job_free(&job);
    CHECK(parse(&job, "command = restore\nrepository = /r\nplan = no\n", &why));
    free(why);
    CHECK(!job.opts.plan_only && !job.opts.dry_run);
    rs_job_free(&job);

    TEST_CASE("jobs: status, of the newest snapshot or one named, against a root");
    CHECK(parse(&job, "command = status\nrepository = /r\n", &why));
    free(why);
    CHECK_INT(job.opts.command, CMD_STATUS);
    CHECK_INT(job.opts.nargs, 1);
    CHECK_STR(job.opts.args[0], "/r");
    rs_job_free(&job);
    CHECK(parse(&job, "command = status\nrepository = /r\nsnapshot = 20261020T030000Z\n"
                      "root = /mnt/old\ntrusted_key = /k.asc\n", &why));
    free(why);
    CHECK_STR(job.opts.args[0], "/r::20261020T030000Z");
    CHECK_STR(job.opts.root, "/mnt/old");
    CHECK_INT(job.opts.ntrusted, 1);
    rs_job_free(&job);
    CHECK(parse(&job, "command = status\nrepository = /r\nrules = /a.rules\nrules = /b.rules\n"
                      "all = true\none_file_system = yes\n", &why));
    free(why);
    CHECK_INT(job.opts.nrules_files, 2);
    CHECK(job.opts.all && job.opts.one_fs);
    rs_job_free(&job);

    TEST_CASE("jobs: where a refused job says to report");
    {
        static const char text[] = "# refused\n"
                                   "result = relative.json\n"
                                   "result = /var/lib/r.json\n"
                                   "result = /var/lib/second.json\n"
                                   "not a pair\n"
                                   "report_group = bad group\n"
                                   "report_group = restate-report\n"
                                   "command = nonsense\n"
                                   "command = status\n"
                                   "command = list\n"
                                   "keep_last = 3\n";

        rs_job_init(&job);
        rs_job_reporting(text, sizeof(text) - 1, &job);
        CHECK_STR(job.opts.result, "/var/lib/r.json");
        CHECK_STR(job.opts.report_group, "restate-report");
        CHECK_INT(job.opts.command, CMD_STATUS);
        rs_job_reporting("result = /a\0", 12, &job);
        CHECK(job.opts.result == NULL);
        rs_job_reporting("", 0, &job);
        CHECK(job.opts.result == NULL && job.opts.command == CMD_NONE);
        rs_job_free(&job);
    }

    TEST_CASE("jobs: list, a directory of a snapshot, or its top");
    CHECK(parse(&job, "command = list\nsnapshot = /r::20261020T030000Z\npath = /etc\n", &why));
    free(why);
    CHECK_INT(job.opts.command, CMD_LIST);
    CHECK_INT(job.opts.nargs, 2);
    CHECK_STR(job.opts.args[0], "/r::20261020T030000Z");
    CHECK_STR(job.opts.args[1], "/etc");
    rs_job_free(&job);
    CHECK(parse(&job, "command = list\nrepository = /r\n", &why));
    free(why);
    CHECK_INT(job.opts.nargs, 1);
    CHECK_STR(job.opts.args[0], "/r");
    rs_job_free(&job);
}

static void bad_jobs(void)
{
    TEST_CASE("jobs: what is refused, and where");
    refused("", "no command");
    refused("# nothing\n", "no command");
    refused("command = capture\nrepository /r\n", "j.conf:2: not \"key = value\"");
    refused("command = capture\nrepository = /r\nshell = rm -rf /\n",
            "j.conf:3: \"shell\" is not a key");
    refused("command = capture\nrepository = /r\nrepository = /s\n",
            "j.conf:3: repository is given already, on line 2");
    refused("command = capture\ncommand = prune\n", "command is given already");
    refused("command = format\n", "j.conf:1: command: \"format\" is not one");
    refused("command = capture\nrepository = /r\nkeep_last = 3\n",
            "j.conf:3: keep_last means nothing to a capture job");
    refused("keep_last = 3\ncommand = capture\nrepository = /r\n",
            "j.conf:1: keep_last means nothing");
    refused("command = capture\nrepository = /r\nall = maybe\n", "all: not true or false");
    refused("command = prune\nrepository = /r\nkeep_last = -1\n", "keep_last: not a number");
    refused("command = prune\nrepository = /r\nkeep_last = 007\n", "not a number");
    refused("command = prune\nrepository = /r\nkeep_last = 100001\n", "not a number");
    refused("command = prune\nrepository = /r\nkeep_last = 1234567\n", "not a number");
    refused("command = prune\nrepository = /r\nkeep_last =\n", "not a number");
    refused("command = capture\nrepository = r\n", "repository: not an absolute path");
    refused("command = capture\nrepository = /a/../b\n", "not an absolute path");
    refused("command = capture\nrepository = /a/./b\n", "not an absolute path");
    refused("command = capture\nrepository = /a/..\n", "not an absolute path");
    refused("command = capture\nrepository = /a//b\n", "not an absolute path");
    refused("command = capture\nrepository = /a\tb\n", "not an absolute path");
    refused("command = capture\nrepository = /r\nquiesce_with = ../x\n",
            "quiesce_with: not a name");
    refused("command = capture\nrepository = /r\nreport_group = -g\n", "not a name");
    refused("command = restore\nsnapshot = ../x\nrepository = /r\n", "snapshot: not a snapshot");
    refused("command = restore\nsnapshot = r::x\n", "not a snapshot");
    refused("command = restore\nsnapshot = /r::a::b\n", "not a snapshot");
    refused("command = restore\nsnapshot = /r::.x\n", "not a snapshot");
    refused("command = restore\nsnapshot = /r::a b\n", "not a snapshot");
    refused("command = restore\nrepository = /r\ninclude = \x01\n", "include: not a pattern");
    refused("command = restore\nrepository = /r\nsnapshot = /s::x\n",
            "snapshot names its repository");
    refused("command = copy\nrepository = /r\n", "a copy job needs copy_to");
    refused("command = list\nrepository = /r\npath = etc\n", "path: not an absolute path");
    refused("command = list\nrepository = /r\nroot = /\n", "root means nothing to a list job");
    refused("command = status\nrepository = /r\npath = /etc\n",
            "path means nothing to a status job");
    refused("command = status\n", "a status job needs repository, or snapshot as REPO::NAME");
    refused("command = capture\n", "a capture job needs repository");
    refused("command = restore\n", "a restore job needs repository, or snapshot as REPO::NAME");
    {
        static const char nul[] = "command = capture\0\n";
        struct rs_job     job;
        struct rs_buf     err;

        rs_job_init(&job);
        rs_buf_init(&err);
        CHECK(!rs_job_parse(nul, sizeof(nul) - 1, "j.conf", &job, &err));
        CHECK_CONTAINS(err.data, "NUL byte");
        rs_buf_reset(&err);
        {
            size_t n = RS_JOB_MAX + 1;
            char  *big = rs_xmalloc(n);

            memset(big, '#', n);
            CHECK(!rs_job_parse(big, n, "j.conf", &job, &err));
            CHECK_CONTAINS(err.data, "larger than a job can be");
            free(big);
        }
        rs_buf_free(&err);
        rs_job_free(&job);
    }

    TEST_CASE("jobs: the keys there are");
    {
        size_t             n = 0;
        const char *const *keys = rs_job_keys(&n);

        CHECK(n > 30);
        CHECK_STR(keys[0], "command");
        CHECK_STR(keys[n - 1], "group");
    }
}

/* Loads the job at `path` with `given`'s other options. */
static int load(const char *path, struct rs_options *given, struct rs_job *job)
{
    static char *args[2];

    args[0] = (char *)(uintptr_t)path;
    given->command = CMD_RUN;
    given->args = args;
    given->nargs = 1;
    return rs_job_load(given, job);
}

static int load_quiet(const void *arg)
{
    const char *const *a = arg;
    struct rs_options  given;
    struct rs_job      job;
    int                status;

    memset(&given, 0, sizeof(given));
    if (a[1])
    {
        given.root = a[1];
    }
    status = load(a[0], &given, &job);
    rs_job_free(&job);
    return status;
}

/* The options `restate run` takes from the command line: how much to say and
 * where, and nothing about what to do. */
static bool run_may_add(const char *name)
{
    static const char *const may[] = { "quiet",  "verbose",       "progress",     "syslog",
                                       "result", "progress-file", "report-group", "passphrase-fd" };
    size_t                   i;

    for (i = 0; i < sizeof(may) / sizeof(may[0]); i++)
    {
        if (strcmp(name, may[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

/* Loads the job in a[0] as `restate run a[1] JOB` would, a[1] an option. */
static int load_parsed(const void *arg)
{
    const char *const *a = arg;
    char              *argv[5];
    struct rs_options  given;
    struct rs_job      job;
    struct rs_buf      err;
    int                status = -1;

    argv[0] = (char *)(uintptr_t)"restate";
    argv[1] = (char *)(uintptr_t)"run";
    argv[2] = (char *)(uintptr_t)a[1];
    argv[3] = (char *)(uintptr_t)a[0];
    argv[4] = NULL;
    memset(&given, 0, sizeof(given));
    rs_buf_init(&err);
    /* --help and --version are answered before any command is. */
    if (rs_options_parse(4, argv, &given, &err) && given.command == CMD_RUN)
    {
        status = rs_job_load(&given, &job);
        rs_job_free(&job);
    }
    rs_options_free(&given);
    rs_buf_free(&err);
    return status;
}

static void loading(void)
{
    char             *dir = rs_test_tmpdir();
    char             *jobs = rs_xasprintf("%s/jobs.d", dir);
    char             *path = rs_xasprintf("%s/nightly.conf", jobs);
    char             *link = rs_xasprintf("%s/link.conf", jobs);
    struct rs_options given;
    struct rs_job     job;
    const char       *a[2] = { path, NULL };
    char             *out = NULL;
    char             *errs = NULL;

    (void)mkdir(jobs, 0755);
    (void)chmod(jobs, 0755);
    rs_test_write(jobs, "nightly.conf", "command = check\nrepository = /r\n", 0644);

    TEST_CASE("jobs: loaded from a file only its owner can change, "
              "with what the command line adds");
    memset(&given, 0, sizeof(given));
    given.quiet = true;
    given.result = "/tmp/r.json";
    given.report_group = "staff";
    given.passphrase_given = true;
    given.passphrase_fd = 5;
    CHECK_INT(load(path, &given, &job), RESTATE_EXIT_OK);
    CHECK_INT(job.opts.command, CMD_CHECK);
    CHECK(job.opts.quiet && job.opts.passphrase_given && job.opts.passphrase_fd == 5);
    CHECK_STR(job.opts.result, "/tmp/r.json");
    CHECK_STR(job.opts.report_group, "staff");
    rs_job_free(&job);

    TEST_CASE("jobs: but not what to do");
    a[1] = "/elsewhere";
    CHECK_INT(rs_test_capture(load_quiet, a, &out, &errs), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(errs, "what to do is the job's to say");
    free(out);
    free(errs);
    a[1] = NULL;

    TEST_CASE("jobs: no option in the table but those that say how much and where");
    {
        /* A sudoers rule can admit `restate run FILE` and rely on this: an
         * option added to options.def and not thought about here is refused
         * by only_reporting, or this fails. Each is tried in every form the
         * parser might take; a form it refuses cannot reach a job either. */
        static const char *const values[] = { "", "=1", "=json", "=linux", "=x", "=/tmp/x" };
        const char              *name;
        size_t                   i;
        size_t                   parsed = 0;

        for (i = 0; (name = rs_option_name(i)) != NULL; i++)
        {
            size_t v;

            for (v = 0; v < sizeof(values) / sizeof(values[0]); v++)
            {
                char       *opt = rs_xasprintf("--%s%s", name, values[v]);
                const char *pa[2] = { path, opt };
                int         status = rs_test_capture(load_parsed, pa, &out, &errs);

                if (status != -1)
                {
                    parsed++;
                    if (run_may_add(name))
                    {
                        CHECK_INT(status, RESTATE_EXIT_OK);
                    } else if (status != RESTATE_EXIT_TROUBLE ||
                               !strstr(errs, "what to do is the job's to say"))
                    {
                        CHECK_STR(opt, "refused by restate run");
                    }
                }
                free(out);
                free(errs);
                free(opt);
            }
        }
        CHECK(parsed > 50);
    }

    TEST_CASE("jobs: one others could change is not run");
    (void)chmod(path, 0664);
    CHECK_INT(rs_test_capture(load_quiet, a, &out, &errs), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(errs, "writable by no one else");
    free(out);
    free(errs);
    (void)chmod(path, 0644);
    (void)chmod(jobs, 0777);
    CHECK_INT(rs_test_capture(load_quiet, a, &out, &errs), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(errs, "writable by no one else");
    free(out);
    free(errs);
    (void)chmod(jobs, 0755);

    TEST_CASE("jobs: a symlink, a job that is not there, and one that is not a job");
    if (symlink(path, link) == 0)
    {
        a[0] = link;
        CHECK_INT(rs_test_capture(load_quiet, a, &out, &errs), RESTATE_EXIT_TROUBLE);
        CHECK_CONTAINS(errs, "a symlink");
        free(out);
        free(errs);
    }
    a[0] = "/nonexistent/x.conf";
    CHECK_INT(rs_test_capture(load_quiet, a, &out, &errs), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(errs, "/nonexistent/x.conf");
    free(out);
    free(errs);
    rs_test_write(jobs, "bad.conf", "command = capture\n", 0644);
    free(path);
    path = rs_xasprintf("%s/bad.conf", jobs);
    a[0] = path;
    CHECK_INT(rs_test_capture(load_quiet, a, &out, &errs), RESTATE_EXIT_TROUBLE);
    CHECK_CONTAINS(errs, "needs repository");
    free(out);
    free(errs);
    {
        size_t n = RS_JOB_MAX + 10;
        char  *big = rs_xmalloc(n + 1);

        memset(big, '#', n);
        big[n] = '\0';
        rs_test_write(jobs, "big.conf", big, 0644);
        free(big);
        free(path);
        path = rs_xasprintf("%s/big.conf", jobs);
        a[0] = path;
        CHECK_INT(rs_test_capture(load_quiet, a, &out, &errs), RESTATE_EXIT_TROUBLE);
        CHECK_CONTAINS(errs, "larger than a job can be");
        free(out);
        free(errs);
    }
    free(path);
    free(link);
    free(jobs);
    rs_test_rmtree(dir);
    free(dir);
}

void test_jobs(void)
{
    capture_job();
    other_jobs();
    bad_jobs();
    loading();
}
