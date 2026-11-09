/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "test.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "meta.h"
#include "util.h"

int         rs_test_checks = 0;
int         rs_test_failures = 0;
const char *rs_test_case = "(none)";
const char *rs_test_argv0 = NULL;

static int case_count = 0;

/*
 * Failures are reported on a stream duplicated out of stderr before any test
 * runs. Some tests capture stderr for the length of a case, and a failure
 * written into the capture would be counted at the end but named nowhere.
 */
static FILE *report = NULL;

/*
 * What a case writes to stderr -- its own warnings, and those of the gzip and
 * gpg it runs, which many cases make fail on purpose -- goes to a file of its
 * own, shown under the case's failures if it has any, and dropped if it has
 * none. RESTATE_TEST_STDERR=1 leaves stderr alone, to watch it all as it is
 * written. The file is opened O_APPEND, so that what a case's children write
 * lands after what it wrote itself, and it is removed as soon as it is open.
 */
static int   case_log = -1;
static int   case_failures_at = 0;
static pid_t case_log_pid = 0;   /* not a child's: a forked test's exit leaves it be */

static void case_log_open(void)
{
    const char *keep = getenv("RESTATE_TEST_STDERR");
    char       *dir;
    char       *path;

    if ((keep && strcmp(keep, "1") == 0) || !report)
    {
        return;
    }
    dir = rs_test_tmpdir();
    path = rs_xasprintf("%s/stderr", dir);
    case_log = open(path, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0600);
    (void)unlink(path);
    (void)rmdir(dir);
    free(path);
    free(dir);
    if (case_log >= 0 && dup2(case_log, STDERR_FILENO) < 0)
    {
        (void)close(case_log);
        case_log = -1;
    }
    case_log_pid = getpid();
}

/* The case done: what it wrote shown, if it failed, and then dropped. */
static void case_log_end(void)
{
    if (case_log < 0)
    {
        return;
    }
    if (rs_test_failures > case_failures_at && lseek(case_log, 0, SEEK_SET) == 0)
    {
        char    buf[4096];
        ssize_t got;
        bool    any = false;
        bool    line_start = true;

        while ((got = read(case_log, buf, sizeof(buf))) > 0)
        {
            ssize_t i;

            if (!any)
            {
                (void)fprintf(report, "    what %s wrote to stderr:\n", rs_test_case);
                any = true;
            }
            for (i = 0; i < got; i++)
            {
                if (line_start)
                {
                    (void)fputs("      ", report);
                }
                (void)fputc(buf[i], report);
                line_start = buf[i] == '\n';
            }
        }
        if (any && !line_start)
        {
            (void)fputc('\n', report);
        }
        (void)fflush(report);
    }
    if (ftruncate(case_log, 0) < 0)
    {
        /* Not emptied, so the next case's failures would show this one's
         * stderr too: better to stop catching it than to mislead. */
        (void)dup2(fileno(report), STDERR_FILENO);
        (void)close(case_log);
        case_log = -1;
    }
    case_failures_at = rs_test_failures;
}

/* A test that exits early, as rs_test_tmpdir does when it cannot make one,
 * says why on stderr: shown, rather than dropped with the file. */
static void case_log_at_exit(void)
{
    if (case_log >= 0 && getpid() == case_log_pid)
    {
        case_failures_at = -1;
        case_log_end();
    }
}

void rs_test_begin(const char *name)
{
    case_log_end();
    rs_test_case = name;
    case_count++;
}

void rs_test_fail(const char *file, int line, const char *fmt, ...)
{
    va_list ap;
    FILE   *out = report ? report : stderr;

    rs_test_failures++;
    (void)fflush(stdout);
    (void)fprintf(out, "  \033[91mFAIL\033[0m %s\n    %s:%d: ", rs_test_case, file, line);
    va_start(ap, fmt);
    (void)vfprintf(out, fmt, ap);
    va_end(ap);
    (void)fputc('\n', out);
    (void)fflush(out);
}

static bool installed(const char *name)
{
    char *a = rs_xasprintf("/usr/bin/%s", name);
    char *b = rs_xasprintf("/usr/local/bin/%s", name);
    bool  ok = access(a, X_OK) == 0 || access(b, X_OK) == 0;

    free(a);
    free(b);
    return ok;
}

bool rs_test_have_gpg(void)
{
    return installed("gpg") && installed("gpgconf") && installed("gpg-agent");
}

char *rs_test_tmpdir(void)
{
    const char *base = getenv("TMPDIR");
    size_t      n;
    char       *path;

    /* macOS's $TMPDIR ends in a slash, and a path with "//" in it is not one a job takes. */
    if (base == NULL || *base == '\0')
    {
        base = "/tmp";
    }
    n = strlen(base);
    while (n > 1 && base[n - 1] == '/')
    {
        n--;
    }
    path = rs_xasprintf("%.*s/restate-test.XXXXXX", (int)n, base);

    if (!mkdtemp(path))
    {
        (void)fprintf(stderr, "mkdtemp %s: %s\n", path, strerror(errno));
        exit(2);
    }
    return path;
}

void rs_test_rmtree(const char *path)
{
    struct stat st;
    DIR        *d;

    if (lstat(path, &st) < 0)
    {
        return;
    }
    if (!S_ISDIR(st.st_mode))
    {
        (void)unlink(path);
        return;
    }
    /* Tests make directories unreadable on purpose; take that back first. */
    (void)chmod(path, 0700);
    d = opendir(path);
    if (d)
    {
        struct dirent *de;

        while ((de = readdir(d)) != NULL)
        {
            char *child;

            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            {
                continue;
            }
            child = rs_xasprintf("%s/%s", path, de->d_name);
            rs_test_rmtree(child);
            free(child);
        }
        (void)closedir(d);
    }
    (void)rmdir(path);
}

void rs_test_write(const char *dir, const char *name, const char *text, unsigned mode)
{
    char *path = rs_xasprintf("%s/%s", dir, name);
    int   fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)mode);

    if (fd < 0 || write(fd, text, strlen(text)) != (ssize_t)strlen(text))
    {
        (void)fprintf(stderr, "writing %s: %s\n", path, strerror(errno));
        exit(2);
    }
    (void)close(fd);
    (void)chmod(path, (mode_t)mode);
    free(path);
}

char *rs_test_slurp(const char *path)
{
    struct rs_buf b;
    char          chunk[4096];
    int           fd = open(path, O_RDONLY);
    ssize_t       n;

    rs_buf_init(&b);
    rs_buf_add(&b, "", 0);
    if (fd < 0)
    {
        return rs_buf_detach(&b);
    }
    while ((n = read(fd, chunk, sizeof(chunk))) > 0)
    {
        rs_buf_add(&b, chunk, (size_t)n);
    }
    (void)close(fd);
    return rs_buf_detach(&b);
}

int rs_test_capture(int (*fn)(const void *), const void *arg, char **out, char **err)
{
    char *dir = rs_test_tmpdir();
    char *out_path = rs_xasprintf("%s/out", dir);
    char *err_path = rs_xasprintf("%s/err", dir);
    int   saved_out;
    int   saved_err;
    int   fd_out;
    int   fd_err;
    int   status;

    (void)fflush(stdout);
    (void)fflush(stderr);
    saved_out = dup(STDOUT_FILENO);
    saved_err = dup(STDERR_FILENO);
    fd_out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    fd_err = open(err_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (saved_out < 0 || saved_err < 0 || fd_out < 0 || fd_err < 0)
    {
        (void)fprintf(stderr, "capture setup failed\n");
        exit(2);
    }
    (void)dup2(fd_out, STDOUT_FILENO);
    (void)dup2(fd_err, STDERR_FILENO);
    (void)close(fd_out);
    (void)close(fd_err);

    status = fn(arg);

    (void)fflush(stdout);
    (void)fflush(stderr);
    (void)dup2(saved_out, STDOUT_FILENO);
    (void)dup2(saved_err, STDERR_FILENO);
    (void)close(saved_out);
    (void)close(saved_err);

    *out = rs_test_slurp(out_path);
    *err = rs_test_slurp(err_path);
    rs_test_rmtree(dir);
    free(out_path);
    free(err_path);
    free(dir);
    return status;
}

int main(int argc, char **argv)
{
    char *self = argc > 0 ? realpath(argv[0], NULL) : NULL;
    int   report_fd;

#ifdef RS_WITH_PROXY
    if (argc == 6 && strcmp(argv[1], "--tls-serve") == 0)
    {
        free(self);
        return test_tls_serve(argv + 2);
    }
    if (argc == 6 && strcmp(argv[1], "--confine-test") == 0)
    {
        free(self);
        return test_confine_run(argv + 2);
    }
#endif
    rs_test_argv0 = self;
    report_fd = dup(STDERR_FILENO);

    if (report_fd >= 0)
    {
        report = fdopen(report_fd, "w");
        if (!report)
        {
            (void)close(report_fd);
        }
    }

    case_log_open();
    if (case_log >= 0)
    {
        (void)atexit(case_log_at_exit);
    }
    (void)printf("restate unit tests\n");

    test_util();
    test_sha256();
    test_glob();
    test_rules();
    test_json();
    test_meta();
    test_index();
    test_image();
    test_machine();
    test_packages();
    test_restore();
    test_accounts();
    test_installer();
    test_rebuild();
    test_pgp();
    test_bsd();
    test_progress();
    test_scan();
    test_md5();
    test_blake2b();
    test_sha1();
    test_pkgdb();
    test_xattr();
    test_fsflags();
    test_live();
    test_sources();
    test_repo();
    test_diff();
    test_opts();
    test_reinstall();
    test_baseline();
    test_identity();
    test_clones();
    test_jobs();
    test_arch();
    test_result();
    test_grant();
    test_request();
    test_remote();
#ifdef RS_WITH_PROXY
    test_tls();
    test_serve();
    test_sessions();
    test_commit();
    test_confine();
#endif
    test_cmd();

    case_log_end();
    if (case_log >= 0)
    {
        (void)dup2(fileno(report), STDERR_FILENO);
        (void)close(case_log);
        case_log = -1;
    }
    rs_name_cache_free();
    if (rs_test_failures == 0)
    {
        (void)printf("  \033[92m✓\033[0m %d checks in %d cases, all passed\n",
                     rs_test_checks, case_count);
    } else
    {
        (void)printf("  \033[91m✗\033[0m %d of %d checks failed\n", rs_test_failures,
                     rs_test_checks);
    }
    if (report)
    {
        (void)fclose(report);
    }
    rs_test_argv0 = NULL;
    free(self);
    return rs_test_failures == 0 ? 0 : 1;
}
