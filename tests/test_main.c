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

static int case_count = 0;

/*
 * Failures are reported on a stream duplicated out of stderr before any test
 * runs. Some tests capture stderr for the length of a case, and a failure
 * written into the capture would be counted at the end but named nowhere.
 */
static FILE *report = NULL;

void rs_test_begin(const char *name)
{
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

char *rs_test_tmpdir(void)
{
    const char *base = getenv("TMPDIR");
    char       *path = rs_xasprintf("%s/restate-test.XXXXXX",
                                    base && *base ? base : "/tmp");

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

static char *slurp(const char *path)
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

    *out = slurp(out_path);
    *err = slurp(err_path);
    rs_test_rmtree(dir);
    free(out_path);
    free(err_path);
    free(dir);
    return status;
}

int main(void)
{
    int report_fd = dup(STDERR_FILENO);

    if (report_fd >= 0)
    {
        report = fdopen(report_fd, "w");
        if (!report)
        {
            (void)close(report_fd);
        }
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
    test_installer();
    test_rebuild();
    test_pgp();
    test_bsd();
    test_scan();
    test_diff();
    test_opts();
    test_cmd();

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
    return rs_test_failures == 0 ? 0 : 1;
}
