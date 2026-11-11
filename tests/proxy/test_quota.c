/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * proxy/quota.c: the quota hook, run as the listening process runs it --
 * started, its output read as it comes, reaped, and answered -- with hooks
 * that are shell scripts written here.
 */
#include "test.h"

#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "quota.h"
#include "util.h"

/* A hook in `dir` named `name`, whose body is `script`: its path. */
static char *hook(const char *dir, const char *name, const char *script)
{
    char *text = rs_xasprintf("#!/bin/sh\n%s\n", script);
    char *path = rs_xasprintf("%s/%s", dir, name);

    rs_test_write(dir, name, text, 0755);
    free(text);
    return path;
}

/* `program` run for `q`, as the listener runs it, until it is done: its
 * answer, what it said and why it failed. */
static int run(const char *program, const struct rs_quota_ask *q, unsigned timeout,
               struct rs_buf *message, struct rs_buf *why)
{
    struct rs_quota_run r;
    int                 i;

    rs_buf_reset(message);
    rs_buf_reset(why);
    if (!rs_quota_start(&r, program, q, (int64_t)time(NULL), timeout, why))
    {
        return -1;
    }
    for (i = 0; i < 1000 && !rs_quota_done(&r); i++)
    {
        struct pollfd pfd;
        int           status;
        pid_t         pid;

        if (r.fd >= 0)
        {
            pfd.fd = r.fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            if (poll(&pfd, 1, 50) > 0)
            {
                rs_quota_read(&r);
            }
        } else
        {
            (void)poll(NULL, 0, 50);
        }
        pid = waitpid(r.pid, &status, WNOHANG);
        if (pid > 0)
        {
            CHECK(!rs_quota_reaped(&r, pid + 1, status));
            CHECK(rs_quota_reaped(&r, pid, status));
            CHECK(!rs_quota_reaped(&r, pid, status));
        }
        rs_quota_check_time(&r, (int64_t)time(NULL));
    }
    CHECK(rs_quota_done(&r));
    return rs_quota_answer(&r, message, why);
}

void test_quota(void)
{
    char               *dir = rs_test_tmpdir();
    char               *env_file = rs_xasprintf("%s/env", dir);
    char               *script = rs_xasprintf("env | grep -E '^(RESTATE_PROXY_|PATH=)' | sort "
                                              "> '%s'\nexit 0", env_file);
    char               *yes = hook(dir, "yes", script);
    char               *no = hook(dir, "no", "echo \"web01 is over its \\\"10 GiB\\\" \"\n"
                                             "echo a second line\nexit 1");
    char               *silent = hook(dir, "silent", "exit 1");
    char               *odd = hook(dir, "odd", "printf 'bad \\377\\376 bytes'\nexit 1");
    char               *three = hook(dir, "three", "exit 3");
    char               *slow = hook(dir, "slow", "sleep 30");
    char               *dies = hook(dir, "dies", "kill -9 $$");
    char               *loud = hook(dir, "loud",
                                    "dd if=/dev/zero bs=1000 count=300 2> /dev/null |\n"
                                    "  tr '\\0' x\nexit 1");
    char               *flat = rs_xasprintf("%s/flat", dir);
    struct rs_quota_ask q;
    struct rs_buf       message;
    struct rs_buf       why;
    char               *got;

    free(script);
    rs_buf_init(&message);
    rs_buf_init(&why);
    rs_test_write(dir, "flat", "#!/bin/sh\nexit 0\n", 0644);
    memset(&q, 0, sizeof(q));
    q.event = "upload";
    q.client = "web01";
    q.repository = "/srv/restate/web01";
    q.label = "managed by sysmanage-agent: web01";
    q.name = "packs/P-1.tar.gz";
    q.bytes = 33554432;

    TEST_CASE("quota: a program to run is an absolute path to one this user may run");
    CHECK(rs_quota_program_ok(yes, &why));
    CHECK(!rs_quota_program_ok("hook.sh", &why));
    CHECK_CONTAINS(why.data, "not an absolute path");
    rs_buf_reset(&why);
    CHECK(!rs_quota_program_ok("/nonexistent/hook", &why));
    CHECK_CONTAINS(why.data, "/nonexistent/hook");
    rs_buf_reset(&why);
    CHECK(!rs_quota_program_ok(flat, &why));
    CHECK_CONTAINS(why.data, "not a program this user can run");
    rs_buf_reset(&why);
    CHECK(!rs_quota_program_ok(dir, &why));

    TEST_CASE("quota: yes, with what it is asked in its environment and nothing else");
    CHECK_INT(run(yes, &q, 10, &message, &why), 0);
    got = rs_test_slurp(env_file);
    CHECK_STR(got ? got : "", "PATH=/usr/bin:/bin:/usr/sbin:/sbin\n"
                              "RESTATE_PROXY_BYTES=33554432\n"
                              "RESTATE_PROXY_CLIENT=web01\n"
                              "RESTATE_PROXY_EVENT=upload\n"
                              "RESTATE_PROXY_LABEL=managed by sysmanage-agent: web01\n"
                              "RESTATE_PROXY_NAME=packs/P-1.tar.gz\n"
                              "RESTATE_PROXY_REPOSITORY=/srv/restate/web01\n");
    free(got);
    q.event = "open";
    q.name = NULL;
    q.label = NULL;
    q.bytes = 0;
    CHECK_INT(run(yes, &q, 10, &message, &why), 0);
    got = rs_test_slurp(env_file);
    CHECK_CONTAINS(got ? got : "", "RESTATE_PROXY_EVENT=open\n");
    CHECK_CONTAINS(got ? got : "", "RESTATE_PROXY_BYTES=0\n");
    CHECK(got && strstr(got, "RESTATE_PROXY_NAME") == NULL);
    CHECK(got && strstr(got, "RESTATE_PROXY_LABEL") == NULL);
    free(got);

    TEST_CASE("quota: no, with its first line, on one line and with no double quote");
    CHECK_INT(run(no, &q, 10, &message, &why), 507);
    CHECK_STR(message.data ? message.data : "", "web01 is over its '10 GiB'");
    CHECK_INT(run(silent, &q, 10, &message, &why), 507);
    CHECK_INT((long long)message.len, 0);
    /* What is not text is not said at all. */
    CHECK_INT(run(odd, &q, 10, &message, &why), 507);
    CHECK_INT((long long)message.len, 0);
    /* More than a pipe holds: read as it comes, the first of it kept. */
    CHECK_INT(run(loud, &q, 10, &message, &why), 507);
    CHECK_INT((long long)message.len, RS_QUOTA_SAID_MAX);

    TEST_CASE("quota: anything but 0 or 1, a signal, or too long, is the hook failing");
    CHECK_INT(run(three, &q, 10, &message, &why), 500);
    CHECK_CONTAINS(why.data, "it exited 3, not 0 (yes) or 1 (no)");
    CHECK_INT(run(dies, &q, 10, &message, &why), 500);
    CHECK_CONTAINS(why.data, "killed by signal 9");
    CHECK_INT(run(slow, &q, 1, &message, &why), 500);
    CHECK_CONTAINS(why.data, "longer than 1 seconds, and was killed");
    /* A program gone since the proxy started: posix_spawn says so itself,
     * or its process exits 127. */
    {
        int answer = run("/nonexistent/hook", &q, 10, &message, &why);

        CHECK(answer == -1 || answer == 500);
        CHECK(why.data &&
              (strstr(why.data, "/nonexistent/hook") || strstr(why.data, "exited 127")));
    }

    TEST_CASE("quota: a run no one waits for is killed and forgotten");
    {
        struct rs_quota_run r;
        int                 status = 0;

        rs_quota_init(&r);
        CHECK(!rs_quota_running(&r) && !rs_quota_done(&r));
        rs_quota_abandon(&r);
        CHECK(rs_quota_start(&r, slow, &q, (int64_t)time(NULL), 30, &why));
        CHECK(rs_quota_running(&r) && !rs_quota_done(&r));
        {
            pid_t pid = r.pid;

            rs_quota_check_time(&r, (int64_t)time(NULL));
            CHECK(!r.killed);
            rs_quota_abandon(&r);
            CHECK(!rs_quota_running(&r) && r.fd == -1);
            CHECK(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status));
        }
    }

    rs_buf_free(&message);
    rs_buf_free(&why);
    rs_test_rmtree(dir);
    free(yes);
    free(no);
    free(silent);
    free(odd);
    free(three);
    free(slow);
    free(dies);
    free(loud);
    free(flat);
    free(env_file);
    free(dir);
}
