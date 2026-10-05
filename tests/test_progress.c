/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <stdlib.h>

#include "progress.h"
#include "test.h"
#include "util.h"

#define SEC ((uint64_t)1000000000)

static uint64_t fake_now;

static uint64_t fake_clock(void)
{
    return fake_now;
}

/* Everything written to `fp` so far. */
static char *contents(FILE *fp)
{
    long  len;
    char *s;

    (void)fflush(fp);
    len = ftell(fp);
    s = rs_xcalloc((size_t)(len > 0 ? len : 0) + 1, 1);
    rewind(fp);
    if (len > 0 && fread(s, 1, (size_t)len, fp) != (size_t)len)
    {
        s[0] = '\0';
    }
    (void)fseek(fp, 0, SEEK_END);
    return s;
}

void test_progress(void)
{
    struct rs_progress_state s;
    char                     line[256];
    FILE                    *fp;
    char                    *text;

    TEST_CASE("progress: a walk, with no total");
    memset(&s, 0, sizeof(s));
    s.phase = "walking";
    s.paths = 812345;
    s.bytes = (uint64_t)143 * 1024 * 1024 * 1024;
    s.start_ns = 0;
    s.current = "/home/alice/dev/project/src/main.c";
    rs_progress_format(&s, 700 * SEC, 79, line, sizeof(line));
    CHECK_CONTAINS(line, "walking  812345 paths  143 GiB  209 MiB/s  0:11:40  ...e/dev/project/src/main.c");
    s.current = "/etc/hosts";
    rs_progress_format(&s, 700 * SEC, 79, line, sizeof(line));
    CHECK_CONTAINS(line, "0:11:40  /etc/hosts");
    s.current = "/home/alice/a/very/long/path/that/will/not/fit/in/what/is/left/of/the/line.txt";
    rs_progress_format(&s, 700 * SEC, 79, line, sizeof(line));
    CHECK_CONTAINS(line, "  ...");
    CHECK_CONTAINS(line, "line.txt");
    CHECK(strlen(line) <= 79);
    s.current = NULL;
    rs_progress_format(&s, 0, 79, line, sizeof(line));
    CHECK_CONTAINS(line, "0 bytes/s  0:00:00");

    TEST_CASE("progress: writing, with a total");
    memset(&s, 0, sizeof(s));
    s.phase = "writing";
    s.total = 1000 * 1024 * 1024;
    s.bytes = 250 * 1024 * 1024;
    rs_progress_format(&s, 10 * SEC, 79, line, sizeof(line));
    CHECK_CONTAINS(line, " 25%  250 MiB of 1000 MiB  25 MiB/s  0:00:30 left");
    rs_progress_format(&s, 0, 79, line, sizeof(line));
    CHECK_CONTAINS(line, "-:--:-- left");
    s.bytes = s.total + 5;
    rs_progress_format(&s, 10 * SEC, 79, line, sizeof(line));
    CHECK_CONTAINS(line, "100%");
    rs_progress_format(&s, 10 * SEC, 8, line, sizeof(line));
    CHECK_INT(strlen(line), 8);

    TEST_CASE("progress: off, nothing is written");
    fp = tmpfile();
    CHECK(fp != NULL);
    if (!fp)
    {
        return;
    }
    rs_progress_set_output(fp, false, fake_clock);
    rs_progress_enable(false);
    CHECK(!rs_progress_enabled());
    rs_progress_phase("walking", 0);
    rs_progress_path("/x");
    rs_progress_bytes(5);
    rs_progress_done();
    text = contents(fp);
    CHECK_STR(text, "");
    free(text);

    TEST_CASE("progress: into a log, a line every ten seconds");
    rs_progress_enable(true);
    CHECK(rs_progress_enabled());
    fake_now = 0;
    rs_progress_phase("walking", 0);
    fake_now = 5 * SEC;
    rs_progress_path("/a");
    rs_progress_bytes(1024);
    text = contents(fp);
    CHECK_STR(text, "");
    free(text);
    fake_now = 11 * SEC;
    rs_progress_path("/b");
    text = contents(fp);
    CHECK_CONTAINS(text, "restate: walking  2 paths  1 KiB");
    CHECK_CONTAINS(text, "  /b\n");
    free(text);
    /* A new phase finishes the one before it. */
    rs_progress_phase("writing", 2048);
    rs_progress_bytes(2048);
    rs_progress_done();
    rs_progress_done();
    text = contents(fp);
    CHECK_CONTAINS(text, "restate: writing  100%");
    free(text);
    (void)fclose(fp);

    TEST_CASE("progress: on a terminal, rewritten in place");
    fp = tmpfile();
    CHECK(fp != NULL);
    if (!fp)
    {
        return;
    }
    rs_progress_set_output(fp, true, fake_clock);
    fake_now = 0;
    rs_progress_phase("walking", 0);
    fake_now = SEC;
    rs_progress_path("/a/rather/long/path/name");
    fake_now = 2 * SEC;
    rs_progress_path("/b");
    rs_progress_done();
    text = contents(fp);
    CHECK(text[0] == '\r');
    CHECK_CONTAINS(text, "\rrestate: walking  2 paths");
    CHECK(text[strlen(text) - 1] == '\n');
    free(text);
    (void)fclose(fp);

    rs_progress_enable(false);
    rs_progress_set_output(NULL, false, NULL);
    rs_progress_enable(true);
    rs_progress_enable(false);
}
