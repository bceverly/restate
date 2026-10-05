/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "progress.h"

#include <string.h>
#include <time.h>
#include <unistd.h>

#include "layout.h"

#define NS_PER_SEC ((uint64_t)1000000000)
/* How often a line is written: a few times a second where it is rewritten in
 * place, every ten seconds where each one is kept. */
#define TTY_EVERY  (NS_PER_SEC / 4)
#define LOG_EVERY  (NS_PER_SEC * 10)
#define WIDTH      79

static bool                     on;
static FILE                    *out;
static bool                     out_tty;
static bool                     out_set;
static uint64_t                 (*clock_fn)(void);
static struct rs_progress_state st;
static uint64_t                 last_ns;
static size_t                   last_len;
static bool                     active;
static char                     current[1024];

static uint64_t real_clock(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0;
    }
    return (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

static uint64_t now(void)
{
    return clock_fn ? clock_fn() : real_clock();
}

void rs_progress_set_output(FILE *fp, bool tty, uint64_t (*now_fn)(void))
{
    out = fp;
    out_tty = tty;
    out_set = fp != NULL;
    clock_fn = now_fn;
}

void rs_progress_enable(bool enable)
{
    on = enable;
    if (on && !out_set)
    {
        out = stderr;
        out_tty = isatty(STDERR_FILENO) == 1;
    }
}

bool rs_progress_enabled(void)
{
    return on;
}

/* "0:11:40": hours, minutes, seconds. */
static void clock_text(uint64_t seconds, char *buf, size_t len)
{
    (void)snprintf(buf, len, "%llu:%02llu:%02llu", (unsigned long long)(seconds / 3600),
                   (unsigned long long)(seconds / 60 % 60), (unsigned long long)(seconds % 60));
}

void rs_progress_format(const struct rs_progress_state *s, uint64_t now_ns, size_t width,
                        char *outbuf, size_t len)
{
    uint64_t elapsed = now_ns > s->start_ns ? now_ns - s->start_ns : 0;
    uint64_t rate = elapsed >= NS_PER_SEC / 10
                        ? (uint64_t)((double)s->bytes / ((double)elapsed / (double)NS_PER_SEC))
                        : 0;
    char     done[32];
    char     speed[32];
    char     when[32];
    int      n;

    rs_human_size(s->bytes, done, sizeof(done));
    rs_human_size(rate, speed, sizeof(speed));
    if (s->total > 0)
    {
        uint64_t pct = s->bytes >= s->total ? 100 : s->bytes * 100 / s->total;
        uint64_t left = (rate > 0 && s->total > s->bytes) ? (s->total - s->bytes) / rate : 0;
        char     total[32];

        rs_human_size(s->total, total, sizeof(total));
        clock_text(left, when, sizeof(when));
        n = snprintf(outbuf, len, "%-8s %3llu%%  %s of %s  %s/s  %s left", s->phase,
                     (unsigned long long)pct, done, total, speed, rate > 0 ? when : "-:--:--");
    } else
    {
        clock_text(elapsed / NS_PER_SEC, when, sizeof(when));
        n = snprintf(outbuf, len, "%-8s %llu paths  %s  %s/s  %s", s->phase,
                     (unsigned long long)s->paths, done, speed, when);
    }
    /* The path being read, if there is room: its end, which is the part that
     * says where in the tree the walk has got to. */
    if (n > 0 && (size_t)n + 4 < width && (size_t)n + 4 < len && s->current && s->current[0])
    {
        size_t room = width - (size_t)n - 2;
        size_t plen = strlen(s->current);

        if (plen <= room)
        {
            (void)snprintf(outbuf + n, len - (size_t)n, "  %s", s->current);
        } else if (room > 3)
        {
            (void)snprintf(outbuf + n, len - (size_t)n, "  ...%s", s->current + plen - (room - 3));
        }
    }
    if (width > 0 && strlen(outbuf) > width)
    {
        outbuf[width] = '\0';
    }
}

static void emit(bool final)
{
    char   line[256];
    size_t len;

    rs_progress_format(&st, now(), WIDTH, line, sizeof(line));
    len = strlen(line);
    if (out_tty)
    {
        /* Over the last one, blanking whatever of it the new one is short of. */
        (void)fprintf(out, "\rrestate: %s%*s", line, last_len > len ? (int)(last_len - len) : 0, "");
        if (final)
        {
            (void)fputc('\n', out);
        }
    } else
    {
        (void)fprintf(out, "restate: %s\n", line);
    }
    (void)fflush(out);
    last_len = len;
}

static void tick(void)
{
    uint64_t t;

    if (!on || !active)
    {
        return;
    }
    t = now();
    if (t - last_ns >= (out_tty ? TTY_EVERY : LOG_EVERY))
    {
        last_ns = t;
        emit(false);
    }
}

void rs_progress_phase(const char *phase, uint64_t total)
{
    if (!on)
    {
        return;
    }
    if (active)
    {
        rs_progress_done();
    }
    memset(&st, 0, sizeof(st));
    st.phase = phase;
    st.total = total;
    st.start_ns = now();
    current[0] = '\0';
    st.current = current;
    last_ns = st.start_ns;
    last_len = 0;
    active = true;
}

void rs_progress_bytes(uint64_t n)
{
    if (on && active)
    {
        st.bytes += n;
        tick();
    }
}

void rs_progress_path(const char *path)
{
    if (on && active)
    {
        st.paths++;
        (void)snprintf(current, sizeof(current), "%s", path ? path : "");
        tick();
    }
}

void rs_progress_done(void)
{
    if (!on || !active)
    {
        return;
    }
    current[0] = '\0';
    emit(true);
    active = false;
}
