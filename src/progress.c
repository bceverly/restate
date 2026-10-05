/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "progress.h"

#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "layout.h"

#define NS_PER_SEC ((uint64_t)1000000000)
/* How often it is drawn: a few times a second where it is redrawn in place,
 * every ten seconds where each line is kept. */
#define TTY_EVERY  (NS_PER_SEC / 4)
#define LOG_EVERY  (NS_PER_SEC * 10)
#define WIDTH      79
#define WIDTH_MAX  160

static bool                     on;
static FILE                    *out;       /* where progress is drawn */
static bool                     out_tty;
static bool                     out_set;   /* chosen by the tests */
static bool                     own_tty;   /* out is /dev/tty, not stderr */
static uint64_t                 (*clock_fn)(void);
static struct rs_progress_state st;
static uint64_t                 last_ns;
static bool                     drawn;     /* the two-line display is on screen */
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
    own_tty = false;
    clock_fn = now_fn;
}

/*
 * The terminal, if there is one, whatever standard error is: a capture whose
 * output is going to a log can still draw its progress for the person
 * watching. Without one -- cron, a service -- lines go to standard error.
 */
static void choose_output(void)
{
    int fd = open("/dev/tty", O_WRONLY | O_CLOEXEC | O_NOCTTY);

    if (fd >= 0 && isatty(fd) == 1)
    {
        out = fdopen(fd, "w");
        if (out)
        {
            out_tty = true;
            own_tty = isatty(STDERR_FILENO) != 1;
            return;
        }
    }
    if (fd >= 0)
    {
        (void)close(fd);
    }
    out = stderr;
    out_tty = isatty(STDERR_FILENO) == 1;
    own_tty = false;
}

void rs_progress_enable(bool enable)
{
    on = enable;
    if (on && !out)
    {
        choose_output();
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

    rs_human_size(s->bytes, done, sizeof(done));
    rs_human_size(rate, speed, sizeof(speed));
    if (s->total > 0)
    {
        uint64_t pct = s->bytes >= s->total ? 100 : s->bytes * 100 / s->total;
        uint64_t left = (rate > 0 && s->total > s->bytes) ? (s->total - s->bytes) / rate : 0;
        char     total[32];
        char     rest[160];
        size_t   used;
        size_t   bar;
        size_t   fill;
        size_t   i;
        int      n;

        rs_human_size(s->total, total, sizeof(total));
        clock_text(left, when, sizeof(when));
        (void)snprintf(rest, sizeof(rest), " %3llu%%  %s of %s  %s/s  %s left",
                       (unsigned long long)pct, done, total, speed, rate > 0 ? when : "-:--:--");
        /* The bar takes what the words leave, between 10 and 40 wide. */
        used = strlen(s->phase) + 3 + strlen(rest);
        bar = width > used + 10 ? width - used : 10;
        bar = bar > 40 ? 40 : bar;
        fill = (size_t)((uint64_t)bar * (pct > 100 ? 100 : pct) / 100);
        n = snprintf(outbuf, len, "%s [", s->phase);
        for (i = 0; i < bar && n > 0 && (size_t)n + 1 < len; i++)
        {
            outbuf[n++] = i < fill ? '#' : '.';
        }
        if (n > 0 && (size_t)n < len)
        {
            (void)snprintf(outbuf + n, len - (size_t)n, "]%s", rest);
        }
    } else if (strcmp(s->phase, "counting") == 0)
    {
        clock_text(elapsed / NS_PER_SEC, when, sizeof(when));
        (void)snprintf(outbuf, len, "%s  %llu paths  %s to read  %s", s->phase,
                       (unsigned long long)s->paths, done, when);
    } else
    {
        clock_text(elapsed / NS_PER_SEC, when, sizeof(when));
        (void)snprintf(outbuf, len, "%s  %llu paths  %s  %s/s  %s", s->phase,
                       (unsigned long long)s->paths, done, speed, when);
    }
    if (width > 0 && strlen(outbuf) > width)
    {
        outbuf[width] = '\0';
    }
}

/* The path, cut from the left to fit: its end says where the walk has got to. */
static void path_line(const char *path, size_t width, char *outbuf, size_t len)
{
    size_t plen = path ? strlen(path) : 0;
    size_t room = width > 4 ? width - 2 : 2;

    if (plen == 0)
    {
        outbuf[0] = '\0';
    } else if (plen <= room)
    {
        (void)snprintf(outbuf, len, "  %s", path);
    } else
    {
        (void)snprintf(outbuf, len, "  ...%s", path + plen - (room - 3));
    }
}

static size_t terminal_width(void)
{
#ifdef TIOCGWINSZ
    struct winsize ws;

    if (out && out_tty && ioctl(fileno(out), TIOCGWINSZ, &ws) == 0 && ws.ws_col > 20)
    {
        return ws.ws_col - 1 > WIDTH_MAX ? WIDTH_MAX : (size_t)ws.ws_col - 1;
    }
#endif
    return WIDTH;
}

static void emit(bool final)
{
    char   line[WIDTH_MAX + 64];
    char   path[WIDTH_MAX + 64];
    size_t width = terminal_width();

    rs_progress_format(&st, now(), width, line, sizeof(line));
    if (out_tty)
    {
        /* Two lines, redrawn in place: the bar, and the path under it. */
        if (drawn)
        {
            (void)fputs("\r\033[2K\033[1A\r\033[2K", out);
        }
        if (final)
        {
            (void)fprintf(out, "restate: %s\n", line);
            drawn = false;
        } else
        {
            path_line(st.current, width, path, sizeof(path));
            (void)fprintf(out, "restate: %s\n%s", line, path);
            drawn = true;
        }
        (void)fflush(out);
        /* The terminal is not the log: the phase's last word goes there too. */
        if (final && own_tty)
        {
            rs_progress_format(&st, now(), WIDTH, line, sizeof(line));
            (void)fprintf(stderr, "restate: %s\n", line);
            (void)fflush(stderr);
        }
        return;
    }
    path_line(st.current, WIDTH - strlen(line) > 12 ? WIDTH - strlen(line) : 12, path, sizeof(path));
    (void)fprintf(out, "restate: %s%s\n", line, final ? "" : path);
    (void)fflush(out);
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
    drawn = false;
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

/* Counting has no bytes of its own to report as read: it reports what it
 * has found to read, in place of them. */
void rs_progress_found(uint64_t n)
{
    if (on && active)
    {
        st.bytes += n;
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
