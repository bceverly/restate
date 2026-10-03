/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "rules.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "glob.h"

/* A rules file larger than this is a mistake -- the wrong file named on the
 * command line -- and reading it whole would only delay saying so. */
#define RULES_FILE_MAX ((size_t)1024 * 1024)

struct builtin {
    enum rs_class cls;
    const char   *pattern;
    const char   *why;
};

#define E RS_CLASS_EPHEMERAL
#define X RS_CLASS_EXPENDABLE
#define B RS_CLASS_BASELINE
#define S RS_CLASS_STATE

/*
 * The built-in rules.
 *
 * Ordered from general to specific, because the last match wins: "/usr" is
 * baseline, and then "/usr/local" carves itself back out as state. The rules
 * that apply at any depth ("*.pid") come last so nothing can override them by
 * accident.
 *
 * These are a starting point and say so. `restate rules` prints them in the
 * rules-file format, so a site that disagrees can take the output, edit it,
 * and run with `-N -R FILE`.
 */

/* Shared by every Unix-like system. */
static const struct builtin common_rules[] = {
    { E, "/dev",            "device nodes, recreated by the kernel at boot" },
    { E, "/tmp",            "cleared at boot on most systems; never state" },
    { E, "/var/tmp",        "temporary files by definition" },
    { E, "/var/run",        "PID files and sockets from the running system" },
    { E, "/lost+found",     "fsck's salvage area, specific to one filesystem" },
    { S, "/etc",            "system configuration" },
    { S, "/root",           "the administrator's home directory" },
    { S, "/home",           "user data" },
    { S, "/var/db",         "local databases" },
    { S, "/var/spool",      "queued mail, print and cron jobs" },
    { S, "/var/mail",       "local mailboxes" },
    { X, "/var/log",        "useful, but not needed to rebuild the machine" },
    { X, "/var/cache",      "regenerated on demand" },
};

static const struct builtin linux_rules[] = {
    { E, "/proc",                  "kernel pseudo-filesystem" },
    { E, "/sys",                   "kernel pseudo-filesystem" },
    { E, "/run",                   "runtime state, a tmpfs on every modern distribution" },
    { E, "/var/lock",              "lock files from the running system" },
    { E, "/mnt",                   "mount points for other filesystems" },
    { E, "/media",                 "removable media" },
    { E, "/swapfile",              "swap" },
    { E, "/swap.img",              "swap, as the Ubuntu installer names it" },
    { B, "/usr",                   "installed by the distribution and its packages" },
    { B, "/bin",                   "installed by the distribution (often a link into /usr)" },
    { B, "/sbin",                  "installed by the distribution (often a link into /usr)" },
    { B, "/lib",                   "installed by the distribution (often a link into /usr)" },
    { B, "/lib32",                 "installed by the distribution" },
    { B, "/lib64",                 "installed by the distribution" },
    { B, "/libx32",                "installed by the distribution" },
    { B, "/boot",                  "kernels and initramfs images, rebuilt by the package manager" },
    { S, "/usr/local",             "software the administrator installed by hand" },
    { S, "/opt",                   "add-on software and its data" },
    { S, "/srv",                   "data served by this machine" },
    { S, "/var/lib",               "application state: databases, containers, services" },
    { S, "/var/backups",           "the distribution's own copies of critical files" },
    { B, "/var/lib/dpkg",          "the package database, rebuilt by reinstalling packages" },
    { B, "/var/lib/rpm",           "the package database, rebuilt by reinstalling packages" },
    { B, "/var/lib/pacman",        "the package database, rebuilt by reinstalling packages" },
    { X, "/var/lib/apt/lists",     "package indexes, refetched by apt update" },
    { X, "/var/lib/snapd/snaps",   "snap images, refetched from the store" },
    { X, "/var/lib/snapd/cache",   "snapd's download cache" },
    { X, "/snap",                  "mounted snap images, recreated by snapd" },
    { X, "/var/lib/flatpak/repo",  "flatpak's object store, refetched on install" },
    { X, "/var/crash",             "crash dumps" },
    { E, "/var/lib/systemd/coredump", "core dumps" },
};

static const struct builtin freebsd_rules[] = {
    { E, "/proc",                  "process pseudo-filesystem, when mounted" },
    { E, "/compat/linux/proc",     "the Linux emulation layer's /proc" },
    { E, "/compat/linux/sys",      "the Linux emulation layer's /sys" },
    { E, "/mnt",                   "mount points for other filesystems" },
    { E, "/media",                 "removable media" },
    { B, "/bin",                   "the base system" },
    { B, "/sbin",                  "the base system" },
    { B, "/lib",                   "the base system" },
    { B, "/libexec",               "the base system" },
    { B, "/rescue",                "the base system's static recovery tools" },
    { B, "/usr",                   "the base system" },
    { B, "/boot",                  "the kernel and loader, from the base system" },
    { B, "/usr/local",             "installed by pkg, reconstructible from its database" },
    { B, "/var/db/pkg",            "the package database" },
    { S, "/usr/local/etc",         "configuration for installed packages" },
    { S, "/usr/local/www",         "web content, conventionally local" },
    { S, "/usr/home",              "user data, where older installs put /home" },
    { S, "/boot/loader.conf",      "boot-time tunables" },
    { S, "/boot/loader.conf.d",    "boot-time tunables" },
    { X, "/usr/obj",               "build output from a source build" },
    { X, "/var/cache/pkg",         "downloaded packages" },
    { X, "/var/db/freebsd-update", "freebsd-update's working files" },
    { X, "/var/db/portsnap",       "the ports tree snapshot" },
};

static const struct builtin openbsd_rules[] = {
    { E, "/mnt",                   "mount points for other filesystems" },
    { B, "/bin",                   "the base sets" },
    { B, "/sbin",                  "the base sets" },
    { B, "/usr",                   "the base sets" },
    { B, "/bsd",                   "the kernel" },
    { B, "/bsd.rd",                "the install kernel" },
    { B, "/bsd.sp",                "the single-processor kernel" },
    { B, "/bsd.mp",                "the multiprocessor kernel" },
    { B, "/bsd.booted",            "the kernel relinked at boot" },
    { B, "/usr/local",             "installed by pkg_add, reconstructible from its database" },
    { B, "/var/db/pkg",            "the package database" },
    { S, "/usr/local/etc",         "configuration some packages keep here" },
    { S, "/var/www",               "httpd's chroot and its content" },
    { S, "/var/unbound",           "unbound's chroot and configuration" },
    { S, "/var/nsd",               "nsd's chroot and zones" },
    { X, "/usr/obj",               "build output from a source build" },
    { X, "/usr/xobj",              "build output from a xenocara build" },
    { E, "/var/sysmerge",          "sysmerge's working area" },
};

static const struct builtin netbsd_rules[] = {
    { E, "/proc",                  "process pseudo-filesystem, when mounted" },
    { E, "/kern",                  "kernel pseudo-filesystem" },
    { E, "/mnt",                   "mount points for other filesystems" },
    { B, "/bin",                   "the base sets" },
    { B, "/sbin",                  "the base sets" },
    { B, "/lib",                   "the base sets" },
    { B, "/libexec",               "the base sets" },
    { B, "/rescue",                "the base sets' static recovery tools" },
    { B, "/usr",                   "the base sets" },
    { B, "/netbsd",                "the kernel" },
    { B, "/stand",                 "kernel modules" },
    { B, "/usr/pkg",               "installed by pkgsrc, reconstructible from its database" },
    { B, "/usr/pkg/pkgdb",         "the pkgsrc package database" },
    { B, "/var/db/pkg",            "the package database on older installs" },
    { S, "/usr/pkg/etc",           "configuration for installed packages" },
    { S, "/usr/local",             "software the administrator installed by hand" },
    { X, "/usr/obj",               "build output from a source build" },
    { X, "/var/db/pkgin",          "pkgin's cache" },
};

static const struct builtin darwin_rules[] = {
    { E, "/Volumes",               "mount points for other volumes" },
    { E, "/System/Volumes",        "the data volume, reachable again through firmlinks" },
    { E, "/private/tmp",           "temporary files" },
    { E, "/private/var/tmp",       "temporary files" },
    { E, "/private/var/run",       "runtime state" },
    { E, "/private/var/folders",   "per-user temporary and cache directories" },
    { E, "/private/var/vm",        "swap and the sleep image" },
    { E, "/cores",                 "core dumps" },
    { E, "/.Spotlight-V100",       "the Spotlight index" },
    { E, "/.fseventsd",            "the filesystem event log" },
    { E, "/.DocumentRevisions-V100", "document versions database" },
    { E, "/.vol",                  "volume-by-id pseudo-filesystem" },
    { B, "/System",                "the sealed system volume" },
    { B, "/bin",                   "the sealed system volume" },
    { B, "/sbin",                  "the sealed system volume" },
    { B, "/usr",                   "the sealed system volume" },
    { B, "/Library/Apple",         "Apple-supplied system additions" },
    { S, "/usr/local",             "software the administrator installed (Homebrew on Intel)" },
    { S, "/opt",                   "add-on software (Homebrew on Apple silicon)" },
    { S, "/Users",                 "user data" },
    { S, "/Library",               "system-wide preferences and support files" },
    { S, "/Applications",          "installed applications" },
    { S, "/private/etc",           "system configuration" },
    { S, "/private/var/db",        "local databases" },
    { S, "/private/var/root",      "the administrator's home directory" },
    { X, "/Library/Caches",        "regenerated on demand" },
    { X, "/private/var/log",       "useful, but not needed to rebuild the machine" },
    { X, "/opt/homebrew/Library/Homebrew", "Homebrew's own checkout, refetched on install" },
};

/* At any depth, and therefore last. */
static const struct builtin anywhere_rules[] = {
    { E, "*.pid",                  "a process ID, meaningless after a reboot" },
    { E, "*.sock",                 "a socket's name, recreated by its server" },
    { E, ".nfs*",                 "NFS silly-rename placeholders" },
    { X, ".cache",                 "per-user caches (XDG)" },
};

#undef E
#undef X
#undef B
#undef S

struct os_table {
    const char           *name;
    const struct builtin *rules;
    size_t                count;
};

#define TABLE(n, t) { n, t, sizeof(t) / sizeof((t)[0]) }

static const struct os_table os_tables[] = {
    TABLE("linux",   linux_rules),
    TABLE("freebsd", freebsd_rules),
    TABLE("openbsd", openbsd_rules),
    TABLE("netbsd",  netbsd_rules),
    TABLE("darwin",  darwin_rules),
};

#undef TABLE

static const char *const class_names[] = {
    "ephemeral", "expendable", "baseline", "state"
};

const char *rs_class_name(enum rs_class cls)
{
    if ((size_t)cls < sizeof(class_names) / sizeof(class_names[0]))
    {
        return class_names[cls];
    }
    return "?";
}

bool rs_class_parse(const char *name, size_t len, enum rs_class *out)
{
    size_t i;

    for (i = 0; i < sizeof(class_names) / sizeof(class_names[0]); i++)
    {
        if (strlen(class_names[i]) == len && strncmp(class_names[i], name, len) == 0)
        {
            *out = (enum rs_class)i;
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------------- */

void rs_rules_init(struct rs_rules *rs)
{
    rs->rules = NULL;
    rs->count = 0;
    rs->cap = 0;
}

void rs_rules_free(struct rs_rules *rs)
{
    size_t i;

    for (i = 0; i < rs->count; i++)
    {
        free(rs->rules[i].pattern);
        free(rs->rules[i].source);
        free(rs->rules[i].why);
    }
    free(rs->rules);
    rs_rules_init(rs);
}

void rs_rules_add(struct rs_rules *rs, enum rs_class cls, const char *pattern,
                  const char *source, const char *why)
{
    struct rs_rule *r;
    size_t          plen = strlen(pattern);

    if (rs->count == rs->cap)
    {
        rs->cap = rs->cap ? rs->cap * 2 : 64;
        rs->rules = rs_xreallocarray(rs->rules, rs->cap, sizeof(*rs->rules));
    }
    r = &rs->rules[rs->count++];
    r->cls = cls;
    /* "/var/log/" means the same as "/var/log"; the trailing slash would
     * otherwise stop the pattern from matching the directory at all. */
    while (plen > 1 && pattern[plen - 1] == '/')
    {
        plen--;
    }
    r->pattern = rs_xstrndup(pattern, plen);
    r->source = rs_xstrdup(source);
    r->why = why ? rs_xstrdup(why) : NULL;
}

const char *rs_rules_host_os(void)
{
    struct utsname u;
    size_t         i;
    static char    lower[sizeof(u.sysname)];

    if (uname(&u) < 0)
    {
        return NULL;
    }
    for (i = 0; i + 1 < sizeof(lower) && u.sysname[i] != '\0'; i++)
    {
        static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
        char              c = u.sysname[i];

        if (c >= 'A' && c <= 'Z')
        {
            lower[i] = alphabet[c - 'A'];
        } else
        {
            lower[i] = c;
        }
    }
    lower[i] = '\0';
    return rs_rules_known_os(lower) ? lower : NULL;
}

bool rs_rules_known_os(const char *os)
{
    size_t i;

    for (i = 0; i < sizeof(os_tables) / sizeof(os_tables[0]); i++)
    {
        if (strcmp(os_tables[i].name, os) == 0)
        {
            return true;
        }
    }
    return false;
}

static void add_table(struct rs_rules *rs, const struct builtin *t, size_t n,
                      const char *source)
{
    size_t i;

    for (i = 0; i < n; i++)
    {
        rs_rules_add(rs, t[i].cls, t[i].pattern, source, t[i].why);
    }
}

bool rs_rules_add_builtin(struct rs_rules *rs, const char *os)
{
    size_t i;

    for (i = 0; i < sizeof(os_tables) / sizeof(os_tables[0]); i++)
    {
        if (strcmp(os_tables[i].name, os) == 0)
        {
            char *source = rs_xasprintf("built-in (%s)", os);

            add_table(rs, common_rules, sizeof(common_rules) / sizeof(common_rules[0]),
                      source);
            add_table(rs, os_tables[i].rules, os_tables[i].count, source);
            add_table(rs, anywhere_rules,
                      sizeof(anywhere_rules) / sizeof(anywhere_rules[0]), source);
            free(source);
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------------- */

static bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

bool rs_rules_parse(struct rs_rules *rs, const char *text, size_t len,
                    const char *name, struct rs_buf *err)
{
    size_t pos = 0;
    size_t lineno = 0;

    while (pos < len)
    {
        size_t        start = pos;
        size_t        end;
        size_t        word_end;
        size_t        pat_start;
        enum rs_class cls;

        lineno++;
        while (pos < len && text[pos] != '\n')
        {
            if (text[pos] == '\0')
            {
                rs_buf_addf(err, "%s:%zu: a NUL byte; this is not a rules file",
                            name, lineno);
                return false;
            }
            pos++;
        }
        end = pos;
        if (pos < len)
        {
            pos++;   /* the newline */
        }

        while (start < end && is_space(text[start]))
        {
            start++;
        }
        while (end > start && is_space(text[end - 1]))
        {
            end--;
        }
        if (start == end || text[start] == '#')
        {
            continue;
        }

        word_end = start;
        while (word_end < end && !is_space(text[word_end]))
        {
            word_end++;
        }
        if (!rs_class_parse(text + start, word_end - start, &cls))
        {
            rs_buf_addf(err, "%s:%zu: unknown class \"%.*s\" (expected ephemeral, "
                        "expendable, baseline or state)", name, lineno,
                        (int)(word_end - start > 40 ? 40 : word_end - start),
                        text + start);
            return false;
        }
        pat_start = word_end;
        while (pat_start < end && is_space(text[pat_start]))
        {
            pat_start++;
        }
        /* A '#' after whitespace starts a comment, so `restate rules` output
         * -- which explains each rule that way -- reads straight back in. A
         * '#' inside a pattern is still literal. */
        {
            size_t k;

            for (k = pat_start; k < end; k++)
            {
                if (text[k] == '#' && is_space(text[k - 1]))
                {
                    end = k;
                    break;
                }
            }
            while (end > pat_start && is_space(text[end - 1]))
            {
                end--;
            }
        }
        if (pat_start == end)
        {
            rs_buf_addf(err, "%s:%zu: \"%s\" needs a pattern after it", name,
                        lineno, rs_class_name(cls));
            return false;
        }
        {
            char *pattern = rs_xstrndup(text + pat_start, end - pat_start);
            char *source = rs_xasprintf("%s:%zu", name, lineno);

            rs_rules_add(rs, cls, pattern, source, NULL);
            free(pattern);
            free(source);
        }
    }
    return true;
}

bool rs_rules_load_file(struct rs_rules *rs, const char *path, struct rs_buf *err)
{
    struct rs_buf text;
    struct stat   st;
    char          chunk[8192];
    int           fd;
    bool          ok;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        rs_buf_addf(err, "%s: %s", path, strerror(errno));
        return false;
    }
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
    {
        rs_buf_addf(err, "%s: not a regular file", path);
        (void)close(fd);
        return false;
    }
    rs_buf_init(&text);
    for (;;)
    {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            rs_buf_addf(err, "%s: %s", path, strerror(errno));
            rs_buf_free(&text);
            (void)close(fd);
            return false;
        }
        if (n == 0)
        {
            break;
        }
        rs_buf_add(&text, chunk, (size_t)n);
        if (text.len > RULES_FILE_MAX)
        {
            rs_buf_addf(err, "%s: larger than %zu bytes; is this really a rules file?",
                        path, RULES_FILE_MAX);
            rs_buf_free(&text);
            (void)close(fd);
            return false;
        }
    }
    (void)close(fd);
    if (!text.data)
    {
        rs_buf_add(&text, "", 0);
    }
    ok = rs_rules_parse(rs, text.data, text.len, path, err);
    rs_buf_free(&text);
    return ok;
}

enum rs_class rs_rules_classify(const struct rs_rules *rs, const char *path,
                                long *which)
{
    size_t i = rs->count;

    /* Backwards, because the last match wins and can stop the search. */
    while (i > 0)
    {
        i--;
        if (rs_glob_covers(rs->rules[i].pattern, path))
        {
            if (which)
            {
                *which = (long)i;
            }
            return rs->rules[i].cls;
        }
    }
    if (which)
    {
        *which = -1;
    }
    return RS_CLASS_STATE;
}

/* The part of a source that names the file: "rules.conf:12" -> "rules.conf". */
static size_t source_group_len(const char *source)
{
    const char *colon = strrchr(source, ':');
    const char *p;

    if (!colon || colon[1] == '\0')
    {
        return strlen(source);
    }
    for (p = colon + 1; *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
        {
            return strlen(source);
        }
    }
    return (size_t)(colon - source);
}

void rs_rules_write(const struct rs_rules *rs, FILE *out)
{
    size_t      i;
    const char *group = NULL;
    size_t      group_len = 0;

    (void)fprintf(out, "# restate rules: CLASS PATTERN, the last match wins.\n"
                       "# A path that no rule covers is state.\n");
    for (i = 0; i < rs->count; i++)
    {
        const struct rs_rule *r = &rs->rules[i];
        size_t                n = source_group_len(r->source);

        if (!group || n != group_len || strncmp(group, r->source, n) != 0)
        {
            (void)fprintf(out, "\n# from %.*s\n", (int)n, r->source);
            group = r->source;
            group_len = n;
        }
        if (r->why)
        {
            (void)fprintf(out, "%-10s  %-28s  # %s\n", rs_class_name(r->cls),
                          r->pattern, r->why);
        } else
        {
            (void)fprintf(out, "%-10s  %s\n", rs_class_name(r->cls), r->pattern);
        }
    }
}
