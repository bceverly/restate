/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The classification rules: what a path IS, as far as reconstruction goes.
 *
 * Every path on the machine falls into one of four classes:
 *
 *   ephemeral    runtime state with no meaning after a reboot: /proc, /run,
 *                /tmp, PID files. Never recorded, never descended into.
 *   expendable   could be kept, but a rebuilt machine does not need it:
 *                caches, package downloads, snap images, logs. Not recorded
 *                by default; --all records it.
 *   baseline     supplied by the operating system or its packages: /usr, the
 *                package database. Recorded with digests, so a later
 *                comparison against the package manager can drop everything
 *                that is still exactly what the vendor shipped.
 *   state        what makes this machine this machine: /etc, /home, /root,
 *                /var/lib, /usr/local. Always recorded.
 *
 * Rules are "CLASS PATTERN" pairs, and the LAST rule that covers a path wins,
 * as in .gitignore -- so a site rules file appended after the built-ins can
 * override any of them. A path no rule covers is state: when in doubt, keep it.
 * A file nobody meant to back up costs some space; a file nobody meant to lose
 * costs the restore.
 *
 * One consequence worth knowing: an ephemeral or expendable directory is not
 * descended into, so no later rule can rescue something beneath it. Classify
 * the directory as state and its unwanted children as expendable instead.
 */
#ifndef RESTATE_RULES_H
#define RESTATE_RULES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "util.h"

enum rs_class {
    RS_CLASS_EPHEMERAL = 0,
    RS_CLASS_EXPENDABLE,
    RS_CLASS_BASELINE,
    RS_CLASS_STATE
};

struct rs_rule {
    enum rs_class cls;
    char         *pattern;
    char         *source;   /* "built-in (linux)", or "FILE:LINE" */
    char         *why;      /* an explanation, or NULL */
};

struct rs_rules {
    struct rs_rule *rules;
    size_t          count;
    size_t          cap;
};

void rs_rules_init(struct rs_rules *rs);
void rs_rules_free(struct rs_rules *rs);

void rs_rules_add(struct rs_rules *rs, enum rs_class cls, const char *pattern,
                  const char *source, const char *why);

/*
 * The operating systems with built-in rules: "linux", "freebsd", "openbsd",
 * "netbsd" and "darwin". rs_rules_host_os() names the one this is running on,
 * or NULL if it is none of them.
 */
const char *rs_rules_host_os(void);
bool        rs_rules_known_os(const char *os);
/* Appends the built-in rules for `os`. false if there are none. */
bool        rs_rules_add_builtin(struct rs_rules *rs, const char *os);

/*
 * Parses rules from memory. `name` is what diagnostics call the input. On
 * failure returns false, leaves the rules already added in place, and puts a
 * one-line explanation in `err`.
 */
bool rs_rules_parse(struct rs_rules *rs, const char *text, size_t len,
                    const char *name, struct rs_buf *err);
bool rs_rules_load_file(struct rs_rules *rs, const char *path, struct rs_buf *err);

/*
 * The class of `path` (an absolute path in the scanned tree's namespace),
 * and, through `which`, the index of the rule that decided it or -1 for the
 * default.
 */
enum rs_class rs_rules_classify(const struct rs_rules *rs, const char *path,
                                long *which);

/* Writes the rules as a rules file, which `restate -N -R FILE` reads back. */
void rs_rules_write(const struct rs_rules *rs, FILE *out);

const char *rs_class_name(enum rs_class cls);
bool        rs_class_parse(const char *name, size_t len, enum rs_class *out);

#endif /* RESTATE_RULES_H */
