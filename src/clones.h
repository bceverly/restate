/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The copies of a machine to install, as autoinstall --clones reads them.
 *
 * A CSV file: a header naming the columns, then one copy per line. Blank
 * lines and lines starting with '#' are skipped.
 *
 *   name,mac,serial,address,gateway,dns
 *   web1,52:54:00:12:34:01,,10.0.0.11/24,10.0.0.1,10.0.0.2 10.0.0.3
 *   web2,,S4EWNX0R123456,,,
 *
 *   name     the copy's host name (required)
 *   mac      a MAC address of the machine to install it on, as the
 *            installer sees it; its network is matched on it too
 *   serial   or a disk serial, as lsblk shows it: one of the two is needed
 *   address  a static address with its prefix length, IPv4 or IPv6; empty
 *            for DHCP
 *   gateway  the default route, for a static address
 *   dns      name servers, separated by spaces or semicolons
 *
 * Only `name` and one of `mac` and `serial` must be columns; the others can
 * be left out. Nothing in the file can need quoting -- every value is a name,
 * a number or an address -- so a quote is refused rather than read. Each
 * name, MAC address, serial and address appears once.
 */
#ifndef RESTATE_CLONES_H
#define RESTATE_CLONES_H

#include <stdbool.h>
#include <stddef.h>

#include "util.h"

struct rs_clone {
    char  *name;
    char  *mac;       /* lowercase, colon-separated; or NULL */
    char  *serial;    /* or NULL */
    char  *address;   /* address/prefix; or NULL, for DHCP */
    char  *gateway;   /* or NULL */
    char **dns;
    size_t ndns;
};

struct rs_clones {
    struct rs_clone *items;
    size_t           count;
};

void rs_clones_init(struct rs_clones *c);
void rs_clones_free(struct rs_clones *c);

/*
 * Parses the CSV in `text`. `name` is what diagnostics call it. False, with
 * one line in `err` saying where and why, on anything wrong; the copies are
 * then empty.
 */
bool rs_clones_parse(struct rs_clones *c, const char *text, size_t len, const char *name,
                     struct rs_buf *err);
bool rs_clones_load_file(struct rs_clones *c, const char *path, struct rs_buf *err);

#endif /* RESTATE_CLONES_H */
