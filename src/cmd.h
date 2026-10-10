/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * The commands. Each returns one of the RESTATE_EXIT_* statuses.
 *
 * Kept out of main.c so the unit tests, which bring their own main(), can call
 * them directly.
 */
#ifndef RESTATE_CMD_H
#define RESTATE_CMD_H

#include "opts.h"

int rs_cmd_capture(const struct rs_options *o);
int rs_cmd_sign(const struct rs_options *o);
int rs_cmd_scan(const struct rs_options *o);
int rs_cmd_diff(const struct rs_options *o);
int rs_cmd_verify(const struct rs_options *o);
int rs_cmd_restore(const struct rs_options *o);
int rs_cmd_machine(const struct rs_options *o);
int rs_cmd_packages(const struct rs_options *o);
int rs_cmd_installer(const struct rs_options *o);
int rs_cmd_buildsheet(const struct rs_options *o);
int rs_cmd_autoinstall(const struct rs_options *o);
int rs_cmd_classify(const struct rs_options *o);
int rs_cmd_rules(const struct rs_options *o);

/* Dispatches on o->command. */
int rs_cmd_run(const struct rs_options *o);

#endif /* RESTATE_CMD_H */
