/*
 * Copyright (c) 2026 Bryan C. Everly
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*
 * Encrypting images, with gpg as a separate process.
 *
 * An image holds whatever the machine had that a reinstall would not put
 * back, and that can include keys: a LUKS key file under /etc, SSH host keys,
 * TLS private keys, a password store. `capture --encrypt-to` encrypts the
 * image to one or more OpenPGP public keys, so a capture can run unattended --
 * from cron, with no passphrase anywhere -- and only the holder of a matching
 * secret key can read the result.
 *
 * gpg runs as a filter in the same pipe as gzip: tar, then gzip, then gpg,
 * then the 0600 temporary that becomes the image. (The content kept during
 * the walk is staged unencrypted in an unlinked temporary beside it first --
 * the index has to lead the archive and is finished last -- which the manual
 * says, with what to do where that matters.)
 *
 * Encrypting needs no keyring: gpg runs in an empty home directory of its own
 * and reads each recipient's key from the file named. Reading an image back
 * runs gpg the other way, in the invoking user's own GnuPG home, which is
 * where the secret key is and where gpg-agent asks for its passphrase.
 */
#ifndef RESTATE_PGP_H
#define RESTATE_PGP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "util.h"

struct rs_pgp {
    pid_t pid;
    int   fd;      /* write plaintext here, or read it from here */
    char *home;    /* the throwaway GnuPG home an encryption runs in */
};

/* Whether `head` (the first `len` bytes of a file) is an OpenPGP encrypted
 * message, binary or ASCII-armored. */
bool rs_pgp_detect(const unsigned char *head, size_t len);

/* Starts gpg encrypting to the public keys in `recipients` (files), writing
 * the ciphertext to `out_fd`. */
bool rs_pgp_encrypt(const char *const *recipients, size_t n, int out_fd, struct rs_pgp *pg,
                    struct rs_buf *err);

/* Starts gpg decrypting from `in_fd`. */
bool rs_pgp_decrypt(int in_fd, struct rs_pgp *pg, struct rs_buf *err);

/* Closes our end and waits for gpg; true if it exited 0. With `abandon`, a
 * reader stopped early: told to stop, and how it ends does not matter. */
bool rs_pgp_finish(struct rs_pgp *pg, bool abandon, struct rs_buf *err);

#endif /* RESTATE_PGP_H */
