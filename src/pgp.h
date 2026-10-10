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

/*
 * ASCII armor taken off: the base64 between "-----BEGIN PGP ...-----" and
 * "-----END PGP ...-----", without the armor's headers and its checksum line,
 * decoded into `out`; every block in `text`, one after the other (a keyring
 * file may hold several keys). False if there is no block, or one does not
 * decode. apt reads .asc keys this way; gpgv reads only binary ones.
 */
bool rs_pgp_dearmor(const char *text, size_t len, struct rs_buf *out);

/* A new directory under /tmp, 0700, for gpg's or gpgv's home; NULL, with the
 * reason in `err`, if one cannot be made. rs_pgp_home_remove removes it and
 * whatever gpg left in it, and frees the name. */
char *rs_pgp_home(struct rs_buf *err);
void  rs_pgp_home_remove(char *home);

/*
 * Runs gpgv, in `home`, against the keyring files named, on `sig`: a file
 * signed inline (an apt InRelease) when `data` is NULL, else a detached
 * signature over `data`. Its status lines (--status-fd) go into `status`.
 * False only if it could not be run at all; what it found is in `status`, and
 * rs_pgp_verdict reads it.
 */
bool rs_pgp_gpgv(const char *home, const char *const *keyrings, size_t n, const char *sig,
                 const char *data, struct rs_buf *status, struct rs_buf *err);

/* Who made a good signature, as gpgv reports it. */
struct rs_pgp_signer {
    char fpr[41];     /* the signing key's primary fingerprint, 40 hex digits */
    char who[256];    /* its user ID, "Pat <pat@example.com>", as gpgv gives it */
    char when[11];    /* the day it was made, "2026-10-09" */
};

/*
 * What gpgv's status lines say. True for a good signature by a key in the
 * keyrings -- valid, unexpired, unrevoked -- with who made it in `signer`;
 * otherwise false, and why not, in a few words, added to `why`: "a bad
 * signature", "signed by a key that has expired", "signed by a key that is
 * not given (ID 0123456789ABCDEF)", "not signed".
 */
bool rs_pgp_verdict(const char *status, struct rs_pgp_signer *signer, struct rs_buf *why);

/* Whether a key file's `len` bytes are ASCII-armored rather than binary. */
bool rs_pgp_armored(const char *data, size_t len);

/*
 * The OpenPGP keys in the file `path` -- binary or armored, one or several --
 * written as one binary keyring, which is all gpgv reads, to `dest` (created,
 * 0600). False, with the reason in `err`, if the file cannot be read or holds
 * nothing that looks like a key.
 */
bool rs_pgp_keyring(const char *path, const char *dest, struct rs_buf *err);

/* The same keys, binary, added to `out`. */
bool rs_pgp_key_bytes(const char *path, struct rs_buf *out, struct rs_buf *err);

/*
 * A detached signature over the file `data`, by the first secret key in
 * `keyfile` (gpg --export-secret-keys, armored or not), into `sig`, binary.
 * gpg runs in a throwaway home the key is imported into, and asks for its
 * passphrase, if it has one, the way gpg does -- through gpg-agent's pinentry,
 * on the terminal named by GPG_TTY or the desktop. The signature is then
 * checked against the key's public half, and who made it put in `signer`.
 */
bool rs_pgp_sign(const char *keyfile, const char *data, struct rs_buf *sig,
                 struct rs_pgp_signer *signer, struct rs_buf *err);

#endif /* RESTATE_PGP_H */
