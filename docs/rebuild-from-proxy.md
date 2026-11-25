# Rebuilding straight from restate-proxy

An Ubuntu autoinstall file that rebuilds a machine restores it from an
image: `--image-at PATH`, a file the installer can reach on a disk or a
share. That means exporting the snapshot first and putting the image
somewhere the installer can read it. This is how the installer reads the
snapshot from the repository itself instead, through restate-proxy, with a
grant that is good for that one restore and nothing else.

## What it has to hold up against

The autoinstall file is fetched by the installer over the network -- PXE,
HTTP, a cloud-init datasource -- and anyone who can fetch it can read it.
Whatever lets the installer reach the repository is therefore in a file that
should be treated as seen by others:

| In the file           | What it would give someone who copied it               |
|-----------------------|--------------------------------------------------------|
| the proxy token       | the grant's access, until it is spent or expires       |
| the decryption key    | the snapshot's content, *with* the packs to decrypt    |
| restate itself        | nothing                                                |
| the trusted keyring   | nothing: public keys                                   |

So the token is made to be worth as little as it can be:

- **Read only**, as every grant can be already.
- **One snapshot**: the grant can read that snapshot and the packs it needs,
  and nothing else in the repository -- no other snapshot is listed or
  served.
- **One restore**: once the restore's `read` session has opened, the grant
  opens no other `read` session, and once it has ended, no session at all.
  Taken first by someone else, the installer's own restore fails, which is
  seen; taken by the installer, it is worth nothing after.
- **Short-lived**: an `expires` of hours, which the helper below sets.

The decryption key is the one secret that outlives the grant. Without the
packs it opens nothing, and the packs are only reachable through the proxy
-- through a grant -- or on the storage host. A site that wants less than
that encrypts each machine's repository to a key of the machine's own as
well as its usual ones (`--encrypt-to` twice), and gives the rebuild that
key alone: what it opens is that machine's own data, which the rebuild is
restoring anyway.

Not in scope: hiding the file from the network it is served on. A site that
can serve each machine its own file over HTTPS should; nothing here depends
on it.

## The grant

Two keys, both only for a grant whose `operations` is `read` alone:

```
# /etc/restate/proxy.d/web01-rebuild.conf
repository   = /srv/restate/web01
operations   = read
snapshot     = 20261120T030000Z
once         = true
token_sha256 = ...
expires      = 2026-11-21T09:00:00Z
label        = rebuild of web01
```

| Key        | Value                                                                  |
|------------|------------------------------------------------------------------------|
| `snapshot` | the one snapshot the grant reads; its directory and the packs its pack list names |
| `once`     | `true`: one `read` session, and none after it has ended                |

`snapshot`: a listing of `snapshots/` holds that snapshot alone, a listing of
`packs/` the packs its pack list (`snapshots/NAME/packs`) names, and any
other snapshot or pack is `404`, as if it were not there. A snapshot with
no pack list -- written before restate 2.0 -- serves no pack at all; the
repository's top (its marker, its chunk keys) is served as for any grant.

`once`: the proxy keeps that the grant's `read` session has opened, in a file
for each of the grant's tokens under its staging directory,
`STAGING/.spent/TOKEN_SHA256`, written before the session is answered, so
that a proxy started again still knows. While that session is open, `look`
sessions are let alone (a run reads indexes as it goes); after it has
ended, or with the proxy started again, every session is refused: `403
grant-spent`. A grant written again with a new token is a new grant. A proxy
with no staging directory cannot keep it, and refuses a `once` grant's
`read` session: `500 proxy-failed`, said in its log.

### Making one

```
restate-proxy --restore-grant CLIENT --repository DIR --snapshot NAME
              --token-file FILE [--hours N] [--label TEXT] [--grants DIR]
```

writes a new token into `FILE` (which must not exist, made `0600`), and the
grant `DIR/CLIENT.conf` (`/etc/restate/proxy.d`), written beside its name
and renamed into place: `operations = read`, the snapshot, `once = true`,
`max_sessions = 2` and `expires` `N` hours from now (24; at most 168). It
refuses to replace a grant that is there. It checks that `DIR` holds a
repository with that snapshot, and prints the grant's file name. A program
that writes its grants itself (SysManage's agent, by its `label`) writes the
same keys.

## The autoinstall file

```
restate autoinstall /srv/restate/web01::20261120T030000Z \
  --image-from https://backup.example.com:8443/v1/web01-rebuild \
  --image-token-file /run/restate/web01-rebuild.token \
  --image-decrypt-with /etc/restate/keys/web01-rebuild.gpg \
  --trusted-key /etc/restate/keys/signing.pub --target vm -o user-data
```

- The image argument is the snapshot, read where it is by the restate
  making the file, with its own access -- the storage host's directory, or
  the proxy with a grant of its own (`--repository-token-file`), never the
  rebuild's, which reading it would spend. `REPO` alone is its newest,
  resolved now, so the file names one snapshot exactly.
- `--image-from URL` is the same repository as the installer will reach it,
  `https://HOST[:PORT]/v1/CLIENT`.
- `--image-token-file`, the rebuild grant's token; `--image-ca-file` or
  `--image-pin-sha256` (up to twice), how the installer trusts the proxy's
  certificate, as `--repository-ca-file` and `--repository-pin-sha256`;
  `--image-decrypt-with`, the key the installer decrypts with, needed where
  the repository is encrypted, and one with no passphrase: the installer
  asks nobody.

What the installer does, in the late-commands, in place of reading
`--image-at`:

1. Writes restate -- the one in the snapshot's own kit, the one that made
   the capture on the machine being rebuilt, so of its release and its
   processor -- and the
   token, the certificate, the key and the keyring into a directory of its
   own under `/run`, only root's.
2. `restate export URL::NAME -o /target/var/tmp/restate-image.tar`, with the
   token, the certificate, the key and `--trusted-key`: the snapshot checked
   for whom it was signed by, as a restore checks it, and every file against
   its digest on the way. The grant is spent here.
3. Everything `--image-at` does, from that image: the packages, then the
   files, by restate restore. The restore is `--allow-unverified`: the image
   is the one step 2 just checked and wrote.
4. Removes the image, and the directory under `/run`.

The image needs room on the new disk next to what is restored from it, for
the length of the install: about the size of the snapshot's content,
compressed.

`autoinstall` refuses `--image-from`:

- with `--image-at` (one or the other);
- for an image file, rather than a snapshot;
- with `--arch` other than the snapshot's processor: the kit's restate is
  that processor's;
- for a snapshot whose kit has no restate, or whose restate predates
  `--trusted-key` (the installer could not check it);
- where the repository is encrypted and no `--image-decrypt-with` is given;
- for a URL that is not `https://HOST[:PORT]/v1/CLIENT`.

restate is carried whole, gzip-compressed, in base64: it makes the file one
to two mebibytes. The installer needs `curl`, `gzip` and, for an encrypted
repository, `gpg`, which Ubuntu's server installer has.

## Jobs and features

An `autoinstall` job takes `repository` and `snapshot` with `image_from`
(and only with it), and `image_from`, `image_token_file`, `image_ca_file`,
`image_pin_sha256` (repeatable) and `image_decrypt_with`. The token file and
the key are held to what `decrypt_with` is: regular files, root's or the
user's, readable by no one else, in a directory only their owner can change.

`restate features` says `"image_from": true`; its `grant_keys` gains
`snapshot` and `once`, so a program writes them only to a proxy that reads
them (an older proxy refuses a grant with a key it does not know, and so
grants nothing, which is the safe way to fail).

## Tests

- Grants: the keys parsed, refused with `append`, refused malformed.
- The proxy, end to end (`tests/cli/proxy.sh`): a `snapshot` grant listing
  and serving that snapshot and its packs alone, `404` for another; a
  `once` grant restoring once, then `403 grant-spent`, and still after the
  proxy is started again; `--restore-grant` making a grant that does that.
- autoinstall: the late-commands for `--image-from` -- restate, the token
  and the key written under `/run`, the export, the restore from it
  `--allow-unverified`, the image and the credentials removed -- and each
  refusal.
- The jobs' keys, and the token and key held to the secret files' rules.
