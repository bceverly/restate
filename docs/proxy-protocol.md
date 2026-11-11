# restate-proxy protocol, version 1

**Status: version 1, in use.** `restate-proxy --serve` implements all of it:
the transport, authentication, sessions and their locks, reading and
writing (see "Running the proxy"). restate reads a repository through it
from 3.1.0.0, and captures and copies into one from 3.2.0.0 ("How restate
uses it"). It was written before the code, so that `restate-proxy` and the
remote backend were built against one description, and so that what
SysManage plans as its Phase 25.5 could be reviewed against it. Now that
restate uses it, version 1 changes only by adding to it.

## What it is for

A repository is a directory, and restate reaches it as one: a local disk, or
a share a file server mounts. `restate-proxy` is a second way in for machines
that cannot or should not mount the share. It runs on the storage host,
serves each client the one repository its token allows, and lets the client
do over HTTPS what a capture, a restore or a listing does to the directory --
and nothing else:

- **Append-only.** A client adds packs and snapshots. It never removes,
  renames or replaces anything in the repository, and there is no request
  that could: no `DELETE` method, no endpoint that writes a name already in
  use. Prune, repack, check, protect, seal and copy stay local jobs on the
  storage host, exactly as they are.
- **The same repository.** The proxy reads and writes the directory with
  restate's own code -- the same locks, the same atomic rename into place --
  so one repository can be used through the proxy by some machines and over
  NFS by others, and switched from one to the other, without moving.
- **Nothing decrypted.** An encrypted repository is served as it is stored.
  The proxy has no key and needs none: it checks what it is sent against the
  `.sum` that goes with it, as `restate ingest` does.

## Transport

- **HTTPS only**: TLS 1.2 or newer (1.3 preferred), ALPN `http/1.1`. There
  is no plain-HTTP listener, and no redirect from one.
- **HTTP/1.1 only.** Persistent connections are expected: a client sends its
  requests one after another on one connection (curl, given many URLs at
  once, does). No pipelining: one request in flight per connection.
- **Request line and headers: 8 KiB in all.** More is refused with `431`
  before anything else is read, and the connection is closed. Each line
  ends in CRLF; a bare CR or LF, a header folded over lines, a control
  character or a NUL is `400`, as is a header this protocol reads
  (`Host`, `Content-Length`, `Authorization`, `Restate-Session`, `Range`,
  `Expect`, `Connection`) given twice. Every request has a `Host`. A header
  it does not read is passed over.
- **A request body has a `Content-Length`.** `Transfer-Encoding` of any kind
  is refused with `411`, and `Expect: 100-continue` is answered with `100`
  only once the request's headers have passed every check -- token, client,
  session, name and size -- so a refused upload sends nothing.
- **No compression** either way: everything restate stores is gzip'd, and
  most of it encrypted, already.
- A response carries `Content-Length` and, for a file, `Last-Modified`.

## Names

Everything under `/v1/` is for version 1. `GET /v1/` answers
`restate-proxy 1\n` to anyone, with no token, so that a client can tell a
proxy from anything else at that address; nothing else is said without one.

A client's requests are under `/v1/CLIENT/`. `CLIENT` is the name the
allow list gives it (its file's name, without `.conf`): one to 64 of
`a-z`, `A-Z`, `0-9`, `.`, `_` and `-`, not beginning with `.` or `-`.

A repository's files are named in requests exactly as they are named in it:

| Name                               | What it is                                   |
|------------------------------------|----------------------------------------------|
| `restate-repository`               | the marker                                   |
| `chunk-key`, `chunk-key.NAME`      | an encrypted repository's chunking key       |
| `packs/NAME.tar.gz`                | a pack's content                             |
| `packs/NAME.idx`                   | its index                                    |
| `packs/NAME.sum`                   | its digest and size, as stored               |
| `packs/NAME.seek`                  | where its segments begin, if it has any      |
| `snapshots/NAME/index.json.gz`     | a snapshot's index                           |
| `snapshots/NAME/index.sig`         | its signature, if it is signed               |
| `snapshots/NAME/kit`               | the paths in its kit                         |
| `snapshots/NAME/info`              | its summary                                  |
| `snapshots/NAME/packs`             | the packs it needs                           |

`NAME` is a name restate gives a pack or a snapshot (`rs_repo_name_valid`).
Any other name -- `lock`, `readers`, a name beginning with `.`, a path with
`..`, an empty component, a percent-encoded `/` -- is `404`, whatever is
there. The proxy never serves or lists a file it does not know the name of.

## Authentication

Every request under `/v1/CLIENT/` carries

```
Authorization: Bearer rsp_<43 characters>
```

A token is 32 random bytes in base64url without padding, prefixed `rsp_` so
that a secret scanner recognizes one: 47 characters, the last of which can
only be one whose two low bits are 0, so that a token has one spelling. The
proxy keeps only its SHA-256 -- of the token exactly as written, prefix and
all, so that `printf %s "$TOKEN" | sha256sum` gives what a grant's
`token_sha256` says -- and compares that in constant time.

The token is checked first: before the path is looked at further, before
the session, before a byte of the body is read. The client in the path has
to be the token's client.

- No token, a token that is not one, a token nobody has, a token whose grant
  has expired, a token that is another client's: all are `401`, with the
  same body and `WWW-Authenticate: Bearer`, so that a request without the
  right token learns nothing -- not even whether `CLIENT` exists.
- A good token asking for what its grant does not allow is `403`.

The client gives its token to curl in a config file of its own (`-K`),
as a `header = "Authorization: Bearer ..."` line, made `0600` in a
directory only it can reach, and never on a command line, where `ps` would
show it. Not a netrc file: curl sends what one holds as `Basic`, and the
proxy takes only `Bearer`. It reads each answer's status and
`Restate-Reason` from the headers curl writes to a file (`-D`), which every
curl it runs on can do.

## Grants

A client's file in `/etc/restate/proxy.d/`, named for it (`web01.conf`), says
what it may do. It is restate's own `key = value` format, as a job file is,
read the same strict way: an unknown key, a value of the wrong kind or a key
given twice that may not be is an error, and a file with an error grants
nothing (the proxy says why in its log, and the client sees `401`). A file
that is not the proxy user's or root's, or that anyone else can write, is
not read at all.

Only a file named `CLIENT.conf`, for a `CLIENT` as above, is a grant. Every
other name in the directory -- one beginning with `.`, one not ending in
`.conf` -- is passed over, so a program writing a grant writes
`.web01.conf.tmp` and renames it into place, and the proxy never reads one
half written.

```
# /etc/restate/proxy.d/web01.conf
repository   = /srv/restate/web01
operations   = append, read
token_sha256 = 8f14e45fceea167a5a36dedd4bea2543c8d2d1e3c1b5d7d0a2a6a1f6c1f8a9e0
token_sha256 = 3b5d5c3712955042212316173ccf37be8b0b0f4a1d5c1e4b8a3e2f7d6c5b4a39
expires      = 2026-12-31T00:00:00Z
label        = managed by sysmanage-agent: web01.example.com
max_sessions = 2
bandwidth    = 08-18 2MiB/s
bandwidth    = 20MiB/s
```

| Key            | Value                                                          |
|----------------|----------------------------------------------------------------|
| `repository`   | the repository's directory: absolute, with no `.` or `..`      |
| `operations`   | `append`, `read`, or both                                      |
| `token_sha256` | a token's SHA-256, in hex; once or twice                       |
| `expires`      | optional: a UTC time after which the grant is no more          |
| `label`        | optional: free text, up to 256 bytes, that the proxy ignores   |
| `max_sessions` | optional: sessions the client may have open at once, 1 to 1024 |
| `bandwidth`    | optional, repeatable: how fast its requests may move bytes, by the hour |

A line is split at its first `=`: the key is what comes before it and the
value everything after, blanks at either end aside, so a value may itself
hold `=` and `#`. `#` begins a comment only as the first thing on a line,
never after a value.

`label` is for whatever writes grants: a program that manages some of the
files in `proxy.d` marks its own with it -- SysManage's agent with a fixed
prefix -- so that it can remove the ones it no longer wants without
touching a file someone wrote by hand.

Two tokens so that one can be rotated: the new one's hash is added, the
client given the new token, and the old one's hash removed. A grant with an
expiry is how a short-lived, read-only grant for one restore is made, with
no change to the protocol. A client is added or removed by writing or
removing its file; the proxy reads them again when they change, and on
`SIGHUP`. Many clients may have the same repository.

### Limits

A grant can hold its client to less than the proxy allows every client:

- **`max_sessions`**: past it, a session is refused with `503
  client-sessions-full`, which restate takes as busy (exit 5), as it does
  the proxy's own `--max-sessions`. A run of restate holds one session at a
  time; a copy from the proxy into the same proxy holds two. With none, the
  client is held only to `--max-sessions`.
- **`bandwidth`**: bytes a second, each way, as `512KiB/s`, `2MiB/s` or
  `1GiB/s` (`64KiB/s` at the least), or `unlimited`. `HH-HH RATE` is for
  those hours of the storage host's local day, from the start of the first
  to the start of the second (`08-18`, or `22-06` across midnight); a
  `RATE` alone is for every hour no range names. Ranges may not overlap,
  and a `RATE` alone is given once. With none, there is no limit. The rate
  is the hour's as each request in a session is begun, and the client's
  requests being answered at once share it equally: a restore's one
  connection has it all, and a capture's renewals cost nothing of it.

A proxy that stores for many clients can hold each to a quota of its own
with `--quota-hook` (below).

What the operations allow:

| Operation | Allows                                                                 |
|-----------|------------------------------------------------------------------------|
| `append`  | sessions of kind `look` and `append`: listing, every file but a pack's content, and uploads |
| `read`    | sessions of kind `look` and `read`: listing and every file, a pack's content included |

`append` alone is what a machine that only captures needs: an incremental
capture reads every `.idx`, to store nothing twice, and the snapshots'
indexes, to pass over what has not changed -- but never a pack's content.

### Checking grants

A client with a bad grant only ever sees `401`, so the storage host is where
a mistake is found:

```
restate-proxy --check-grants [DIR] [--json]
```

reads every grant in `DIR` (`/etc/restate/proxy.d` if none is given) as the
proxy would, and says of each that it is good, or what is wrong with it: one
line per file, or with `--json` one object, `{"schema": 1, "grants":
[{"file": ..., "client": ..., "ok": true|false, "error": ...}]}`. It exits 0
if every grant is good and 2 if one is not. It needs no running proxy, and
says nothing of any token but its hash's place in the file.

## Sessions

Every request but opening a session belongs to one, given by a header:

```
Restate-Session: 6f1c0a9d2e7b4c35a8f0e1d2c3b4a596
```

A session is what holds the repository's locks while a client uses it --
the real ones, `lock` and `readers`, that a prune on the storage host takes
too -- so a capture through the proxy and a prune on the storage host keep
out of each other's way exactly as two local runs do, and a restore's packs
are not pruned under it.

| Kind     | Lock in the repository | As a local run takes it for                         |
|----------|------------------------|-----------------------------------------------------|
| `look`   | none                   | what reads only indexes: `snapshots`, `list`, `diff` |
| `read`   | `readers`, shared      | what reads content: `restore`                       |
| `append` | `lock`, exclusive      | `capture`, which through the proxy is always `--append-only` |

### Open

```
POST /v1/CLIENT/sessions
Content-Length: 6

append
```

The body is the kind. On success, `201` with the session in the body and a
header, and how long its lease lasts:

```
HTTP/1.1 201 Created
Restate-Session: 6f1c0a9d2e7b4c35a8f0e1d2c3b4a596
Restate-Lease: 300
Content-Length: 33

6f1c0a9d2e7b4c35a8f0e1d2c3b4a596
```

- `423` if the lock is held -- a capture already running, a prune -- which
  the client gives as exit 5 (busy), so a job's retry applies as it does on
  NFS.
- `409` if the repository is version 1 (made by restate 1.3 or older): a
  capture would have to change its marker, which nothing through the proxy
  may. One capture on the storage host makes it version 2.
- `503` if the proxy has as many sessions open as it allows
  (`sessions-full`), or the client as many as its grant does
  (`client-sessions-full`).
- `507` if the quota hook says the client may store no more
  (`quota-exceeded`); only an `append` session asks it.

A session id is 16 random bytes in hex, belongs to the client that opened
it, and is `401` from any other.

### Renew and end

```
POST /v1/CLIENT/sessions/ID/renew      ->  204, Restate-Lease: 300
POST /v1/CLIENT/sessions/ID/end        ->  204
```

A client renews well inside the lease (every minute, for a lease of five),
on a connection of its own: a renew may come while another of the session's
requests is still going, on another connection, and is answered at once.
And the lease runs only while the session is idle: it never ends while a
request of the session is being read or answered -- an index of 2 GiB sent
at 2 MB/s takes a quarter of an hour -- and starts again when the last one
finishes. A session not renewed in time is ended by the proxy, as one ended
by its client would be; its locks go with it, and a request in it afterwards
is `404`. A client that dies, then, holds nothing for longer than a lease.

A client ends its session itself whenever it stops -- having finished,
failed, or been told to stop (`SIGTERM`, `SIGINT`) -- before it exits, so
that the next run does not find the repository busy for the rest of a
lease.

Ending a session ends it as a run ends:

- Whatever its uploads left in staging that was not committed is removed.
- An `append` session that committed packs but no snapshot -- a capture
  that failed or was stopped -- has those packs taken out again, as a local
  capture that fails takes out the packs it wrote. A pack it committed that
  was there already, the same, is left: it was not this session's.

The proxy removes the staging of a session it finds there from before it
was last started, too.

Each session that ends is one line in the proxy's log, in `key=value` form
for a program to read:

```
session-end client=web01 kind=append seconds=812 bytes_in=2254857216 bytes_out=1048576 packs=68 snapshot=20261020T030000Z result=ok
```

`result` is `ok`, `ended` (ended without a commit of a snapshot, where it
is an `append` session), `expired` or `failed`; `snapshot` is there only for
one that committed one.

## Reading

In any session (`look`, `read` or `append`), unless said otherwise.

### Listing a directory

```
GET /v1/CLIENT/list/            the repository's top
GET /v1/CLIENT/list/packs/
GET /v1/CLIENT/list/snapshots/
GET /v1/CLIENT/list/snapshots/NAME/
```

`200`, `text/plain`, one entry per line, sorted by name:

```
restate-list 1
f 2130 1761120000 20261020T030000Z-4012-0001.idx
f 33554877 1761120000 20261020T030000Z-4012-0001.tar.gz
f 72 1761120000 20261020T030000Z-4012-0001.sum
d 0 1761120400 20261020T030000Z
```

Each is `KIND SIZE MTIME NAME`: `f` a regular file, `d` a directory, `o`
anything else; its size in bytes; when it last changed, in seconds since the
epoch. Only names the table above knows are listed (in the top, the marker
and the chunk keys; nothing beginning with `.`). A snapshot directory is
listed whether or not its index is there, and a pack's files whether or not
its `.idx` is: what counts is for the client to work out, as it does from a
directory. A directory that is not there is `404`.

### A file

```
GET  /v1/CLIENT/f/packs/NAME.idx
HEAD /v1/CLIENT/f/snapshots/NAME/info
GET  /v1/CLIENT/f/packs/NAME.tar.gz
Range: bytes=1048576-
```

`200` with the file, or `206` with the range asked for. `HEAD` says the same
without the body, which is how a client asks whether a file is there and
how large it is.

- `Range` is one range of bytes, `bytes=FIRST-` or `bytes=FIRST-LAST`:
  a restore reads a pack from the segment `.seek` points to. Anything else --
  several ranges, a suffix range, a range that begins at or past the end --
  is `416`, with `Content-Range: bytes */SIZE`. A range that ends past the
  end ends at the end, as HTTP has it. A `206` says what it holds in
  `Content-Range: bytes FIRST-LAST/SIZE`, and every file is answered with
  `Accept-Ranges: bytes`.
- A pack's content (`packs/NAME.tar.gz`) is only for a `read` session:
  `403` in any other.
- A file that is not there is `404`.

Every file is served as it is stored, byte for byte: encrypted where the
repository is.

## Writing

Only in an `append` session. A capture uploads each file into the session's
staging, where nothing reads it, and then commits it -- which is `restate
ingest` run on it in the proxy: copied into the repository under a name
nothing reads, checked there, and renamed into place, `.idx` last.

### Uploads

```
PUT /v1/CLIENT/sessions/ID/files/packs/NAME.tar.gz
Content-Length: 33554877

<the file>
```

`201` once it is in staging, whole. A file of that name already in the
session's staging is replaced: an upload that failed partway is sent again.
Only the names in the table above, except the marker, may be uploaded; and
each no larger than restate writes one, which is said before the body is
read (`413`):

| Name                           | At most          |
|--------------------------------|------------------|
| `packs/NAME.tar.gz`            | 64 MiB           |
| `packs/NAME.idx`               | 256 MiB          |
| `packs/NAME.sum`               | 4 KiB            |
| `packs/NAME.seek`              | 16 MiB           |
| `snapshots/NAME/index.json.gz` | 2 GiB - 1 byte   |
| `snapshots/NAME/index.sig`     | 64 KiB           |
| `snapshots/NAME/kit`, `info`   | 256 MiB          |
| `snapshots/NAME/packs`         | 16 MiB           |
| `chunk-key`, `chunk-key.NAME`  | 4 KiB            |

A pack is cut at 32 MiB of content, plus at most one 4 MiB chunk, so 64 MiB
leaves room for gzip's and gpg's overhead and nothing more. The proxy also
limits how much one session's staging may hold, and refuses past it with
`507`; and with a quota hook, it asks the hook before each upload, and
refuses one the hook says no to with `507 quota-exceeded` -- before a byte
of its body is sent.

### Commits

```
POST /v1/CLIENT/sessions/ID/commit/packs/NAME
POST /v1/CLIENT/sessions/ID/commit/snapshots/NAME
POST /v1/CLIENT/sessions/ID/commit/chunk-key
POST /v1/CLIENT/sessions/ID/commit/chunk-key.NAME
```

**A pack** -- its content, `.sum` and `.idx` uploaded, and its `.seek` if it
has one -- is ingested: its content has to be what its `.sum` says, and, in
a repository that is not encrypted, what its `.idx` says; encrypted, every
file but the `.sum` has to be. A capture commits each pack as soon as it
has uploaded it, so that its staging holds one pack at a time.

- `201`: it is in the repository now.
- `200`: the same pack was there already (its `.sum` is the same): nothing
  to do, as when a commit is sent again after its answer was lost.
- `409`: a different pack of that name is there.
- `422`: it is not a pack restate wrote, or not one this repository can
  hold -- the body says what is wrong.

**A snapshot** -- its index, kit, summary and pack list uploaded, and its
signature if it is signed -- is ingested: every pack its list names has to
be in the repository, and its files encrypted exactly when the repository
is. It is the last thing a capture commits.

- `201`, `200` and `422` as for a pack.
- `409`: another snapshot has that name. A capture names its snapshot for
  the time it was taken, and two in one second are told apart by a number
  after it, so the client tries the next name.

**A chunk key** is put in place only if nothing of that name is there: `201`
if it was, `200` if something was there already, which is kept. A capture
reads the chunk keys again afterwards, as it does on a share where two
machines may make one at once.

## Status codes

| Code  | Meaning here                                                           |
|-------|------------------------------------------------------------------------|
| `200` | done; for a commit, it was there already, the same                     |
| `201` | made: a session, an upload, a commit                                   |
| `204` | done, nothing to say: renew, end                                       |
| `206` | the range asked for                                                    |
| `400` | not a request this protocol has                                        |
| `401` | no session or token, or not one that is good for this client           |
| `403` | not allowed by this client's grant or this session's kind              |
| `404` | no such file, directory or session                                     |
| `405` | not a method this endpoint takes; every `DELETE`                       |
| `409` | in the way: a different file of that name, a version 1 repository      |
| `411` | a body without `Content-Length`                                        |
| `413` | larger than restate writes that file                                   |
| `416` | a range that is not one range within the file                          |
| `417` | an `Expect` other than `100-continue`                                  |
| `422` | not what restate writes: the body says what is wrong                   |
| `423` | the repository is busy: another capture, or a prune                    |
| `431` | request line and headers over 8 KiB                                    |
| `501` | an upload or a commit to a proxy with no staging it can use            |
| `505` | an HTTP version other than 1.1                                         |
| `503` | the proxy, or this client, is at its limit of sessions; try again later |
| `507` | the session's staging, or the disk, is full; or the client is over its quota |
| `500` | the proxy failed; its log says why                                     |

An error's body is one line of `text/plain`, for a person: the client shows
it as restate shows any error. A program decides what to do by the code, or
by the reason every error carries in a header of its own, which is fixed
and never worded for a person:

```
HTTP/1.1 409 Conflict
Restate-Reason: repository-version-1
```

| Reason                   | Code  | What it is                                         | restate exits |
|--------------------------|-------|----------------------------------------------------|---------------|
| `unauthorized`           | `401` | no good token for this client, or no such session  | 2             |
| `forbidden`              | `403` | not in this grant, or not in this kind of session  | 2             |
| `not-found`              | `404` | no such file or directory                          | 2             |
| `repository-version-1`   | `409` | made by restate 1.3 or older: one capture on the storage host makes it version 2 | 2 |
| `name-taken`             | `409` | a different pack or snapshot of that name is there | 2             |
| `invalid`                | `422` | not what restate writes                            | 2             |
| `too-large`              | `413` | larger than restate writes that file               | 2             |
| `busy`                   | `423` | another capture, or a prune                        | 5             |
| `sessions-full`          | `503` | the proxy is at its limit of sessions              | 5             |
| `client-sessions-full`   | `503` | this client is at its grant's `max_sessions`       | 5             |
| `storage-full`           | `507` | the session's staging, or the disk, is full        | 2             |
| `quota-exceeded`         | `507` | the quota hook says the client may store no more   | 2             |
| `bad-request`            | `400`, `405`, `411`, `416`, `417`, `431`, `505` | not a request this protocol has | 2 |
| `proxy-failed`           | `500` | the proxy failed; its log says why                 | 2             |
| `not-implemented`        | `501` | the proxy takes no uploads: it has no staging      | 2             |

A `name-taken` on committing a snapshot is not an error the client shows:
it tries the next name. restate's result JSON for a run against a proxy
carries the reason of the failure that ended it, as `"proxy_reason"`, so a
program reading the result chooses what to say by it.

## How restate uses it

The remote backend is a store (`src/store.h`) whose files are reached this
way, so that `repo.c` -- every command that uses a repository -- is the same
code against a directory and against a proxy. What each of the store's
operations becomes:

| Store operation           | Through the proxy                                        |
|---------------------------|----------------------------------------------------------|
| open a repository         | open a session: `append` for capture, `read` for restore, `look` otherwise |
| stat, is a file           | its directory's `GET /list/DIR/`, fetched once a session |
| list                      | `GET /list/DIR/`                                         |
| read, peek, open          | `GET /f/NAME`; open at an offset is `Range`              |
| create, write             | a file in the session's stage on this machine, laid out as the repository is, and read from there until it is sent |
| rename into place         | a pack's content, `.sum` and `.seek`: nothing yet; its `.idx`: all four uploaded and the pack committed, in one curl. A snapshot's directory: its files uploaded and the snapshot committed. A chunk key: uploaded and committed. Then taken out of the stage |
| place new (a chunk key)   | upload it, then commit it                                |
| replace (a pack's `.sum`) | in the stage, before its pack is sent; nothing in the repository is replaced |
| remove                    | in the stage; nothing in the repository is removed -- a failed capture's packs go with its session |
| lock, unlock              | the session's own locks; unlock is ending it             |

Everything that would remove, replace or rename something already in the
repository -- prune, repack, sign on a snapshot already there, protect --
is refused against a proxy, and run on the storage host.
`capture --sign-with` signs the index before it is uploaded, on the client,
where it is staged. A snapshot whose name turns out to be taken as it is
committed (`409 name-taken`) is made again under the next name -- its index
and summary name it -- and sent again.

The client trusts the proxy's certificate as curl does, from the system's
certificate authorities, unless it is told otherwise -- for a proxy whose
certificate a site's own CA signed, without that CA being trusted by the
whole machine:

| Job key                  | Command line              | curl                     |
|--------------------------|---------------------------|--------------------------|
| `repository_token_file`  | `--repository-token-file` | a `-K` config file       |
| `repository_ca_file`     | `--repository-ca-file`    | `--cacert`               |
| `repository_pin_sha256`  | `--repository-pin-sha256` | `--pinnedpubkey sha256//...` |

`repository_ca_file` is a PEM file of the certificate authorities to trust
instead of the system's. `repository_pin_sha256` is the base64 SHA-256 of
the proxy's public key, as `openssl` prints it; given twice, either is
accepted, so that a key can be replaced without a run failing in between.
The token file is held to what `passphrase_file` is: a regular file, its
owner's or root's, that nobody else can read.

## Running the proxy

```
restate-proxy --serve [--listen HOST:PORT]... [--cert FILE] [--key FILE]
                      [--grants DIR] [--max-connections N] [--idle-timeout SECONDS]
                      [--max-sessions N] [--lease SECONDS]
                      [--staging DIR] [--max-staging MIB]
                      [--quota-hook PROGRAM]
```

- `--listen` is `HOST:PORT`, `[ADDRESS]:PORT` for IPv6, or `:PORT` for every
  address; repeatable, and `:8443` if not given. Each address family gets a
  socket of its own.
- `--cert` is the certificate chain in PEM, the proxy's own certificate
  first (`/etc/restate/proxy.crt`), and `--key` its private key in PEM,
  unencrypted (`/etc/restate/proxy.key`). Both are read once, at start.
- `--grants` is the allow list (`/etc/restate/proxy.d`). It is read again on
  `SIGHUP`, and whenever the directory changes -- a grant renamed into
  place, or one removed -- within a few seconds.
- Each connection is served by a process of its own, with the grants as
  they were when it came. Past `--max-connections` (64), a connection is
  closed as it comes. A connection that says nothing for `--idle-timeout`
  seconds (60) is closed.
- The sessions are the listening process's, with the locks they hold: a
  session outlives the connection that opened it, and a connection's process
  asks the listener for it. Past `--max-sessions` (64), a session is refused
  with `503`. One idle for `--lease` seconds (300) is ended, and a request in
  it afterwards is `404`.
- `--staging` is where an append session's uploads wait to be committed
  (`/var/lib/restate-proxy/staging`), a directory of `CLIENT/ID` for each
  session. It is made if it is not there (its parent has to be), and has to
  be the proxy's user's alone (mode `0700`); otherwise nothing can be
  uploaded, which the log says as the proxy starts, and an upload is `501`.
  What sessions before a start left there is removed as it starts. One
  session's staging holds at most `--max-staging` MiB (4096), past which an
  upload is `507`.
- `--quota-hook` is a program, by its absolute path, asked before an
  `append` session opens and before each upload whether the client may
  store more (below). The proxy does not start if it is not one it can run.
- `SIGTERM` or `SIGINT` stops it: it stops listening, ends every connection
  and every session, and exits 0.

Its log is standard error, a line per event in `key=value` form: what it
listens on, the grants it read (`grants clients=N refused=M`) and each one
it refused, with why (`grant-refused file=... error="..."`), each request
(`request peer=... client=... method=... target=... status=... reason=...
bytes=...`), each session opened (`session-open client=... kind=...`) and
each ended (`session-end`, as above), a session it could not open, with
why (`session-refused client=... error="..."`), and a commit or an upload
that failed on its side, not the client's (`commit-failed client=...
name=... error="..."`, `upload-failed`), and each answer of the quota
hook's that refused (`quota-refused client=... event=... message="..."`)
or failed (`quota-hook-failed client=... event=... error="..."`). A token
is never in it, nor a session's id. It starts with a line of what it is:
`started version=... tls="..." confinement="..." ... quota_hook=...`.

### The quota hook

A host that stores for many clients holds each to what it pays for, or was
given, by whatever keeps that -- a filesystem's quotas, a database, a
billing system -- through a program of its own, `--quota-hook PROGRAM`,
asked before an `append` session opens and before each upload.

It is run by the listening process, which is not confined (so the hook may
reach whatever it needs, a socket included), as the proxy's user: with no
arguments, standard input `/dev/null`, standard error the proxy's log, none
of the proxy's descriptors, and an environment of its own and nothing of
the proxy's:

| Variable                   | What it is                                           |
|----------------------------|------------------------------------------------------|
| `PATH`                     | `/usr/bin:/bin:/usr/sbin:/sbin`                      |
| `RESTATE_PROXY_EVENT`      | `open`, as an append session opens; `upload`, before each file of a capture is sent |
| `RESTATE_PROXY_CLIENT`     | the client, `web01`                                  |
| `RESTATE_PROXY_REPOSITORY` | its repository, as its grant names it               |
| `RESTATE_PROXY_LABEL`      | its grant's `label`, where it has one                |
| `RESTATE_PROXY_NAME`       | the upload's name, `packs/NAME.tar.gz`; not set for `open` |
| `RESTATE_PROXY_BYTES`      | the upload's size; `0` for `open`                    |

Its answer is how it exits: `0`, the client may; `1`, it may not, and the
client is told `507 quota-exceeded`, with the first line the hook wrote to
standard output, if it wrote one (up to 200 bytes, on one line, as text).
Any other exit, a signal, or still running after 30 seconds -- when it and
what it started are killed -- is the hook failing, and the request is `500
proxy-failed`. The listening process never waits for it: only the
connection that asked does. A capture asks it once for its session and
once for each file it sends, four or five for each pack of 32 MiB, so a
hook that answers from what it keeps, rather than by measuring the
repository each time, costs the capture nothing it would notice.

```sh
#!/bin/sh
# /usr/local/libexec/restate-quota: each client to 500 GiB of its own ZFS dataset.
used=$(zfs get -Hp -o value used "tank/restate/$RESTATE_PROXY_CLIENT") || exit 2
if [ $((used + RESTATE_PROXY_BYTES)) -gt $((500 * 1024 * 1024 * 1024)) ]; then
  echo "$RESTATE_PROXY_CLIENT is over its 500 GiB"
  exit 1
fi
exit 0
```

### Confinement

A connection is one client's from its first good token: a request for any
other client on it afterwards is `401`. From then on two processes serve
it, each confined as tightly as what it does allows, so that a fault in the
parser, or in what reads an upload, cannot reach another client's
repository:

- **the connection's** -- TLS, the requests, reading, uploads -- reads the
  client's repository and writes its staging, runs no program and makes no
  socket;
- **the committer** -- the commits, which are `restate ingest`'s code --
  reads the staging, writes the repository, and runs gzip, which reads what
  a pack holds; it too makes no socket.

| System  | How                                                                     |
|---------|-------------------------------------------------------------------------|
| OpenBSD | `unveil(2)` the repository, the staging and, for the committer, gzip; `pledge(2)` `stdio rpath wpath cpath`, and `fattr proc exec` for the committer |
| Linux   | Landlock (kernel 5.13 or later): the same, with the system's programs and libraries (`/usr`, `/lib`...) read and run by the committer only; no TCP bind or connect; from Landlock's ABI 6, no signal or abstract socket outside. And a seccomp filter refusing sockets, `ptrace`, mounts, modules, BPF, namespaces, `io_uring` and the like, and, for the connection's process, running a program |
| FreeBSD | Capsicum: the connection's process enters capability mode, reaching the repository and its staging through descriptors alone. The committer is not confined: a program cannot be run in capability mode |

Elsewhere, and on a Linux kernel without Landlock, what cannot be is not, and
the `confinement` the proxy says it has as it starts says so (`none`, or
`seccomp` alone).

## Not in version 1

- Anything that removes or changes what is in a repository.
- A client certificate in place of a token.
