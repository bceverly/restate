# restate: changes needed for SysManage integration

This lists what restate needs so SysManage can use it as the fleet's backup
mechanism (SysManage ROADMAP Phase 24, "Fleet Backup & Recovery with restate",
target v3.12.0.0). It realizes the "Integration with SysManage" item under
**Later** in this repository's ROADMAP.md.

How SysManage will drive restate, in brief:

- Each managed host keeps a restate repository on the NAS: one directory per
  host, `/srv/backups/restate/<fqdn>-<short host id>/` (keyed by SysManage's
  host id, so renamed or reinstalled hosts keep their history; under
  multi-tenancy, `/srv/backups/<tenant>/...`), exported over NFSv4 to that
  host only. The export uses `all_squash` with `anonuid` mapped to a
  dedicated `restate` user on the NAS.
- Hosts only append. A host's capture adds snapshots but can never delete or
  rewrite one; `prune`, `check` and `copy` run on the storage side, on the
  NAS's own agent (items 18, 19).
- The SysManage agent runs unprivileged and never builds a restate command
  line from data it was sent. The server's backup policy reaches the host as
  data. The agent validates it and installs it root-owned under
  `/etc/restate/`. A fixed systemd unit then runs restate as root, and the
  agent starts that unit with one exact sudoers form.
- The agent reads the outcome, reports it to the server, and the server
  schedules, retains, alerts and offers restores.

The items are grouped by priority. **Must** blocks the v3.12.0.0 integration,
**Should** makes it good, and **Later** can follow.

---

## Must

### 1. A machine-readable result for every command SysManage runs

Today the only structured outcome is the `--syslog` line, and it carries
less than SysManage needs. `diff`, `verify`, `status` and `snapshots` print
text for people.

- Add `--result FILE`: when the command ends, write one JSON object to FILE
  atomically (write to a temp file, then rename). Cover `capture`, `prune`,
  `check`, `restore`, `status` and `verify`. Include:
  - `command`, `status` (`ok` / `incomplete` / `busy` / `failed` /
    `untrusted`), `exit`, `started_at`, `seconds`
  - for capture: `snapshot` (the full `REPO::NAME`), `paths`, `kept`,
    `read_bytes`, `reused_bytes`, `new_bytes`, `repository_bytes`
  - `unreadable`, as a count plus the first N paths with their reasons;
    exit 3 is useless to an operator without them
  - `quiesce`: each hook that ran, its pause and resume times, and its
    result
  - `warnings`, for example a live database detected without `--quiesce`
- Add `--json` to `snapshots`, `diff` (including `--packages`) and `status`,
  so SysManage can show snapshot lists and drift without parsing text.
- Write the exit codes 0-5 into the man page as a stable contract.
  SysManage maps them directly: 3 is a warning, 5 means retry later, and 2
  and 4 are failures.

### 2. Structured progress

`-P` prints a human line every 10 seconds when there's no terminal. Add
`--progress=json` (or `--progress-fd N`) that emits one JSON object per
line: phase, paths walked, bytes read, bytes new, current hook. SysManage
shows live progress for long first captures, such as a mail store or a
Nextcloud data directory.

### 3. A root-owned job file instead of a command line

restate has no configuration file today; every setting is a command-line
flag. To keep the privilege boundary tight, SysManage installs a
**job file** and runs a fixed command.

- Add `restate run JOBFILE` (or `--job FILE`), reading a small declarative
  file such as `/etc/restate/sysmanage.d/nightly.conf`. It holds: command
  (`capture` / `prune` / `check`), repository path, rules files, `--all` /
  `--baseline-content`, `--quiesce`, `--encrypt-to` fingerprint, keep
  policy, check mode (`--read-all` or not), and the result and progress
  destinations.
- Refuse a job file that isn't owned by root or is group- or
  world-writable, the same rule as `hooks.d`.
- The file must not be able to run arbitrary commands. Only known keys,
  each strictly typed.

### 4. A systemd unit and timer template

Ship `restate-job@.service` (and optionally `restate-job@.timer`), running
`restate run /etc/restate/sysmanage.d/%i.conf`. It should set:

- `Nice=` / `IOSchedulingClass=idle` (some hosts here are laptops serving
  with their lids closed and already run hot)
- `TimeoutStartSec=` large enough for a first capture
- `KillMode=mixed`, so the resume hooks still run on stop

SysManage starts it with `systemctl start restate-job@<policy>`. The run
survives an agent restart and logs to the journal. Alternatively SysManage
ships the unit; but a restate-owned unit lets other users use it too.

### 5. Repositories on NFS

restate opens no network connections, so the NAS is reached through an
NFS mount. Today this is the riskiest part.

- **Locking:** the man page says `flock(2)` locks may be ignored on some
  network filesystems. Either:
  - detect NFS and use an `O_EXCL` lock file with a holder record (host, pid,
    started_at) and stale-lock recovery, or
  - test and document that NFSv4 locking is honored, and refuse NFSv3
    mounts that aren't mounted with locking.

  Two captures, or a capture and a prune, writing the same repository is the
  failure that must not happen.
- **Staging location:** the image staging file sits next to the output, and
  costs disk space equal to the uncompressed content. Check what the
  repository write path stages, and make sure nothing large is staged on the
  NFS mount. Add `--tmpdir DIR` so staging can be on local disk.
- **Squashed ownership:** with `all_squash`, files on the NAS are owned by
  the mapped user, not root. Make sure no repository code insists on root
  ownership or exact modes for its own files. The `0700`/`0600` checks
  should accept the mapped owner, or be switchable with a documented flag.
- **Interrupted runs:** a dropped NFS mount or a host reboot mid-capture
  must leave the repository consistent. Document whether `prune` or `check`
  is the recovery step, and report leftovers in the `check` JSON.

### 6. Quiesce: declared services and the hooks this fleet needs

Live detection is `/proc` only, and only for services it knows. SysManage
needs to say what to quiesce, and needs hooks for the services on the first
hosts it will back up.

- Add `--quiesce-with NAME` (and a matching job-file key) to run
  `hooks.d/NAME` even when detection doesn't see the service.
- **Nextcloud:** a new hook. On pause, `occ maintenance:mode --on` (run as
  the web server user), then pause its database through the existing MySQL
  or PostgreSQL hook. On resume, `occ maintenance:mode --off`.
- **UniFi Network:** a new hook. The shipped `mongodb` hook stops a
  `mongod` unit, but UniFi runs its own embedded mongod (default port 27117)
  under the `unifi` service. On pause, `mongodump --port 27117` into
  `$RESTATE_DUMP_DIR`, then stop `unifi`; on resume, start it. Or document
  including UniFi's own autobackups (`/var/lib/unifi/backup/autobackup/*.unf`).
- **Mail:** confirm that a Maildir under `/var/vmail` (or wherever the
  server keeps it) is classified as state and copies safely without
  stopping. Add a hook only if a database (for example postfixadmin) needs
  one.
- Record each hook's outcome in the result (item 1). A failed pause must
  mark the run `incomplete`, not `ok`.

### 7. File-level restore by path

SysManage's most common restore will be "give me this directory back",
not "rebuild this host".

- Add positional path arguments or `--include PATTERN` to `restore` (only
  `--exclude` exists today), so `restore REPO::NAME --root /var/tmp/restore
  --include /home/bob/**` brings back one subtree.
- The `--dry-run` output for a path-limited restore should be available as
  JSON (`--result`), so SysManage can show the plan before it's applied.

### 8. A feature probe

Add `restate features --json`, listing version, supported commands, result
schema version, and available hooks. The agent then reports what this
host's restate can do, and the server never sends a job an older restate
can't run.

### 18. An append-only writer mode

SysManage's design rule is that a backed-up host can add snapshots but never
remove or rewrite one, so a compromised host cannot destroy its own history.

- Add a repository writer mode (for example `capture --append-only`, or a
  repository flag set at `init`) in which a capture only ever creates new
  files: new packs, new index files, new snapshot directories. It never
  deletes, renames over or rewrites an existing pack, index or snapshot, and
  never truncates.
- Make every write path compatible with directory permissions that forbid
  deleting or replacing files written earlier (for example a sticky,
  create-only directory on the target, or NAS-side immutable snapshots
  between runs), and say exactly which operations a capture still needs.
- A capture in this mode must not need the `lock` file to be rewritten in a
  way the storage side can't allow; document the locking it uses.
- `check` reports if anything in an append-only repository was removed or
  changed since the previous check.

### 19. Storage-side maintenance

Because hosts only append (item 18), `prune`, `check` (including
`--read-all`) and `copy` (item 11) run on the storage side: on the NAS's own
SysManage agent, against the repository directory locally.

- `prune` and metadata-only `check` must work on an encrypted repository
  without the private key, from the target's side, without the backed-up
  host's write cache.
- They must work on a repository written by a different machine: the
  target's restate reads a repository whose files are owned by the mapped
  `restate` user, with no assumption that the running host is the one
  captured.
- `check --read-all` on an encrypted repository needs the private key:
  document how it is supplied for one run (item 10), and otherwise report the
  check as metadata-only rather than as passed.
- Prune and copy results through `--result` (item 1).

---

## Should

### 9. Unattended signing for repository snapshots

A trusted machine (the NAS, or the SysManage server) signs snapshots after
they are written:

- `restate sign REPO::NAME --sign-with KEY`, or `REPO` alone for its newest,
  with `--passphrase-fd N` for a key with a passphrase.
- As a job: `command = sign`, with `repository`, `snapshot` (or none, for the
  newest), `sign_with` and `passphrase_file` -- the key files held to what
  `decrypt_with` is. Its result has `signed` (`REPO::NAME`) and `signer`.
  Run it before `protect`. `restate features` lists `sign` in
  `job_commands`.
- `snapshots` says of each snapshot whether it is signed and the key the
  signature names (`issuer`, unchecked); with `trusted_key`, whether it is
  good (`trusted`) and whose (`signer`, `signer_name`). The features flag is
  `snapshot_signer`.
- Restore already refuses unsigned or untrusted input (exit 4). SysManage
  will surface that as a clear "this snapshot is not signed" message rather
  than defaulting to `--allow-unverified`.

### 10. Encryption and restore keys

Captures need only the public key (`--encrypt-to`). Document, and expose in
the job file, how a restore gets the private key non-interactively, for
example from a file descriptor or a gpg agent socket, so SysManage can supply
it from OpenBAO for one restore without leaving it on disk.

### 11. Off-site copy without decrypting

Add `restate copy REPO::NAME DEST_REPO`, which copies a snapshot's packs and
index to a second repository, encrypted packs as they are. SysManage can then
keep a second copy off the NAS: an external disk, or a second site.

### 12. First-capture estimate

Add `capture --estimate` (or a size summary in `scan`): the bytes that
would be kept, per top-level directory. SysManage uses it to warn before a
first backup that won't fit on the NAS, and to suggest exclusions such as
Nextcloud preview caches.

### 13. Clones and SysManage agent identity

`/var/lib/sysmanage-agent/agent.db` is already classified as identity.
Document what `restore --as NAME` does with identity files. For a SysManage
host, a clone must not keep the original's agent database, or it would
connect as the original host. Ideally `--as` removes identity files, or
leaves them out, and says so in its result.

### 14. Man page

The BUGS section is out of date. It says the repository stores each file
whole, and that restore doesn't read the whole image first; both contradict
the FastCDC chunking and `--check-first`. Fix it before SysManage's docs
link to it.

### 20. A repository usage report

Add `restate du REPO --json` (or usage fields in `snapshots --json`): total
size on disk, size per snapshot, the bytes each snapshot alone keeps alive,
and the growth since the previous snapshot. SysManage uses it for capacity
forecasting, the per-host size on the Backups page, and usage metering
against a tenant's quota. It must be cheap: computed from pack indexes, not
by reading pack data.

---

## Later

### 15. Beyond dpkg

The SysManage fleet includes Fedora/RHEL/Rocky, openSUSE, Alpine, the BSDs
and macOS.

- Package-aware classification and inventories for rpm, zypper/rpm, apk,
  FreeBSD pkg and Open/NetBSD (already on this ROADMAP).
- Packaging beyond the PPA: rpm (COPR/OBS), FreeBSD port, OpenBSD port,
  NetBSD pkgsrc, Homebrew.
- Filesystem-snapshot quiescing (ZFS, btrfs, LVM snapshots), so large data
  directories can be captured from a consistent point in time without
  stopping services.

### 16. Bare-metal recovery hand-off

SysManage's provisioning engine can PXE-boot and autoinstall a machine.
Keep `autoinstall --image-at` and `buildsheet` output stable and documented
as a contract, so SysManage can use them for "rebuild this host from its
last snapshot" without scraping text.

### 17. A shared store across machines

Already listed under **Later**: a content-addressed store shared between
machines. For SysManage it would cut NAS usage for hosts that share large
identical content. Not needed for v3.12.0.0, since per-host repositories
are the starting point.

### 21. Tenant-safe shared store

When the shared store (item 17) arrives, its scope must be explicit. A store
shared between machines must never span tenants: shared chunks would tell
one tenant whether another holds a given file. Give each store an owner
label, refuse to attach a repository whose owner label differs, and keep
the keyed chunker per store, so equal content in two tenants' stores
produces different chunk ids.

### 22. An append-only gateway, so hosts never mount the storage

No restate change planned. SysManage ROADMAP Phase 25.5's append-only HTTPS
gateway is a project of its own, installed on the storage host; restate
keeps to local paths and has no network code, and the host side presents
the repository to it as a local path (FUSE, or a staging directory the agent
uploads from -- the gateway's design to settle). If that needs something
small of restate -- a hook, or a guarantee about how it writes packs --
it becomes an item here then.

---

## Suggested order

1. Items 1, 3, 4, 8: a structured result, the job file, the unit, and the
   feature probe. With these, SysManage can schedule and report.
2. Items 5, 18, 19: NFS, append-only writing and storage-side maintenance.
   Run the first real test against the NAS before relying on it.
3. Item 6: the Nextcloud and UniFi hooks, then the first three hosts
   (ubiquiti first: its drive shows 706 reallocated sectors).
4. Items 2 and 7: progress and file-level restore.
5. Items 9-14 and 20, then 15-17 and 21.
