# Running restate-proxy

How to put repositories behind `restate-proxy` and reach them from the
machines that back up into them: choosing it or a file share, granting
clients, the certificate, and a way in from outside through a firewall. What
the proxy says on the wire, and every option and key in full, are in
[proxy-protocol.md](proxy-protocol.md) and `restate-proxy(8)`; installing it
is in the README's [Installing restate-proxy](../README.md#installing-restate-proxy).

The examples use a storage host at `192.168.1.10` on the LAN, reached from
outside as `backup.example.com`, and a client `web01`.

## NFS or the proxy

A repository can be a directory each machine mounts over NFS or SMB, or a
URL, `https://backup.example.com:8443/v1/web01`, that restate reaches through
the proxy. restate does the same with either -- capture, restore, check,
diff, copy -- and the repository on the storage host is the same directory;
a machine can even change from one to the other.

|                                   | NFS or SMB                                  | restate-proxy                                  |
|-----------------------------------|---------------------------------------------|------------------------------------------------|
| A machine that has been taken over | has the share: it can remove or change what is there, unless the storage host runs `restate protect` after each capture and keeps its own snapshots | can add snapshots, and read what its grant allows; nothing it sends can remove or change anything, and it reaches only its own repository |
| Across what                        | a network you trust: NFS with `sec=sys` has no login and no encryption | anywhere: TLS, and a token for each machine |
| What each machine needs            | the share mounted, and locks that work over it | `curl`, a token file, and the proxy's certificate trusted |
| What the storage host needs        | the export, and the locks set up (`vfs.nfsd.enable_locallocks=1` on FreeBSD) | `restate-proxy`, a certificate and a grant for each machine |
| Speed                              | the disk's and the network's                | the same: an incremental of 45 MiB took 11.2 s through the proxy and 11.0 s over NFS into the same repository |
| What runs only on the storage host | `protect`; everything else can run anywhere | `prune`, `repack`, `protect`, `sign` on a snapshot already there, and making the repository (`init`, `capture --create`) |

The proxy is the safer default for any machine you would not hand the whole
share to, and the only one for a machine outside your network. NFS is fine
where the machines and the storage are one administrator's on one LAN, and
the storage host protects each repository after each capture.

Encrypt either way (`capture --encrypt-to`): the storage host, and anyone
who reaches its disks, then sees only packs it cannot read. The proxy needs
no key to serve, check or prune an encrypted repository.

## Setting it up

On the storage host, a repository for each client, the proxy's user's to
write:

```bash
sudo restate init /srv/restate/web01        # or --encrypt-to KEY, as for any repository
sudo chown -R restate-proxy:restate-proxy /srv/restate/web01
```

A token for the client, and its grant. The token file goes to the client;
only its digest stays here:

```bash
sudo restate-proxy --new-token /root/web01.token
# prints: token_sha256 = 1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd
```

```ini
# /etc/restate/proxy.d/web01.conf
repository   = /srv/restate/web01
operations   = append, read
token_sha256 = 1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd
```

Then the certificate (below), and the service:

```bash
sudo restate-proxy --check-grants
sudo systemctl enable --now restate-proxy
```

On the client, the token in a file only root can read, and a job:

```bash
sudo install -m 0600 -o root -g root web01.token /etc/restate/proxy.token
```

```ini
# /etc/restate/jobs.d/nightly.conf
command               = capture
repository            = https://backup.example.com:8443/v1/web01
repository_token_file = /etc/restate/proxy.token
encrypt_to            = /etc/restate/keys/backup.asc
result                = /var/lib/restate/nightly.json
```

`restate run /etc/restate/jobs.d/nightly.conf` captures through the proxy;
`restate snapshots --repository-token-file /etc/restate/proxy.token
https://backup.example.com:8443/v1/web01` lists what is there. A capture
through the proxy is always append-only, so the job needs no `append_only`,
and cannot have `create`: the repository is made on the storage host.

Pruning, checking and copying off-site go on on the storage host, against
the directory, as for any repository there; run as root, restate gives what
it makes there the directory's owner, so the proxy can still write it:

```bash
sudo restate prune --whole-packs --keep-daily 14 --keep-weekly 8 /srv/restate/web01
sudo restate check --metadata-only /srv/restate/web01
```

## The allow list

A client's grant is its file in `/etc/restate/proxy.d`, `CLIENT.conf`, and a
client with no good grant only ever sees `401`. The proxy reads the
directory again within a few seconds of a change, and on `SIGHUP`
(`systemctl reload restate-proxy`), so nothing needs a restart.

- **Writing one.** Write it beside its name and rename it into place --
  `.web01.conf.tmp`, then `web01.conf` -- so the proxy never reads one half
  written; it reads only names ending in `.conf` that do not begin with a
  dot. It, and the directory, have to be root's or the proxy's user's, and
  writable by no one else, or it is not read at all.
- **Checking.** `restate-proxy --check-grants` reads every grant as the
  proxy would and says what is wrong with each (`--json` for a program); it
  exits 2 if one is not good. The proxy's log says the same as it reads
  them: `grant-refused file=... error="..."`.
- **What it may do.** `operations = append` is what a machine that only
  captures needs: it can add snapshots and read the indexes an incremental
  capture reads, but never a pack's content. Add `read` for a machine that
  restores from it too.
- **Changing its token.** Add the new token's `token_sha256` line beside the
  old one, give the client the new token, and remove the old line: no run
  fails in between.
- **One restore, and no more.** A grant of its own with `operations = read`
  and `expires = 2026-12-01T00:00:00Z` gives a machine being rebuilt, or a
  colleague, what it needs for one restore, and nothing after.
- **Limits.** `max_sessions` holds the client to that many sessions at once
  (a run of restate holds one), and `bandwidth` to a rate by the hour of the
  storage host's day: `bandwidth = 08-18 2MiB/s` keeps a capture that runs
  late out of the working day's link, `bandwidth = 20MiB/s` is the rest.
  A host that stores for others can hold each to a quota with
  `--quota-hook` ([proxy-protocol.md](proxy-protocol.md#the-quota-hook)).
- **Grants a program manages.** `label` is free text the proxy ignores: a
  program that writes grants marks its own with it, so that it removes only
  the ones it wrote.

## The certificate

The proxy's certificate has to name the host in the URL its clients use --
`backup.example.com` -- and, through a firewall that passes TLS through (as
below), it is the proxy's, on the storage host: nothing in between decrypts
anything. `--cert` is the chain in PEM, the proxy's own certificate first
(`/etc/restate/proxy.crt`), and `--key` its private key, unencrypted
(`/etc/restate/proxy.key`), root's, group `restate-proxy`, mode 0640. Both
are read once, as the proxy starts: a new one takes `systemctl restart
restate-proxy`, which ends every session open -- a capture running then
fails, and runs again as its job does -- so renew outside the backup window.

**Let's Encrypt, for a public name.** Clients need nothing: the systems'
certificate authorities trust it. Since the proxy holds the certificate, it
is requested on the storage host, and since that host is not on port 80
from outside, by the DNS challenge, from certbot with your DNS provider's
plugin or from acme.sh. A deploy hook puts each renewal in place:

```bash
#!/bin/sh
# /etc/letsencrypt/renewal-hooks/deploy/restate-proxy
install -m 0640 -o root -g restate-proxy "$RENEWED_LINEAGE/fullchain.pem" /etc/restate/proxy.crt
install -m 0640 -o root -g restate-proxy "$RENEWED_LINEAGE/privkey.pem" /etc/restate/proxy.key
systemctl restart restate-proxy
```

**A site's own certificate authority, for a private name.** The clients
trust it for the proxy alone, not for the whole machine, with
`repository_ca_file` (`--repository-ca-file`), a PEM file of the authorities
to trust in place of the system's:

```bash
# once, kept off the storage host: the authority
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=Example backup CA" -keyout site-ca.key -out site-ca.pem
# the proxy's, signed by it
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=backup.example.com \
  -keyout proxy.key -out proxy.csr
openssl x509 -req -in proxy.csr -CA site-ca.pem -CAkey site-ca.key -days 825 \
  -extfile <(printf 'subjectAltName=DNS:backup.example.com\n') -out proxy.crt
```

```ini
# in the client's job
repository_ca_file = /etc/restate/site-ca.pem
```

**Its key, pinned.** `repository_pin_sha256` (`--repository-pin-sha256`)
holds a client to the proxy's own key, whoever signed its certificate --
the base64 SHA-256 of its public key:

```bash
openssl x509 -in /etc/restate/proxy.crt -pubkey -noout | openssl pkey -pubin -outform der |
  openssl dgst -sha256 -binary | openssl enc -base64
```

Given twice, either is accepted, so a key can be replaced without a run
failing in between: pin the next key beside the current one first. A Let's
Encrypt renewal makes a new key unless it is told to keep it (certbot's
`--reuse-key`), so pin one only with that.

## From outside, through a firewall

The proxy listens on one port (8443 unless `--listen` says another). A
machine outside reaches it through the firewall at the edge of the storage
host's network -- forwarded to it, or, where the firewall serves other names
on the same address and port, routed to it by the name the client asks for.
Either way the firewall passes the TLS connection through as it is: it
never holds the proxy's certificate, never sees a token, and the proxy's
confinement and its checks of each token are what stand between the
internet and the repositories.

### pfSense: HAProxy, routing by SNI in TCP mode

pfSense's HAProxy package, in TCP mode, reads the name in the TLS
ClientHello (SNI) and sends the connection to the backend for that name,
without decrypting it. These settings send `backup.example.com` on the WAN
address's port 8443 to the storage host at `192.168.1.10:8443`.

**The backend** (Services > HAProxy > Backend), `restate_proxy`:

| Setting                | Value                                                     |
|------------------------|-----------------------------------------------------------|
| Server list            | Mode `active`, Name `nas`, Forward to `Address+Port`, Address `192.168.1.10`, Port `8443`, Encrypt(SSL) `no`, SSL checks `no` |
| Server timeout         | `120000`                                                  |
| Health check method    | `Basic`, with Check frequency left empty                  |
| Transparent ClientIP   | off                                                       |

**The frontend** (Services > HAProxy > Frontend), `Backup`:

| Setting               | Value                                                       |
|-----------------------|-------------------------------------------------------------|
| Status                | Active                                                      |
| External address      | Listen address `WAN address (IPv4)`, Port `8443`, SSL Offloading off |
| Type                  | `ssl / https(TCP mode)`                                     |
| Access control lists  | Name `backup`, Expression `Server Name Indication TLS extension matches`, Value `backup.example.com` |
| Actions               | `Use Backend`, backend `restate_proxy`, Condition acl names `backup` |
| Default backend       | `None`                                                      |
| Client timeout        | `120000`                                                    |

**A firewall rule** (Firewall > Rules > WAN): pass, TCP, destination `WAN
address`, port `8443`. No port forward is needed, since HAProxy listens on
the WAN address itself; and where the clients' addresses are known, a source
limited to them keeps everyone else from reaching the proxy at all.

**The name**, `backup.example.com`, resolves to the WAN address outside.
Inside, a host override in pfSense's DNS Resolver (Services > DNS Resolver >
Host Overrides) resolves it to `192.168.1.10`, so the machines on the LAN
reach the proxy directly, with the same URL and the same certificate.

What matters, and why:

- **TCP mode, SSL Offloading off, Encrypt(SSL) off.** HAProxy passes the
  bytes through; offloading would put the certificate and key on the
  firewall and decrypt every capture there.
- **The SNI has to have arrived before the ACL is looked at.** In TCP mode,
  HAProxy matches the name only once it has the ClientHello, which takes
  these two lines in the frontend:

  ```
  tcp-request inspect-delay 5s
  tcp-request content accept if { req_ssl_hello_type 1 }
  ```

  Look for them in the configuration pfSense writes (Diagnostics > Command
  Prompt: `cat /var/etc/haproxy/haproxy.cfg`); if the frontend has none,
  paste them into its Advanced pass thru. Without them, a connection whose
  ClientHello is late matches no ACL, finds no backend, and is closed.
- **Timeouts longer than the proxy's.** HAProxy's client and server
  timeouts end a connection idle that long; the proxy ends its own after
  `--idle-timeout` (60 s), and a large snapshot's commit can be that long
  in the proxy with nothing sent either way. 120 s leaves both to the proxy.
  HAProxy's default, 30 s, can cut one off.
- **No health check, or a slow one.** With Basic and no frequency, TCP mode
  checks nothing. Each check is a connection that opens and closes without
  TLS, which the proxy logs as `tls-refused`: if you want one, make it every
  minute or so.
- **The client's address.** Every connection from outside reaches the proxy
  from pfSense's LAN address, and the proxy logs that as each request's
  `peer`; which client it was is in the same line, as `client=`, from its
  token. restate-proxy does not take the PROXY protocol, so `send-proxy` on
  the server line breaks every connection. Transparent ClientIP shows the
  real address, at the cost the package warns of: HAProxy then runs as root.
- **Other names on the same address.** The frontend can be a Shared
  Frontend on 443 with the firewall's other sites -- one ACL and one action
  each -- and the clients' URL then `https://backup.example.com/v1/web01`.

From a machine outside, `restate snapshots --repository-token-file
/etc/restate/proxy.token https://backup.example.com:8443/v1/web01` lists the
client's snapshots; `401` means the proxy answered and refused the token, and
"the proxy did not answer" means the connection never got there -- the
firewall rule, the ACL's name, or the name's address.

## What crosses the network

restate itself opens no network connection, through the proxy or not. For a
repository behind the proxy, it runs `curl`, as `installer fetch` and
`baseline fetch` do, to the URL's host and nowhere else: HTTPS only, the
token given in a curl config file only the user running restate can read
(`-K`), never on a command line, the proxy's certificate checked against the system's
authorities, or `repository_ca_file`'s, and its key against
`repository_pin_sha256` where one is given. What it sends is the repository's
files -- packs, indexes and snapshots, encrypted if the repository is -- and
the session's requests; it reads the proxy's answers from the headers curl
writes. No library is linked for it.
