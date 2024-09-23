# Setting up a Sigsum log server

This document describes how to setup and configure the individual
components needed for operating a log instance. See
[ansible](https://git.glasklar.is/sigsum/admin/ansible) for recipes
for more automated deployment.

## Installing server and dependencies

To install Sigsum tools and the log server, run

```
go install sigsum.org/sigsum-go/cmd/...@latest
go install sigsum.org/log-go/cmd/...@latest
```

If you're unfamiliar with `go install`, it will by default install
executables in `$GOBIN`, `$GOPATH/bin`, or `$HOME/go/bin`, depending
on which enviroment variables are set. You may want to add this
directory to $PATH.

The Sigsum server depends on a Trillian service and MariaDB. To install
Trillian, run

```
go install github.com/google/trillian/cmd/...@latest
```
For further information on Trillian, see [Introduction to
Trillian](https://www.rgdd.se/post/observations-from-a-trillian-play-date/)
and (https://github.com/google/trillian/blob/master/README.md). In
Trillian terminology, the Sigsum log server is a _Trillian
personality_.

To install MariaDB, on debian-based systems you may use a command like
```
apt-get install mariadb-server
```

## One-time database setup

To setup permissions on the database, run the
`mysql_secure_installation` script, with default answers to all
questions.

Next, to create the tables needed by Trillian, run the `resetdb.sh`
script, located in the `log-go/integration/` directory. It will also
use the `storage.sql` file (with table definitions) found in the same
directory. By default, the script creates a user and a table both
named "sigsum_test", password "zaphod". It can be configured via
environment variables, see comments in the script.

## Configuration file

The log server looks for a configuration file
`/etc/sigsum/config.toml`, to change the location, set the
`$SIGSUM_LOGSERVER_CONFIG` environment variable. See
[example](./config.toml.example).

## Starting Trillian

Trillian is usually two separate processes, which we refer to as
"Trillian server" and "Trillian sequencer". The sequencer is used only
on the primary log node.

To start the Trillian server,
```
trillian_log_server \
  -mysql_uri=sigsum_test:zaphod@tcp(127.0.0.1:3306)/sigsum_test \
  -rpc_endpoint=localhost:6962 \
  -http_endpoint=""
```

See Trillian documentation for further configuration, in particular,
the `-log_dir` option can be used to specify where it stores logs.  If
you rather get leveled logging output on stderr, use
`-logtostderr=false -stderrthreshold=WARNING` for WARNING and above.

To start the Trillian sequencer, on primary log node only, run
```
trillian_log_signer \
  -force_master \
  -mysql_uri=sigsum_test:zaphod@tcp(127.0.0.1:3306)/sigsum_test \
  -rpc_endpoint=localhost:6963 \
  -http_endpoint=""
```

## Creating the Trillian merkle trees

Primary and secondary nodes need different types of trees to be
configured in the respective database, using Trillian's `createtree`
command. On success, numerical id of the new tree is written on
standard output. The log server needs that number stored in a file
containing a line `tree_id=...`. That file should be passed on a
`trillian-tree-id-file=...` line in the log's config file.

On the primary node, with the above configuration, the tree and the tree-id
file can be created using
```
(
  id=$(createtree -admin_server=localhost:6962) && echo tree_id=${id}
) | tee primary-tree-id
```
On the secondary node, instead run
```
(
  id=$(createtree -admin_server=localhost:6962 -tree_type PREORDERED_LOG) &&
  echo tree_id=${id}
) | tee secondary-tree-id
```
The `PREORDERED_LOG` type means that entries already have indices (and
hence order) assigned when passed to Trillian, which is needed because
the secondary node replicates the tree at the primary node, and it's
the primary node that determines the order of entries. That is also why
the secondary node doesn't need a Trillian sequencer.

## Primary node

### Key management

The primary node needs its own signing key pair. This can be an
unencrypted private key file, generated using `sigsum-key gen -o KEY`
(which generates a new keypair, stores the unencrypted private key in
the file `KEY` and corresponding public key in `KEY.pub`). This uses
openssh keyfile formats, and is equivalent to `ssh-keygen -q -N '' -t
ed25519 -f KEY`.

Alternatively, the server can access the private key via the ssh-agent
protocol. Using an agent is particularly useful for hardware keys, but
it can also help reducing the attack surface when using a key file on
disk, e.g., to give the server uid access to a signing oracle, without
giving it direct access to the private key file.

To enable failover to a secondary node in case of catastrophic failure
of the primary node, the private key must be securely backed up
elsewhere.

The [key-mgmt
documentation](https://git.glasklar.is/sigsum/core/key-mgmt/-/blob/main/docs/key-management.md)
describes one way to provision and back up private log keys using
YubiHSM hardware. The [same
repository](https://git.glasklar.is/sigsum/core/key-mgmt) also hosts
`sigsum-agent`, a signing oracle that speaks the ssh-agent protocol,
and which supports both YubiHSM keys and keys on disk.

### Configuration

The most important settings in the config file for the primary server
are:

1. `external-endpoint`: ip-address:port for log clients to connect to.

2. `internal-endpoint`: ip-address:port for secondary node to connect
   to.

3. `trillian-rpc-server=localhost:6962`: ip-address:port where the Trillian
   server responds to gRPC requests.

4. `trillian-tree-id-file`: file recording the number produced by `createtree`.

5. `key-file`: identifies the log's signing key. Either the name of the
   private key file, or the name of a public key file, in case
   the corresponding private key is accessible via ssh-agent.

6. `secondary-url`: base url to the secondary node's internal
   endpoint.

7. `secondary-pubkey-file`: public key for verifying the secondary's
   signatures.

8. `sth-file`: name of the file where the latest signed tree head is
   stored, by default, `/var/lib/sigsum-log/sth`.

Before starting the primary the first time, we need to tell it to
start out by signing and publishing a tree head corresponding to the
empty tree. To do this, run the command `sigsum-mktree`; this reads
the `sth-file=` entry in the config file and creates a special startup
file next to that file. E.g., with the default location
`/var/lib/sigsum-log/sth`, the startup file is
`/var/lib/sigsum-log/sth.startup`. The startup file is automatically
deleted after use, and it is an error if both files exist.

The primary server executable is `sigsum-log-primary`.

## Secondary node

The secondary node needs its own signing key pair, it is used only to sign
responses to the primary server, so usually no need to back it up; it
can be rotated at will by reconfiguring and restarting the primary
node with the secondary's new key.

Configuration of `external-endpoint` (which returns HTTP 404 for
everything), `internal-endpoint`, `trillian-rpc-server`,
`trillian-tree-id-file`, and `key-file` is analogous to the primary
configuration. In addition, the secondary should be configured with:

1. `primary-url`: base url for the primary node's internal endpoint.

The secondary server executable is `sigsum-log-secondary`.
