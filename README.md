# Sigsum log-go

This repository provides a Sigsum log server, implementing the the
[sigsum
protocols](https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md).
The log server provides replication between a primary and a secondary
node, and it interacts with configured witnesses to collect
cosignatures. [Trillian](https://transparency.dev/#trillian) and
[MariaDB](https://mariadb.org/) are used for backing storage on each
node.

## Server docs

See [docs](./doc/readme.md) for information on how to setup and
configure a Sigsum log instance.

## Public prototype
There is a public prototype running with zero promises of uptime,
stability, etc.  Relevant log information:

- Log URL: https://poc.sigsum.org/jellyfish
- Public key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBVPSZdrWf8JoSNnX1jLPjRuBFV1PDw7FdRl3LT2USsL`

See [services](https://www.sigsum.org/services/) for information about
this log and related services.

As described in the design and API documentation, you can talk to the
log by sending it ASCII key-value pairs. For example, fetching a
signed (and possibly cosigned) tree head and a few entries:

```
$ curl https://poc.sigsum.org/jellyfish/get-tree-head
size=1291
root_hash=2b06e738e93ad2e8b9e1c8ae86b762cb20f16b0bda4ce3e40680d412b9cae5ea
signature=5e91a847fb088341b26dc217c46878cd0bd1b9b576ce7d9d5f0fa781b1b139488bebc1883748c2c731aab546ee37ffcfa5823a37e55a8b5e501390235fcab00f
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1697784602 cb584f52b8c65e3eab6a7b0f17eca82ab8cfb766a46f7f26b76c2dc7a0a750ee8bd971dad7101cdebfdd786affd82582b4c42d41ff185d01f2cf756fbce0ef07
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1697784602 23b808cec68b1d6a9860bf1a4dc8de41d32d8105886e8f45170a49acaa046effd630cccf61235aa12b889bf3ed04002069d10bdf1041f99a6a7e09b42785b50c

$ curl https://poc.sigsum.org/jellyfish/get-leaves/10/12
leaf=3c14dfb28e7ed39442fe6376feb9f98b5f97a41ccf024dd2c6f38640c699a66c a8140f22aabfd2684635a8c266b557f3a06f958b8cd051605ed17648fb4949ff0922c0a73045c90e4baddf7033ba2a34b5841221ac7067918aada94553f0f104 4f313845ab7b7bc4592e437869e838fcccef45b402bd970f8aa2628ec17ef5cf
leaf=1507de45cbe91d7192063c7c143b9d07aa52ac4a47c278d728dd9c9e86c834f3 315ee5e2eb5a7d3a573760e612f76337a1a445fa1c117cf9bf94d0dc327d15f0feee0f67ba679d74cb08cb4748793aa09576f5496abf831a4c1105925c635404 4f313845ab7b7bc4592e437869e838fcccef45b402bd970f8aa2628ec17ef5cf
```

Tools for interacting with sigsum logs are maintained separately, see
[sigsum-go](https://git.glasklar.is/sigsum/core/sigsum-go/).


## Development

### Integration tests

There's an integration test script in `integration/test.sh`, see
[docs](./integration/README.md) for details.
