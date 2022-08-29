# Sigsum log-go
This repository provides a
	[Trillian](https://transparency.dev/#trillian)
	[personality](https://github.com/google/trillian/blob/master/docs/Personalities.md)
implementing the sigsum/v0
	[design](https://git.sigsum.org/sigsum/tree/doc/design.md)
and
	[API](https://git.sigsum.org/sigsum/tree/doc/api.md).

## Public prototype
There is a public prototype running with zero promises of uptime,
stability, etc.  Relevant log information:

- Base URL: https://ghost-shrimp.sigsum.org/
- Public key: `e65f8bff3a5cfe1781b094ebcf41d6a6d0e254c0de5144373719e64099fbb343`
- Shard start: 1656173139 (Sat 25 Jun 2022 04:05:39 PM UTC)

Two [witnesses](https://github.com/sigsum/sigsum-witness-py) are running as well,
this too with zero promises of uptime, stability, etc.  Relevant witness information:

- Public key: `812dbef0156b079e2d048747b2189cbfa64f96e2204a17cb23cb528080871503`
- Public key: `8c343bffe33a5889b5f350dc162bbdfec3b29e2c498475ccdf969a2743be0291`

As described in the design and API documentation, you can talk to the
log by sending it ASCII key-value pairs.  For example, fetching a cosigned
tree head and two log entries:

```
$ curl https://ghost-shrimp.sigsum.org/sigsum/v0/get-tree-head-cosigned
timestamp=1656448119
tree_size=77
root_hash=e2382a44b83dd21403d9989fc6b1438a1043e1acb791e5630f45706e3e5ac466
signature=be19395e1914c67c7e2a49303c672675ff6a2365ead7dc0751e109923174c53c81b5fb56d1446c6e43c0ba68c88160b243e75fc6fd1e66aedbfae14165786a0a
cosignature=96faf7c119c895445c90c028caa0c287385d3c9e0d24672b0d499fc71e7ec4cad2bd6d242c66ff7ba9362161110933c397e6eadf48722be35c6f22e9c0a18605
key_hash=15e203ad786ad5e36c053ba883d09ad7dc6b2011bb9c111330f79c8f1d6b8e69

$ curl https://ghost-shrimp.sigsum.org/sigsum/v0/get-leaves/0/1
shard_hint=1656251476
checksum=c87b1ea095861174ef52ed7281eaf44fc237671f3fd61803a3cea3c98b9e81fe
signature=b32cad0ce5f1593250ce863ec3c039275db21b63bcae09aa905e348409ff97283b6f76efd9d87f4945a9b7d550ba480746f7aa08011f2217b7ed100159c87007
key_hash=d96934d633dca1ef8913a5421338ff371d07279f4b0b787b13c338f3520194e4
shard_hint=1656251511
checksum=471f5f5accbae3f550e0478a5bf32a272f107c9609380c15ddade128c8595681
signature=8745e005d0330c836e0f1137167697b324cb6765996a97ee53273f997c12259b2e7ab3d48aeb566c589230ece505ac392eb57629edcb7f0f26ee4eb18c1a620f
key_hash=d96934d633dca1ef8913a5421338ff371d07279f4b0b787b13c338f3520194e4
```

Go tooling that makes it easier to interact with sigsum logs will appear in a
separate repository in the near future, see
	[sigsum-go](https://gitlab.sigsum.org/sigsum/core/sigsum-go/).

## Development

### Integration tests

There's an integration test script in `integration/test.sh`. To run it, setup
the prerequisites described bellow, then start the script from the
`integration/` directory:

```
$ cd integration
$ ./test.sh
```

#### Install dependencies

```
# Install Sigsum server
go install ./cmd/...
# Install sigsum-debug
go install git.sigsum.org/sigsum-go/cmd/sigsum-debug
# Install Trillian
go install github.com/google/trillian/cmd/{trillian_log_signer,trillian_log_server,createtree,deletetree,updatetree}
```


#### MariaDB server

While the integration test will start all the other components it expects to
find a mariadb server running on localhost on port 3306. On this server, there
should be an existing database named `test`, initiallized with Trillian's
[`storage.sql`](https://github.com/google/trillian/blob/master/storage/mysql/schema/storage.sql),
and a user with username `test` and password `zaphod` that can acees this
database.

#### Client config

Use `sigsum-debug` to generate a private key:

```
$ sigsum-debug key private
5f0af480f639e8cb7a52d62f6aa301ef69db585a1db8df93f404e06b15fbbebc
```

Compute the keyhash associated to this new private key:
```
echo 5f0af480f639e8cb7a52d62f6aa301ef69db585a1db8df93f404e06b15fbbebc | sigsum-debug key public | sigsum-debug key hash
657237c6570e11001fd18529e44832368f86a34f6cd32b11a7f0237ffa7bfa68
```

Choose a domain hint that starts with "_sigsum_v0." (e.g.
`_sigsum_v0.example.com`) and add a `TXT` record for this domain that contains
the keyhash.

Create a file `integration/config/client.conf` with the private key and domain
name, e.g.:

```
cli_priv=5f0af480f639e8cb7a52d62f6aa301ef69db585a1db8df93f404e06b15fbbebc
cli_domain_hint=_sigsum_v0.example.com
```
