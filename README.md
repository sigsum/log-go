# sigsum-log-go
This repository provides a
	[Trillian](https://transparency.dev/#trillian)
	[personality](https://github.com/google/trillian/blob/master/docs/Personalities.md)
that implements the sigsum/v0
	[design](https://git.sigsum.org/sigsum/tree/doc/design.md)
and
	[API](https://git.sigsum.org/sigsum/tree/doc/api.md).

## Public prototype
There is a public prototype that is up and running with zero promises of uptime,
stability, etc.  Relevant log information:

- Base URL: https://poc.sigsum.org/glass-frog/
- Public key: `16589cb2dfb3e7f374bf307d33e4751bc0dfd2f5612e1609e7aeb479fa23a0c5`
- Shard start: 1638780441 (Mon Dec 6 08:47:21 AM UTC 2021)

A [witness](https://github.com/sigsum/sigsum-witness-py) is also up and running
with zero-promises of uptime, stability, etc.  Relevant witness information:

- Public key: `812dbef0156b079e2d048747b2189cbfa64f96e2204a17cb23cb528080871503`.

As described in our design and API documentation, you can talk to the log by
passing ASCII key-value pairs.  For example, fetch a cosigned tree head and a
log entry:
```
$ curl https://poc.sigsum.org/glass-frog/sigsum/v0/get-tree-head-cosigned
timestamp=1638833163
tree_size=28
root_hash=794349f5b8a9967ba7e6b4bc4737f0ef3ffea08ab5ed2ab6a78bb4ddbdf0f91d
signature=1cdccd80b5b07922dadcaa6dd7ab1ee9054df0e0d52897901149bd15cab979ba1c17a111a85cfc7c77130492ecb166605227fd23ff7a5396f9ef72d64232ad00
key_hash=15e203ad786ad5e36c053ba883d09ad7dc6b2011bb9c111330f79c8f1d6b8e69
cosignature=70e93519bdb609c37caa821a738ab41a02613b6441e8c6a0201af05c08a332fea292f8454d3a600897802275982ad09f3fa91ac8d434aca5cca763c757dffa0b
$
$ printf "start_size=0\nend_size=0\n" | curl --data-binary @- https://poc.sigsum.org/glass-frog/sigsum/v0/get-leaves
shard_hint=1638780441
checksum=1d3337e06d2dfbd652a1b575880cabb65b3d35c6dda7078ebffdaaea5a450494
signature=2da5ff9ce3def370b1139ce34ccf064e0fe5d8a46df1e832ba47a536e9a098fdfedc00a4d1e99832043883ff2e91472f8998320243b071eccbee093bf04c9002
key_hash=33041122596cafbd785679498967695f6b68113cac6e969aa2574302057bb5ec
```

Go tooling that makes it easier to interact with sigsum logs will appear in a
separate repository in the near future, see
	[sigsum-lib-go](https://git.sigsum.org/sigsum-lib-go/).
