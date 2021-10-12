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

- Base URL: https://poc.sigsum.org/ghost-shrimp/
- Public key: `90b4db54ca093f4ccf68e8ae12a3c250bc4fbc396c96d42c42a613a62bffe279`
- Shard interval: [1632441600, 1636329599], i.e., 24th September--7th November, 2021.

A [witness](https://github.com/sigsum/sigsum-witness-py) is also up and running
with zero-promises of uptime, stability, etc.  Relevant witness information:

- Public key: `812dbef0156b079e2d048747b2189cbfa64f96e2204a17cb23cb528080871503`.

As described in our design and API documentation, you can talk to the log by
passing ASCII key-value pairs.  For example, fetch a cosigned tree head and a
log entry:
```
$ curl https://poc.sigsum.org/ghost-shrimp/sigsum/v0/get-tree-head-cosigned
timestamp=1634033236
tree_size=2
root_hash=1c4632f71d0f77f386231de4fa8df532961588a38333a30351eafc9e8b488b47
signature=dbe338a3d9eb0e8d1fc3b80ffb17dfeac9c8fc6d33a87506469ac80b2d397fa3f2fc9803d3a4b24913914cf7fdda9a281f060cf9aeb9aa2855f7d8872fa5ca03
key_hash=15e203ad786ad5e36c053ba883d09ad7dc6b2011bb9c111330f79c8f1d6b8e69
cosignature=f2f6e7b58b11f65e232bb1a3a24a2af9566749039e22fe253f49957cb5da7e15b3dd2ca8e748c665af7b79ccca43f3a9a3a9f7da1892c2ff5baee671ecc8bd0c
$
$ printf "start_size=0\nend_size=0\n" | curl --data-binary @- https://poc.sigsum.org/ghost-shrimp/sigsum/v0/get-leaves
shard_hint=1636329599
checksum=59aca44e7dc5d5cf49908cc8305216bf9625aa08cbd3c3ed544e6b6169cf0779
signature=1549532a06bca6eec832558d0e853375a95b87f585eeee2f320185efc37a33a447c4be8a9a37e0f89e7cb2525272eb09ea2c6a045e732421cf52fd3c294cf50c
key_hash=9a95dd85f3f92ecf5aabd9a13a12363a16e3d5711445d1939b18409346381682
```

Go tooling that makes it easier to interact with sigsum logs will appear in a
separate repository in the near future, see
	[sigsum-lib-go](https://git.sigsum.org/sigsum-lib-go/).
