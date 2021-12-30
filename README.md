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

- Base URL: https://poc.sigsum.org/glasswing-butterfly/
- Public key: `4ab3d2b51e47dc9de4cce4bdeba9e08622e93a2f7f89b4cb77197fc6b0044de7`
- Shard start: 1639579652 (Wed 15 Dec 2021 02:47:32 PM UTC)

A [witness](https://github.com/sigsum/sigsum-witness-py) is also up and running
with zero-promises of uptime, stability, etc.  Relevant witness information:

- Public key: `812dbef0156b079e2d048747b2189cbfa64f96e2204a17cb23cb528080871503`.

As described in our design and API documentation, you can talk to the log by
passing ASCII key-value pairs.  For example, fetch a cosigned tree head and a
log entry:
```
$ curl https://poc.sigsum.org/glasswing-butterfly/sigsum/v0/get-tree-head-cosigned
timestamp=1640879637
tree_size=8
root_hash=a2e1944b7a49c74e96919d0655209b201a0a50e3172c595e1115d09b5aec675c
signature=5ae00b5a0e9d579e70e1dc9800b5f1c84746b40f039bc2879622cb5bba0c2a5314f69c7819a55de1737ff85f5dac8371530eef54376ab8fc7034af8e08164909
cosignature=5b0c80e701b65bf1cf895f14a4c60691d067cf65a869f8da9368d83ac9add5d29b764a40401072b328dafdc29950f4e4835e1c2d268c86b2d8c59b75ce24220f
key_hash=15e203ad786ad5e36c053ba883d09ad7dc6b2011bb9c111330f79c8f1d6b8e69
$
$ printf "start_size=0\nend_size=0\n" | curl --data-binary @- https://poc.sigsum.org/glasswing-butterfly/sigsum/v0/get-leaves
shard_hint=1640878226
checksum=7971968263fc030a12e33d49713c7def60a0ca6a90af03944e644f9349ac3476
signature=01ffc2105507dd703de0e4e2fc03f9364a1b1a36cf0fa09a609bf6cc037d4bc3fe48b234aa48213c4c2646389c220bc171b7936d16bbfcece6610a8648a77807
key_hash=9a95dd85f3f92ecf5aabd9a13a12363a16e3d5711445d1939b18409346381682
```

Go tooling that makes it easier to interact with sigsum logs will appear in a
separate repository in the near future, see
	[sigsum-lib-go](https://git.sigsum.org/sigsum-lib-go/).
