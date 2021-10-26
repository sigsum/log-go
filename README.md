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

- Base URL: https://poc.sigsum.org/barreleye-fish/
- Public key: `f38f0f0f2c50e2166e8b9522694672e0d7bc016c62d7927cb38e815dc373c824`
- Shard interval: [1635120000, 1638921599], i.e., 25 October--8 December, 2021.

A [witness](https://github.com/sigsum/sigsum-witness-py) is also up and running
with zero-promises of uptime, stability, etc.  Relevant witness information:

- Public key: `812dbef0156b079e2d048747b2189cbfa64f96e2204a17cb23cb528080871503`.

As described in our design and API documentation, you can talk to the log by
passing ASCII key-value pairs.  For example, fetch a cosigned tree head and a
log entry:
```
$ curl https://poc.sigsum.org/barreleye-fish/sigsum/v0/get-tree-head-cosigned
timestamp=1635267692
tree_size=5
root_hash=ea62a8332e068d14605d8c84a6e98b53a8ce98725866c3196f4dd47dd39ba067
signature=2a347032481e09472f83886570ca4654d0e7d79f15d5d234cc5e65e4bdb5e9f9fb5f8487434314a2c6ebc98ceb4cd4430e322e3a5f3564db4d52496e99b67f02
key_hash=15e203ad786ad5e36c053ba883d09ad7dc6b2011bb9c111330f79c8f1d6b8e69
cosignature=1a1e10e23156f2dd84a0684edd472e07fa8c1509700ebcfc18bd7142a66f898f42a0a8bf906859a1f87aeca1e98b4204af298e2a26f77e1385a23f71d89a7908
$
$ printf "start_size=0\nend_size=0\n" | curl --data-binary @- https://poc.sigsum.org/barreleye-fish/sigsum/v0/get-leaves
shard_hint=1638921599
checksum=febf79a761074dbc2d2f70652d8756af566044875bd5ab08602085efd147313f
signature=cec25c767ed0ce25ff26883ec9de0fce5d0b474e9f27b5f2b34225ace111836d5bdae1ed2c53f77d8c89155db96302ef782943f69a8e4f29569527ed1e0ee00d
key_hash=9a95dd85f3f92ecf5aabd9a13a12363a16e3d5711445d1939b18409346381682
```

Go tooling that makes it easier to interact with sigsum logs will appear in a
separate repository in the near future, see
	[sigsum-lib-go](https://git.sigsum.org/sigsum-lib-go/).
