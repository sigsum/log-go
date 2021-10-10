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
- Base URL: https://poc.sigsum.org
- Public key: `bc9308dab23781b8a13d59a9e67bc1b8c1585550e72956525a20e479b1f74404`
- Shard interval: [X, Y]

A [witness](https://github.com/sigsum/sigsum-witness-py) is also up and running
with zero-promises of uptime, stability, etc.  Relevant witness information:
- Public key: `777528f5fd96f95713b8c2bb48bce2c83628e39ad3bfbd95bc0045b143fe5c34`.

As described in our design and API documentation, you can talk to the log by
passing ASCII key-value pairs.  For example, fetch a cosigned tree head and a
log entry:
```
$ curl https://poc.sigsum.org/sigsum/v0/get-tree-head-cosigned
timestamp=1633888287
tree_size=17
root_hash=51ce7e8e7fa98d48ab84750ae9dcbabda268fbcca74ab907836a35a513396f9d
signature=9c1c5ffab45e6bc6120c060b47520688659e7ad581b7db1f591442b9498fbaff7bd6a34d874a2809c71fb0996c7b71998a092f80ebd2dd5c9d3e21c5cf2f880d
key_hash=35c1364f52d2de9e8b002e6b1c0b376da5ccef65442654eb51d76e7aa2d22d74
cosignature=2e058af6b6c26b470d1921e848b3479b1893417eed8215aa1eeb2dc089487fd38dd5d38d18297d61bd263826888a43c28d76c73d991a38f4d93e8731aa83200f
$
$ printf "start_size=0\nend_size=0\n" | curl --data-binary @- https://poc.sigsum.org/sigsum/v0/get-leaves
shard_hint=0
checksum=0000000000000000000000000000000000000000000000000000000000000000
signature=0e0424c7288dc8ebec6b2ebd45e14e7d7f86dd7b0abc03861976a1c0ad8ca6120d4efd58aeab167e5e84fcffd0fab5861ceae85dec7f4e244e7465e41c5d5207
key_hash=9d6c91319b27ff58043ff6e6e654438a4ca15ee11dd2780b63211058b274f1f6
```

Go tooling that makes it easier to interact with sigsum logs will appear in a
separate repository in the near future, see
	[sigsum-lib-go](https://git.sigsum.org/sigsum-lib-go/).
