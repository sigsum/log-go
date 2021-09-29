# sigsum-log-go
Sigsum logging brings transparency to **sig**ned check**sum**s.  What a
checksum represents is up to you.  For example, it could be the cryptographic
hash of a [provenance file](https://security.googleblog.com/2021/06/introducing-slsa-end-to-end-framework.html),
a [Firefox binary](https://wiki.mozilla.org/Security/Binary_Transparency), or a
text document.

You can use sigsum logging to:
1. Discover which checksum signatures were produced by what secret signing keys.
2. Be sure that everyone observes the same signed checksums.

## How it works
Suppose that you develop software and publish binaries.  You sign those binaries
and make them available to users in a package repository and on your website.
You are committed to distribute the same signed binaries to every user.  That is
an easy claim to make.  However, word is cheap and sometimes things go wrong.
How would you even know if your signing infrastructure got compromised?  A few
select users might already receive maliciously signed binaries that include a
backdoor.  This is where we can help by adding transparency.

For each binary you can log a signed checksum that corresponds to that binary.
If such a sigsum appears in the log that you did not expect: excellent, now
you know that your signing infrastructure was compromised at some point.
Similarly, you can also detect if a binary from your website or package
repository misses a corresponding log entry by inspecting the log.  The claim
that the same binaries are published for everyone can be _verified_.

Starting to apply the pattern of transparent logging is already an improvement
without any end-user enforcement.  It becomes easier to detect honest mistakes
and attacks against your website or package repository.

To make the most out of a sigsum log, end-users should start to enforce public
logging in the future.  This means that a binary in the above example would be
_rejected_ unless a corresponding sigsum is publicly logged.

Please refer to our
[design document](https://git.sigsum.org/sigsum/tree/doc/design.md) and
[API specification](https://git.sigsum.org/sigsum/tree/doc/api.md)
for additional details.

## Public prototype
We implemented sigsum logging as a [Trillian](https://transparency.dev/#trillian)
[personality](https://github.com/google/trillian/blob/master/docs/Personalities.md).
A public prototype is up and running with zero promises of uptime, stability,
etc.
The log's base URL is http://poc.sigsum.org:4780/st/v0.
The log's public verification key is
`bc9308dab23781b8a13d59a9e67bc1b8c1585550e72956525a20e479b1f74404`.
The log's shard interval is [X, Y].

An experimental [witness](https://github.com/sigsum/sigsum-witness-py) is also
up and running with zero-promises of uptime, stability, etc.
The public verification key is
`777528f5fd96f95713b8c2bb48bce2c83628e39ad3bfbd95bc0045b143fe5c34`.

You can talk to the log by passing ASCII key-value pairs.  For example,
fetch a tree head and a log entry:
```
$ curl http://poc.sigsum.org:4780/sigsum/v0/get-tree-head-latest
timestamp=1632956637
tree_size=17
root_hash=51ce7e8e7fa98d48ab84750ae9dcbabda268fbcca74ab907836a35a513396f9d
signature=c4bb2429410523d109540e0bd47e46b46bce6b233eb895fce4c761e60f15ac8a9d245153e3eaf30c7360b0f7bd49a6f7e4327bb1e7dc2396535726191b42c90b
$
$ printf "start_size=0\nend_size=0\n" | curl --data-binary @- http://poc.sigsum.org:4780/sigsum/v0/get-leaves
shard_hint=0
checksum=0000000000000000000000000000000000000000000000000000000000000000
signature=0e0424c7288dc8ebec6b2ebd45e14e7d7f86dd7b0abc03861976a1c0ad8ca6120d4efd58aeab167e5e84fcffd0fab5861ceae85dec7f4e244e7465e41c5d5207
key_hash=9d6c91319b27ff58043ff6e6e654438a4ca15ee11dd2780b63211058b274f1f6
```

We are currently working on tooling that makes it easier to interact with the
log.
