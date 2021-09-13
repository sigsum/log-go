# sigsum-log-go
_Sigsum_ logging brings transparency to **sig**ned check**sum**s.  What a
checksum represents is up to you.  For example, it could be the cryptographic
hash of a [provenance file](https://security.googleblog.com/2021/06/introducing-slsa-end-to-end-framework.html),
a [Firefox binary](https://wiki.mozilla.org/Security/Binary_Transparency), or a
text document.

Sigsum logging can be used to:
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
If such a _sigsum_ appears in the log that you did not expect: excellent, now
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

## Design considerations
We had several design considerations in mind while developing sigsum logging.  A
short preview is listed below.  Refer to our [design document](https://github.com/sigsum/sigsum/blob/main/doc/design.md)
and [API specification](https://github.com/sigsum/sigsum/blob/main/doc/api.md)
for additional details.  Feedback is welcomed and encouraged!
- **Preserved data flows:** an end-user can enforce transparent logging without
making additional outbound network connections.  Proofs of public logging should
be provided using the same distribution mechanism as the data.  In the above
example the software publisher would put these proofs into their package
repository.
- **Sharding to simplify log life cycles:** starting to operate a log is easier
than closing it down in a reliable way.  We have a predefined sharding interval
that determines the time during which the log will be active.
- **Defenses against log spam and poisoning:** to maximize a log's utility it
should be open for anyone to use.  However, accepting logging requests from
anyone at arbitrary rates can lead to abusive usage patterns.  We store as
little metadata as possible to combat log poisoning.  We piggyback on DNS to
combat log spam.
- **Built-in mechanisms that ensure a globally consistent log:** transparency
logs rely on gossip protocols to detect forks.  We built a proactive gossip
protocol directly into the log.  It is based on witness cosigning.
- **No cryptographic agility**: the only supported signature scheme is Ed25519.
The only supported hash function is SHA256.  Not having any cryptographic
agility makes the protocol and the data formats simpler and more secure.
- **Few and simple (de)serialization parsers:** complex (de)serialization
parsers increase attack surfaces and make the system more difficult to use in
constrained environments.  End-users need a small subset of [Trunnel](https://gitlab.torproject.org/tpo/core/trunnel/-/blob/main/doc/trunnel.md)
to work with signed and logged data.  The log's network clients also need to
parse ASCII key-value pairs.

## Public prototype
We implemented sigsum logging as a [Trillian](https://transparency.dev/#trillian)
[personality](https://github.com/google/trillian/blob/master/docs/Personalities.md).
A public prototype is up and running with zero promises of uptime, stability,
etc.  The log's base URL is `http://tlog-poc.system-transparency.org:4780/st/v0`.
The log's public verification key is `bc9308dab23781b8a13d59a9e67bc1b8c1585550e72956525a20e479b1f74404`.

An [experimental witness](https://github.com/sigsum/sigsum-witness-py)
is also up and running with zero promises of uptime, stability, etc.  The
public verification key is `777528f5fd96f95713b8c2bb48bce2c83628e39ad3bfbd95bc0045b143fe5c34`.

You can talk to the log by passing ASCII key-value pairs.  For example,
fetch a tree head and a log entry:
```
$ echo "TODO: update to sigsum links"
$ curl http://tlog-poc.system-transparency.org:4780/st/v0/get-tree-head-latest
timestamp=1623053394
tree_size=1
root_hash=f337c7045b3233a921acc64688b729816a10f95f8be00910418aaa3c71245d5d
signature=50e88b935f6010dedb61314685371d16bf180be99bbd3463a0b6934be78c11ebf8cc81688e7d11b0dc593f2ea0453f6be8ed60abb825b5a08535a68cc007e20e
key_hash=2c27a6bafcbe210753c64666ca108025c68f28ded8933ebb2c4ef0987d7a6302
$
$ printf "start_size=0\nend_size=0\n" | curl --data-binary @- http://tlog-poc.system-transparency.org:4780/st/v0/get-leaves
shard_hint=0
checksum=0000000000000000000000000000000000000000000000000000000000000000
signature_over_message=0e0424c7288dc8ebec6b2ebd45e14e7d7f86dd7b0abc03861976a1c0ad8ca6120d4efd58aeab167e5e84fcffd0fab5861ceae85dec7f4e244e7465e41c5d5207
key_hash=9d6c91319b27ff58043ff6e6e654438a4ca15ee11dd2780b63211058b274f1f6
```

We are currently working on tooling that makes it easier to interact with the
log.
