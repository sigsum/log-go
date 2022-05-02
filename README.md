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

- Base URL: https://poc.sigsum.org/crocodile-icefish/
- Public key: `4791eff3bfc17f352bcc76d4752b38c07882093a5935a84577c63de224b0f6b3`
- Shard start: 1651494520 (Mon 02 May 2022 12:28:40 PM UTC)

A [witness](https://github.com/sigsum/sigsum-witness-py) is also up and running
with zero-promises of uptime, stability, etc.  Relevant witness information:

- Public key: `812dbef0156b079e2d048747b2189cbfa64f96e2204a17cb23cb528080871503`.

As described in our design and API documentation, you can talk to the
log by passing ASCII key-value pairs.  For example, fetching a cosigned
tree head and two log entries:

```
$ curl https://poc.sigsum.org/crocodile-icefish/sigsum/v0/get-tree-head-cosigned
timestamp=1651496711
tree_size=3
root_hash=9e1197a53487295824c659fff4d05c6386f6d5e59cbc3d70f5693901cac15ca8
signature=d93ee124ce3b33fc2a7c16c2d74da5353a4f7e55c77a775f7eaec786e26dbf3e2cf25f7b00f9611d4f55196d4734242cf750ec2d42801f0b8abf27ae0146850e
cosignature=1f65d3d9f24a160ef26c47352329234e6f045e29f21af5d55dde6e42e8bb0577ef34382e405f208488f18cc3b1e55fa439d1641cd2a376320820192728bb4f02
cosignature=050ca46592dc9f1f4e8a4ad2ceae233dd25865a67c0cb8f938f10469f780dfb6c41c641aa19c968e526c1a9340241207a3b67d1f003b7b3fb18ff74ba1aa3702
key_hash=e94908c5c663c19a37b0b5e1e09db411cdb77e3e5d5f49bd7a8e2f53f748bdec
key_hash=15e203ad786ad5e36c053ba883d09ad7dc6b2011bb9c111330f79c8f1d6b8e69

$ curl https://poc.sigsum.org/crocodile-icefish/sigsum/v0/get-leaves/0/1
shard_hint=1651495935
checksum=a7f95461acc7e1b5c03371f3656c1f1d3b5c61478863955e6155d1795fab5c02
signature=36b205d4468b824f8c419c4f78583654780378ffb8e092078736d4e0354d52d5fcce54c9742092333ec50841b07e482898b549ca09956715d0a754633535fe0b
key_hash=c522d929b261241eef174b51b8472fa5d5f961892089a7b85fd25ce73271abca
shard_hint=1651495944
checksum=a7f1de4e4a83913b9f8279cb5d74f5adda378d3e21cacf8be89c35e4a133d01b
signature=67f90c0579c29f6d91e1d7fd06ed900cd76db44e4d899acc77e2535e268ce09a040d9ca0b2c1becb5ae79ce35ec260ed65b8436d7ff524415080343bd207cd06
key_hash=c522d929b261241eef174b51b8472fa5d5f961892089a7b85fd25ce73271abca
```

Go tooling that makes it easier to interact with sigsum logs will appear in a
separate repository in the near future, see
	[sigsum-lib-go](https://git.sigsum.org/sigsum-lib-go/).
