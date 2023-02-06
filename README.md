# Sigsum log-go
This repository provides a
	[Trillian](https://transparency.dev/#trillian)
	[personality](https://github.com/google/trillian/blob/master/docs/Personalities.md)
implementing the sigsum/v0
	[design](https://git.sigsum.org/sigsum/tree/doc/design.md)
and
	[API](https://git.sigsum.org/sigsum/tree/doc/api.md).

## Server docs

See [docs](./doc/readme.md) for information on how to setup and
configure an Sigsum log instance.

## Public prototype
There is a public prototype running with zero promises of uptime,
stability, etc.  Relevant log information:

- Base URL: https://poc.sigsum.org/jellyfish
- Public key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINmewJUQl/97RtbjM6sPemj0Q4RryBxEuXp4iLauwxBA`

At the moment, the witness protocol is being reworked, so there are no
witnesses up and running and no cosignatures.

As described in the design and API documentation, you can talk to the
log by sending it ASCII key-value pairs. For example, fetching a
signed (and possibly cosigned) tree head and the first entry:

```
$ curl https://poc.sigsum.org/jellyfish/get-tree-head
size=1
root_hash=2cb35714fa562402198a80197be8948af3da96a0f01ae7b5f6f2d4379aafd783
signature=f8bcd0891bcad2c6a95d776c9b08701805e0bef23ad04bd97827402f57773490a732cbebf2f0313da428d1eae58af541a4aa711d9ccc52f4b4459e394e32e506

$ curl https://poc.sigsum.org/jellyfish/get-leaves/0/1
leaf=cd446a8537e59056c999aeb7ecd47f6b4f82f86309d08789b169d43e9ce53935 ba6c8ee7ad4b72eb62bf29f4aeee958c809dca8f74ad87f983d431e77d7fc8412feea268929d3927ffe0d0bea3264edca5a1a36fadeac092d3ae46ff8eb2e106 0c317483e28564540fbe32fbb9292d627211e881e3cf677346aabc738b2bf1bf
```

Go tooling that makes it easier to interact with sigsum logs will appear in a
separate repository in the near future, see
	[sigsum-go](https://git.glasklar.is/sigsum/core/sigsum-go/).


## Development

### Integration tests

There's an integration test script in `integration/test.sh`, see
[docs](./integration/README.md) for details.
