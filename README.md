# Sigsum log-go

This repository provides a log server that implements the [sigsum protocols][].
Database replication between a primary node and a secondary node is included.
[Trillian][] and [MariaDB][] are used for backing the storage on each node.

[sigsum protocols]: https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md
[Trillian]: https://transparency.dev/#trillian
[MariaDB]: https://mariadb.org/

## Documentation

See the [docs](./doc/readme.md) directory for information on how to setup and
configure a Sigsum log instance.  An [ansible collection][] is also available
for reference.

The [RELEASES](./RELEASES.md) file describes how the log-go software is
released.  Releases are announced on the [sigsum-announce][] list.

For documentation on Sigsum in general, refer to the [project
website](https://www.sigsum.org/docs/).

[ansible collection]: https://git.glasklar.is/sigsum/admin/ansible
[sigsum-announce]: https://lists.sigsum.org/mailman3/postorius/lists/sigsum-announce.lists.sigsum.org/

## Development

### Contributing

You are encouraged to file issues and open merge requests.  To contribute
without a GitLab account, interact with us on the [sigsum-general][] list.  You
can also file issues on our [issue tracker][] by sending an email to:

    gitlab+sigsum-core-log-go-issue@incoming.glasklar.is

If you are a first-time contributor providing a merge request, please review the
log-go [LICENSE](./LICENSE) and copyright in the [AUTHORS](./AUTHORS) file.
Append your name to the list of authors at the bottom in a separate commit.

[sigsum-general]: https://lists.sigsum.org/mailman3/postorius/lists/sigsum-general.lists.sigsum.org/
[issue tracker]: https://git.glasklar.is/sigsum/core/log-go/-/issues

### Testing

Our [CI configuration](./gitlab-ci.yml) builds the log-go software, runs all
unit tests, and performs an integration test with two nodes on localhost.

Please make sure that all CI tests pass.

If you would like to work on the integration tests themselves and/or run
locally, see [README](./integration/README.md) in the integration directory.

### Commit messages

At this time it is a non-goal to have a clean git-commit history.  Use your best
judgment to write good commit messages.  We are not picky about the formatting.

### Public test instance

There is a public test instance available that deploys the main branch every 10
minutes.  Feel free to use it as you see fit when developing Sigsum use-cases.

  - Log URL: https://poc.sigsum.org/jellyfish
  - Public key: `154f49976b59ff09a123675f58cb3e346e0455753c3c3b15d465dcb4f6512b0b`

Please note that there are no promises of uptime or stability for this public
test instance.  For information on test witnesses and more stable public
instances, refer to the [project website](https://www.sigsum.org/services/).

### Available tooling

Tooling and libraries to use Sigsum is available in the [sigsum-go][]
repository.  If you are just looking to poke at a log server manually, you may
do so by exchanging ASCII key-value pairs as described in the
[sigsum protocols][].  For example, try fetching a signed (and possibly
cosigned) tree head and a few entries from the public test instance:

```
$ curl https://poc.sigsum.org/jellyfish/get-tree-head
size=1291
root_hash=2b06e738e93ad2e8b9e1c8ae86b762cb20f16b0bda4ce3e40680d412b9cae5ea
signature=5e91a847fb088341b26dc217c46878cd0bd1b9b576ce7d9d5f0fa781b1b139488bebc1883748c2c731aab546ee37ffcfa5823a37e55a8b5e501390235fcab00f
cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1697784602 cb584f52b8c65e3eab6a7b0f17eca82ab8cfb766a46f7f26b76c2dc7a0a750ee8bd971dad7101cdebfdd786affd82582b4c42d41ff185d01f2cf756fbce0ef07
cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1697784602 23b808cec68b1d6a9860bf1a4dc8de41d32d8105886e8f45170a49acaa046effd630cccf61235aa12b889bf3ed04002069d10bdf1041f99a6a7e09b42785b50c
$
$ curl https://poc.sigsum.org/jellyfish/get-leaves/10/12
leaf=3c14dfb28e7ed39442fe6376feb9f98b5f97a41ccf024dd2c6f38640c699a66c a8140f22aabfd2684635a8c266b557f3a06f958b8cd051605ed17648fb4949ff0922c0a73045c90e4baddf7033ba2a34b5841221ac7067918aada94553f0f104 4f313845ab7b7bc4592e437869e838fcccef45b402bd970f8aa2628ec17ef5cf
leaf=1507de45cbe91d7192063c7c143b9d07aa52ac4a47c278d728dd9c9e86c834f3 315ee5e2eb5a7d3a573760e612f76337a1a445fa1c117cf9bf94d0dc327d15f0feee0f67ba679d74cb08cb4748793aa09576f5496abf831a4c1105925c635404 4f313845ab7b7bc4592e437869e838fcccef45b402bd970f8aa2628ec17ef5cf
```

[sigsum-go]: https://git.glasklar.is/sigsum/core/sigsum-go/

## Contact

  - IRC room `#sigsum` @ OFTC.net
  - Matrix room `#sigsum` which is bridged with IRC
  - The [sigsum-general][] mailing list
