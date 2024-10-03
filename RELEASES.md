# Log server releases

## What's being released?

The following programs are released and supported:

  - `cmd/sigsum-log-primary`
  - `cmd/sigsum-log-secondary`
  - `cmd/sigsum-mktree`

Releases are announced on the [sigsum-announce][] mailing list. The
[NEWS file](./NEWS) documents, for each release, the user visible
changes, the recommended upgrade procedure, and other Sigsum
components that have been interop-tested with the log server release.

Note that a release is simply a git-tag specified on our mailing list.
You are expected to build the released tools yourself, e.g., with `go
install`. There may be intermediate git-tags between two advertised
releases; those are *not* released and supported.

The log-go go module is *not* considered released (as signalled by
the v0 version tag), even though we release the above programs with
the same tag. By the terms of the LICENSE file you are free to use
this code "as is" in almost any way you like, but for now, we
support its use *only* via the above programs, and we don't aim to
provide any backwards compatibility for internal interfaces.

We encourage deployment of our released Sigsum log servers. For
applications to be able to *depend* on Sigsum logging, they also need
trusted log witnesses and log monitoring. Availability and quality of
these components is out of scope for the log server release process.

[sigsum-announce]: https://lists.glasklarteknik.se/mailman3/postorius/lists/sigsum-announce.lists.sigsum.org/

## Upgrading

You are expected to upgrade linearly from one advertised release to
the next advertised release, e.g., from v0.9.0 to v0.14.1, unless
specified otherwise. We strive to make upgrading easy. Any
complications, e.g., any manual steps required for migration of stored
state or configuration, is documented in the [NEWS file](./NEWS).

Downgrading is in general not supported.

Primary and secondary nodes of a log instance should be upgraded in
tandem: running nodes on different software releases is not tested.

## Expected changes in upcoming releases

  1. There are no planned changes to the wire protocol between log
     clients and log servers. The [sigsum v1 protocol][] is used. This
     also fully specifies the cryptographic details, such as precisely
     which bytes are being signed, and intended meaning, for each type
     of signature. Any breaking changes would have to be considered
     *very carefully* and be *coordinated well in advance*.
  2. There are no planned changes to the wire protocol between log
     servers and witnesses. The [tlog-witness protocol][] is used.
  3. Changes are likely to other operational aspects of the log
     server, e.g., configuration interfaces, available metrics, and
     storage of the log server's state. Such changes, as well as the
     migration procedure, will be documented in the [NEWS file](./NEWS).

[sigsum v1 protocol]: https://git.glasklar.is/sigsum/project/documentation/-/blob/log.md-release-v1.0.0/log.md
[tlog-witness prococol]: https://github.com/C2SP/C2SP/blob/tlog-checkpoint/v1.0.0-rc.1/tlog-witness.md.

## Release cycle

We make feature releases when something new is ready. We expect one or
several months between feature releases.

In case critical bugs are discovered, we intend to provide bugfix-only
updates for the latest release in a timely manner. Backporting
bugfixes to older releases than the latest one will be considered on a
case-by-case basis, with priority to the case that the latest feature
release is particularly recent or upgrading to it is particularly
disruptive.

## Future improvements

Some desired incremental improvements of the release processes:

  - Document and automate more of the release testing.
  - Define a process for signing releases, e.g., a signed git tag.
