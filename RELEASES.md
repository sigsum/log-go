# Log server releases and release processes

## Releases

### What's being released?

The following programs are released and supported:

  - `cmd/sigsum-log-primary`
  - `cmd/sigsum-log-secondary`
  - `cmd/sigsum-mktree`

Releases are announced on the [sigsum-general][] mailing list. The
[NEWS file][] documents, for each release, the user visible
changes, the recommended upgrade procedure, and other Sigsum
components that have been interop-tested with the log server release.

Note that a release is simply a git-tag specified on our mailing list.
You are expected to build the released tools yourself, e.g., with `go
install`. There may be intermediate git-tags between two advertised
releases; those are *not* released and supported.

The log-go go packages are *not* considered released (as signalled by
the v0 version tag), even though we release the above programs with
the same tag. By the terms of the LICENSE file you are free to use
this code "as is" in almost any way you like, but for now, we
support its use *only* via the above programs, and we don't aim to
provide any backwards compatibility for internal interfaces.

We encourage deployment of our released Sigsum log servers. For
applications to be able to *depend* on Sigsum logging, they also need
trusted log witnesses and log monitoring. Availability and quality of
these components is out of scope for the log server release process.

[sigsum-general](https://lists.glasklarteknik.se/mailman3/postorius/lists/sigsum-general.lists.sigsum.org/)
[NEWS file](./NEWS)

### Upgrading

You are expected to upgrade linearly from one advertised release to
the next advertised release, e.g., from v0.9.0 to v0.14.1, unless
specified otherwise. We strive to make upgrading easy, with any
complications, e.g., any manual steps required for migration of stored
state or configuration, documented in the [NEWS file][].

Downgrading is in general not supported. Upgrading several releases is
generally *intended* to work, but not properly tested. We currently do
manual testing of upgrades, and only cover upgrades from the previous
release.

Primary and secondary nodes of a log instance should be upgraded in
tandem: running nodes on different software releases is not tested.

### Expected changes in upcoming releases

  1. There are no planned changes to the wire protocol between log
     clients and log servers. The the [sigsum v1 protocol][] is used. This
     also fully specifies the cryptographic details, such as precisely
     which bytes are being signed, and intended meaning, for each type
     of signature. Any breaking changes would have to be considered
     *very carefully* and be *coordinated well in advance*.
  2. Changes are likely to other operational aspects of the log
     server, e.g., configuration interfaces, available metrics, and
     storage of the log server's state. Such changes, as well as the
     migration procedure, will be documented in the [NEWS file][].
  3. For the wire protocol between log servers and witnesses,
     substantial changes are planned that affect everything *except*
     the resulting cosignatures as they are are published to log
     clients. Such changes will require logs and witnesses to
     coordinate upgrades, while log clients are completely unaffected.

[sigsum v1 protocol](https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md)

## Log server release process

### Release cycle

As of now there is no release schedule. We expect feature releases
when something new is ready, and we expect one or several months
between feature releases.

In case critical bugs are discovered, we intend to provide bugfix-only
updates for the latest release in a timely manner. Backporting
bugfixes to older releases than the latest one will be considered on a
case-by-case basis, with priority to the case that the latest feature
release is particularly recent or upgrading to it is particularly
disruptive.

### Release checklist

  - [ ] Test the procedure for upgrading from the previous release.
  - [ ] Test and document interop with sigsum-go command line tools,
        and with known witness implementations.
  - [ ] Check that the README and RELEASES.md files are up-to-date.
  - [ ] After finalizing the release documentation, in particular, the
      NEWS file, create a new tag, usually incrementing the third
      number from what was used for release candidates being tested.

### NEWS file checklist

  - [ ] The previous NEWS entry is for the previous release
  - [ ] Broad summary of changes
  - [ ] Detailed instructions on how to upgrade from the previous release.
  - [ ] Other repositories/tools/tags that are known to be interoperable.

### RELEASES file checklist

  - [ ] What in the repository is being released and supported.
  - [ ] Where are releases announced (sigsum-general mailing list).
  - [ ] The overall release process (based on the above procedure).
  - [ ] The expectation we as maintainers have on users.
  - [ ] The expectations users can have on us as maintainers, e.g.,
      how we're testing a release and what we intend to (not) break in
      the future.

### Announcement email checklist

  - [ ] What is being released, e.g., log server software / log-go.
  - [ ] Specify new release tag.
  - [ ] Specify previous release tag.
  - [ ] Specify how to report bugs.
  - [ ] Refer to the RELEASES file for information on the release process and
    expectations.
  - [ ] Copy-paste the NEWS file entries for this release.

### Future improvements

  - Document and automate more of the release testing.
  - Release signing.
