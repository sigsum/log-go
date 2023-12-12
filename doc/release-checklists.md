# Release checklists

This document is intended for maintainers making releases of the
log-go software.

## Release checklist

  - [ ] Test the procedure for upgrading from the previous release.
  - [ ] Test and document interop with sigsum-go command line tools,
        and with known witness implementations.
  - [ ] Check that the README, RELEASES.md and MAINTAINERS files are
        up-to-date.
  - [ ] After finalizing the release documentation, in particular, the
      NEWS file, create a new tag, usually incrementing the third
      number from what was used for release candidates being tested.

## NEWS file checklist

  - [ ] The previous NEWS entry is for the previous release
  - [ ] Broad summary of changes
  - [ ] Detailed instructions on how to upgrade from the previous release.
  - [ ] Other repositories/tools/tags that are known to be interoperable.

## RELEASES file checklist

  - [ ] What in the repository is being released and supported.
  - [ ] Where are releases announced (sigsum-announce mailing list).
  - [ ] The overall release process is described.
  - [ ] The expectation we as maintainers have on users.
  - [ ] The expectations users can have on us as maintainers, e.g.,
      how we're testing a release and what we intend to (not) break in
      the future.

## Announcement email checklist

  - [ ] What is being released, e.g., log server software / log-go.
  - [ ] Specify new release tag.
  - [ ] Specify previous release tag.
  - [ ] Specify how to report bugs.
  - [ ] Refer to the RELEASES file for information on the release process and
    expectations.
  - [ ] Copy-paste the NEWS file entries for this release.
