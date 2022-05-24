# sigsum_log_go design

This document describes the design of `sigsum_log_go`, an
implementation of
[Sigsum](https://git.sigsum.org/sigsum/tree/doc/design.md).

## General

TODO: add general design info

A log instance

- has one signing key,

- is made up of one or more log nodes -- primary and secondary,

- has at any given time exactly one primary and zero or more,
  secondaries

- should really have at least one secondary node, to not risk losing
  data,

- confirms new leaves (add-leaf returning HTTP code 200) once they
  have been incorporated in the tree and sequenced but not before.

Log nodes

- publish two API:s, one public and one for use by other nodes of the
  same log instance.

## Roles -- primary and secondary

A log node is configured to act as the `primary` node, or to act as a
`secondary` node. A primary is configured to know the base URL and
pubkey of zero or more secondaries. A secondary is configured to know
the base URL and pubkey of one primary.

### Interaction

A primary node that has no secondary nodes configured is the single
node in a test instance and lacks all means of recovering from storage
failures. This configuration is only recommended for testing of the
software.

A primary node that has at least one secondary node configured

- fetches and verifies the tree head from all its secondaries using
  the internal API endpoint `getTreeHeadToCosign` (TBD: rename
  endpoint to be uniquely named across both API:s?)

- considers a secondary node that can not be reached to have a tree
  size of zero,

- advances its tree head no further than to the lowest tree size of
  all its secondary nodes.

A secondary node:

- runs a Trillian server configured with a `PREORDERED_LOG` tree and
  without a sequencer,

- periodically fetches all leaves from the primary using the internal
  API endpoints `getTreeHeadUnsigned` and `getLeaves`,

- populates Trillian with the leaves fetched from its primary, in the
  order that they are delivered,

- should advance its tree head more often than its primary node,
  typically every few seconds.

### Promoting a secondary to become the primary

In order to promote a secondary node to become the primary node of a
log instance, the following things need to be done:

1. Shutting down the secondary. This effectively stops the primary
   from advancing its tree head, regardless of its current status.

1. Converting the Trillian tree from type `PREORDERED_LOG` to type
   `LOG`, using `updatetree`. Note that the tree needs to be `FROZEN`
   before changing the tree type and unfrozen (`ACTIVE`) afterwards.

1. Configuring the secondary to use the signing key of the log instance.

1. Starting the secondary with `-role primary` and at least one
   secondary node.

In order for clients to reach the new primary rather than the old one,
DNS record changes are usually needed as well.


### Open questions

- should secondaries publish the public API as well, but reply with
  "404 not primary"? clients ending up at a secondary might benefit
  from this
