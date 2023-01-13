# Failover

This document describes the needed setup and promotion procedure for
promoting a secondary node to primary, in case the primary node fails.

The primary ensures that it only signs and publishes tree heads that
are fully replicated by the secondary node. No similar synchronization
happens with general backups of the primary's state. Therefore,
restoring the state of a failed primary node from a recent backup is
*not* recommended, since that may lose recent log entries, violating
the log's append-only property.

## Log's private key

Since the log is identified by it's signing key, for the secondary
node to take on the rol of primary, it must have access to the
corresponding private key. Hence, for failover to be possible in case
of catastrophic failure, a secure backup of the private key is
required. E.g., using n-of-k secret sharing, or a securely stored
clone of a hardware key.

## Promoting a secondary to become the primary

In order to promote a secondary node to become the primary node of a
log instance, the following things need to be done:

1. Shutting down the secondary. This effectively stops the primary
   from advancing its tree head, regardless of its current status.

1. Converting the Trillian tree from type `PREORDERED_LOG` to type
   `LOG`, using `updatetree`. Note that the tree needs to be `FROZEN`
   before changing the tree type and unfrozen (`ACTIVE`) afterwards.

1. Configuring the secondary to use the signing key of the log instance.

1. Configure a new node to act as a new secondary.

1. Start the primary log server on the node being promoted.

1. In order for clients to reach the new primary rather than the old
   one, DNS record changes are usually needed as well.

## The signed treehead auxillary state

The primary server stores it's latest signed tree head to a file
(`sth-path` config setting). If possible, this file should be backed
up, and transferred to the secondary as part of the promotion.
Alternatively, the promoted server could be started with an empty
"latest" signed tree head. 

This matters for the promotes logs initial behavior, until the new
secondary has been able to replicate the tree. If the latest signed
tree is copied over properly, the promoted server will advertise the
latest tree published by the old primary, and not advance until new
secondary has caught up. If instead the promoted server is started
with an empty "latest" signed tree head, may for some time publish old
tree heads, temporarily violating the append-only property, and
witnesses are expected to refuse to cosign the log.

TODO: This is unsatisfactory. One possible improvement is to start the
promoted in a mode where it either advertises it's initial tree head
(since this is what the primary had published or was about to
published at the taime it failed) or no tree head at all, until new
secondary has caught up.
