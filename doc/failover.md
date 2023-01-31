# Failover

This document describes the required setup and promotion procedure for
promoting a secondary node to primary, in case the primary node fails.

The primary ensures that it only signs and publishes tree heads that
are fully replicated by the secondary node.

System backups are out of scope of the Sigsum software, but note that
restoring the state of a failed primary node from backup is *not*
recommended, since that may lose recent log entries, breaking the
log's append-only property beyond repair.

## Log's private key

Since the log is identified by its signing key, for the secondary
node to take on the role of primary, it must have access to the
corresponding private key. Hence, for failover to be possible in case
of catastrophic failure, a secure backup of the private key is
required. E.g., using n-of-k secret sharing, or a securely stored
clone of a hardware key.

## Promoting a secondary to become the primary

In order to promote a secondary node to become the primary node of a
log instance, the following steps are needed:

1. Shut down the secondary. This effectively stops the primary
   from advancing its tree head, regardless of its current status.

2. Convert the Trillian tree from type `PREORDERED_LOG` to type
   `LOG`, using `updatetree`. Note that the tree needs to be `FROZEN`
   before changing the tree type and unfrozen (`ACTIVE`) afterwards.

3. Configure the secondary to use the signing key of the log instance.

4. Create special startup file `sth.startup` next to the configured
   location of the sth file (signed tree head), with the contents
   `startup=local-tree`. This tells the new primary to initially
   create a signed tree head corresponding to its local tree, i.e.,
   the replica of the old primary.

5. Configure a new node to act as a secondary.

6. Start the primary log server on the node being promoted.

7. In order for clients to reach the new primary rather than the old
   one, DNS record changes are usually needed as well.
