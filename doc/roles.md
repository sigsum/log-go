# Log server roles

This document describes the system architecture of the log_go log
server implementation. A log instance is identified by the public
signing key used for verifying tree head signatures, and by the base
url that clients use to interact with the log instance.

A log instance consists of several nodes, each node running internal
and/or external server components. There are two types of nodes,
primary and secondary. The log instance has exactly one primary node
(and if, at some point in time, the primary node is down or not
reachable, the log instance is considered down).

A log instance can also have a single secondary node (support for
multiple secondaries is planned). Secondary nodes replicate the
primary node's log database, to enable failover without losing data or
violating the append-only property of the log. For a production log
server, it's strongly recommended to configure the log instance to
include a secondary.

If the primary node fails, it's possible to promote the secondary to
become primary (and in this case, it's also strongly recommended to
configure a new secondary node). See [fail-over](./failover.md) for
details on necessary setup and the promotion procedure.

Besides the log server itself, each node also runs an internal
trillian service and a mariadb database for storing the log state;
these servers are not exposed outside of the node, in particular, data
replication is not done at this level.

## The primary node

A primary node is configured with the private signing key of the log
instance, url and public key of the secondary node, if any, and public
key and url of each witness that is expected to cosign the log.

If a secondary is configured, the primary server queries the
secondary's tree, and it will only sign and publish a tree head when
corresponding entries are properly stored to disk both locally and by
the secondary.

This means that in case the secondary is out of service for any
reason, the primary will not sign and publish new log entries. The
primary will continue to respond to queries from clients, but requests
to add new log entries will only get a partial success response (202
Accepted); since the data is not replicated, the log can not commit to
publish it. Clients are expected to retry such requests, and will get
a success response once the secondary is back in service and has
replicated the data.

A primary node implements two HTTP APIs, with separate base urls: The
public one, used by log clients, and an internal api, used by the
secondary node.

## The secondary node

A secondary node interacts only with the primary node. It is
configured with its own signing key (corresponding signatures are seen
and verified only by the primary), and the public key of the primary,
and the base url of the primary node's internal HTTP API.

The secondary periodically polls the primary for new leaves, and
copies them to the secondary's trillian instance. The trillian
instance is configured with a `PREORDERED_LOG` tree and without a
sequencer. Polling should use a frequency that is higher than the
primary's publishing frequency, typically on the order of once every
few seconds and once every few minutes, respectively.
