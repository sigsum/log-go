# Configuring and using the log server implementation

The documents in this folder describe the `log-go` implementation of a
[Sigsum](https://git.glasklar.is/sigsum/project/documentation) log
server.

Sections:

1. [System architecture](./architecture.md), in particular, how a log
   instance can have one primary and one secondary node.

2. [Rate-limit configuration](./rate-limit.md), strongly recommended
   for public log servers to combat log spam.

3. [Fail-over](./failover.md), instruction for setup and procedures to
   be able to fail over to the secondary node on catastrophic failure
   of the primary.

4. [Server-setup](./setup.md). How to manually setup a new log
   instance (for deployment using ansible, see
   [ansible](https://git.glasklar.is/sigsum/admin/ansible)),
