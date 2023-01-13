# Configuring and using the log server implementation

The documents in this folder describe the `log_go` implementation of a
[Sigsum](https://git.glasklar.is/sigsum/project/documentation) log
server.

Sections:

1. [System architecture](./roles.md), in particular, how a log
   instance can have one primary and one secondary node.
   
1. [Rate-limit configuration](./rate-limit.md), strongly recommended
   for public log servers.
   
1. [Fail-over](./failover.md), instruction for setup and procedures to
   be able to fail over to sthe secondary node on catastrophic failure
   of the primary.
   
1. TBD: Quick-start instructions, how to setup a new log instance,
   possible using ansible recipies.
