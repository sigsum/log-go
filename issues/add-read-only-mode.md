# Add read-only mode
Reported by: rgdd

The process of shutting down a log will likely consist of at least two steps:
1. Stop accepting new logging requests. Serve the final (co)signed tree heads
for a while.
2. Take the log offline.

The first step requires some form of read-only mode. For example:
- Disable all write endpoints (`add-leaf` and `add-cosignature`)
- Implement a `StateManager` that serves fixed (co)signed tree heads.

For inspiration we could look at certificate transparency:
- https://github.com/google/certificate-transparency-go/tree/master/trillian/ctfe
