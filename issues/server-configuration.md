# Server configuration
Reported by: ln5

All server configuration is done via command-line arguments.

This is good for configuration settings which last through the lifetime of an
invocation of a log instance, i.e., from launch to Ctrl-C.  Examples:
- `--http_endpoint`
- `--key`.

It is less good for settings that change over time.  Examples:
- `--witnesses`

Reading a configuration file at start and when receiving, say, SIGHUP, is an
alternative.

Implementing a "control port", typically a TCP endpoint, where an administrator
can "program" the log instance is another alternative. Such an interface can
also be used for diagnostics.
