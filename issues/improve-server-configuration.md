**Title:** Improve server configuration and documentation </br>
**Date:** 2021-12-09 </br>

# Summary
Make server configuration more robust and dynamically updatable without restart.

# Description
All server configurations are currently done via command-line arguments.  This
may be OK for settings that last through a log's entire lifetime.  However, it
is inappropriate for parameters like `--witnesses` which are not static.

Reading a configuration file at start and when receiving, say, SIGHUP, is an
alternative.  Implementing a "control port", typically via a TCP endpoint, where
an administrator can "program" the log instance is another alternative.

This issue requires some design considerations before getting started.  It would
be good to improve documentation on how to run sigsum-log-go at the same time.
