**Title:** Add checkpoint support </br>
**Date:** 2021-12-09 </br>

# Summary
Add experimental checkpoint support.

# Description
Sigsum collaborated on a common
	[checkpoint format](https://github.com/google/trillian-examples/tree/master/formats/log)
a while back.  A checkpoint is basically a cosigned tree head.

The current decision is to add experimental support for checkpoints.  There is
no formal decision to adopt the above checkpoint yet, hence _experimental_.

To keep it simple:
1. Don't add any timestamp extension.
2. Only serve the most recent tree head as a checkpoint.  This allows us to
experiment with external feeders and distributors that are not part of the log.
