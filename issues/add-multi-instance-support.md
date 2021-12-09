**Title:** Add multi-instance support </br>
**Date:** 2021-12-09 </br>

# Summary
Add support for multiple active sigsum-log-go instances for the same log.

# Description
A sigsum log accepts add-cosignature requests to make the final cosigned tree
head available.  Right now a single active sigsum-log-go instance is assumed per
log, so that there is no need to coordinate cosigned tree heads among instances.

Some log operators will likely want to run multiple instances of both the
Trillian components and sigsum-log-go, backed by a managed data base setup.
Trillian supports this, but sigsum-log-go does not due to lack of coordination.

This issue requires both design considerations and an implementation of the
`StateManager` interface to support multi-instance setups of sigsum-log-go.
