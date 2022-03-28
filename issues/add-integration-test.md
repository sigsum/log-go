**Title:** Add integration test </br>
**Date:** 2021-12-09 </br>

# Summary
Add integration test that runs sigsum-log-go hooked-up to Trillian.

# Description
Today we don't have any integration tests.  Before a new version is tagged, it
is tested by (i) running unit tests, and (ii) running manual tests against a
local setup of Trillian and sigsum-log-go.  Automating (ii) would be helpful
for development and increased confidence that everything works as expected.

Started in branch:

    rgdd/integration
