**Title:** Fix strict hex parsing </br>
**Date:** 2021-12-09 </br>

# Summary
Fix so that sigsum-log-go is strict about lower-case hex parsing.

# Description
The current sigsum-log-go implementation uses "encoding/hex" which accepts
upper-case and lower-case hex.  This is a violation of the Sigsum API
specification and needs to be fixed: upper-case hex must be rejected.
