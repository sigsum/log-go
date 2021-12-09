**Title:** Improve error messages </br>
**Date:** 2021-12-09 </br>

# Summary
Error messages that are returned by the log need to be looked-over.

# Description
Some error messages are too verbose and may even span multiple lines.  Error
messages that span multiple lines violate the Sigsum API specification.  This
issue requires seeing over what error messages are currently returned, then
ensuring that what becomes externally visible is appropriate.

Examples of appropriate error messages:
- `Error=unknown witness with key hash $hash`
- `Error=invalid tree head signature for tree head with timestamp $t`
- `Error=rate limit exceeded for $domain_hint`
