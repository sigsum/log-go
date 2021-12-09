**Title:** Add rate limit support </br>
**Date:** 2021-12-09 </br>

# Summary
Add support for rate-limiting add-leaf requests via second-level domain name.

# Description
A sigsum log requires a submitter to prove that a domain name is aware of their
public verification key.  Rate limits can then be applied per second-level
domain name.  Trillian has built-in rate-limiting using a so-called quota
manager; gRPC calls include an arbitrary `charge_to` string that is used as an
identifier with regards to who should be charged for the request.

First investigate whether Trillian's built-in rate limiting can be used and with
which assumptions.  For example, is `etcd` a required process?  Then implement
and document how an operator can configure sigsum-log-go with rate limits.
