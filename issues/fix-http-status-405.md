**Title:** Fix HTTP status 405 </br>
**Date:** 2021-12-09 </br>

# Summary
Stop returning HTTP Status 405 or ensure that RFC 2616 is followed.

# Description
When using HTTP GET for a POST endpoint or vice versa, HTTP status code 405 is
currently returned by sigsum-log-go. According to RFC 2616, an Allow header MUST
be included in the response.  This issue requires figuring out what
sigsum-log-go should do: not return HTTP Status 405 or adhere to RFC 2616?

Extract from RFC 2616:
```
10.4.6 405 Method Not Allowed

The method specified in the Request-Line is not allowed for the resource
identified by the Request-URI. The response MUST include an Allow header
containing a list of valid methods for the requested resource.
```

To find the relevant parts in the sigsum-log-go code, see the output of

	git grep StatusMethodNotAllowed
