# HTTP status 405, no Allow header
Reported by: ln5

When using HTTP GET for a POST endpoint or vice versa, HTTP status code 405 is
returned by the server. According to RFC2616 an Allow header MUST be included in
the response.

```
10.4.6 405 Method Not Allowed

The method specified in the Request-Line is not allowed for the resource
identified by the Request-URI. The response MUST include an Allow header
containing a list of valid methods for the requested resource.
```

Find relevant places to start looking:
```
$ git grep StatusMethodNotAllowed
```
