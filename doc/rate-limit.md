# Sigsum log rate limiting

Documentation on how sigsum rate limiting works, and how it is
configured.

## Objective

The overall objective of the rate limit mechanism is to limit the rate
at which new leaves are added to the log. Note that this does *not*
provide any protection from more general denial of service attacks.
Rate-limit applies only to `add-leaf` requests, and the mechanism is
intended to make it feasible to operate a public log, which anyone can
submit new leaves to.

## Enabling rate limits

Rate limits are enabled by using the `--rate-limit-config` command
line option to the `sigsum-log-primary` server. Without this option,
there are no rate-limits (appropriate only if access to the log server is
restricted by other means). The config file specifies allow lists of
various kinds, and corresponding limits.

## Config file syntax

The config file is line based, where each line consist of items
separated by white space. Comments are written with "#" and extend to
the end of the line. International domain names are written in utf-8
(no punycode).

## Allow lists

The rate limit is based on counts of added leafs per 24 hours. Adding
a leaf usually takes several requests; the first one makes the leaf
known to the log, yielding a 202 (Accepted) response. A typical client
will then repeat the request until it gets a 200 response. For rate
limiting purposes, only the first request for each leaf is counted.

Which counter is used, and what limit it is compared to, depends on
the configured allow lists. Each entry specifies a limit, an
unsigned decimal integer specifying the maximum number of leafs that
may be submitted per 24 hours. A limit of zero means that no leafs can
be submitted.

### Allowed keys

Allowed keys are configured with config lines of the form
```
key <key hash> <limit>
```
The key hash is the hex-encoded hash of the public key used to verify the leaf
signature in the request.

### Allowed domains

Allowed submitter domains are configured with a config line of the
form
```
key <domain> <limit>
```
The domain is a DNS domain in standard dotted notation, e.g.,
`foo.example.org`. The domain associated with the request is based on
a `sigsum-token:` header in the http request, which must be provided by
the submitter. The header includes a domain name and signature, and it
is used only if the log can verify the signature using a public key
retrieved from DNS. (In particular, the submitter's IP address and any
associated PTR records are not consulted).

Note that all subdomains of the configured domain are allowed, i.e.,
the line applies to all requests with a verified submit-token
specifying the given domain or a subdomain thereof. All requests from
those domains are counted together towards the given limit.

### Enabling public access

It's encouraged to enable public access, and allow anyone to submit
leafs to the log, restricted only by rate limits. To do this,
rate-limiting depends on a list of [public
suffixes](https://publicsuffix.org/). It is enabled using a config
line of the form
```
public <suffix file> limit
```
There can be only one of these lines.

The suffix file should be the name of a a copy of
<https://publicsuffix.org/list/public_suffix_list.dat>. (Automatic
updates of this list is under consideration, but not yet implemented).
Like for allowed domains, above, a domain is associated with a request
via the `sigsum-token:` header. The suffix list is used to extract the
"registered domain", roughly, the longest know public suffix matching
the domain, and one additional label.

The given limit is applied per "registered domain", which means that
total requests allowed by this configuration can be very much higher. It
is recommended to specify a rather low limit, e.g., 10-100. It is
deemed impractical for a prospective attacker to get tens of thousands
of registered domain.

TODO: Also add a limit on the total number of public requests, so one
could have, e.g., 10 per registered domain but 10000 total for all?

### Rule precedence

The order of the config lines doesn't matter. When determining which
limit should be applied to an incoming `add-leaf` request, it is
matched as follows:

1. If the leaf key matches a "key" line, that limit applies.

2. Otherwise, if one or more "domain" lines match, the one with the
   longest domain applies.

3. Otherwise, if public access is enabled, and the domain matches a
   known public suffix, the public line applies, and the request count
   associated with the registered domain.

4. If none of the lines match, the request is refused.

This means that if a domain matches a public suffix, one can set a
more specific limit (higher or lower) for that domain or a specific
subdomain using a "domain" line, which overrides the limit for the
registered domain. And similarly, a "key" line can be used to override
domain-based limits for a particular key.

## Test domain

There's a test domain test.sigsum.org, with a public key
`4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29`
registered in DNS. The corresponding private key is
`0000000000000000000000000000000000000000000000000000000000000001`,
and it can be used by anyone to create valid submit tokens for test
purposes.

By default, this test domain is banned, as if a line "domain
test.sigsum.org 0" were present in the config file, overriding all
other domain-based configuration affecting this domain. To enable use
of this domain, e.g., for integration tests of the rate limiting
feature, there's a command line option `--enable-test-domain=true`.