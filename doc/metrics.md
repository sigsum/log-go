# Metrics

The primary and secondary log servers expose Prometheus metrics on the
internal endpoint, at `/metrics`. The internal endpoint is configured
with `--internal-endpoint`.

The Prometheus output includes `HELP` and `TYPE` lines, but the notes
below document the intended meaning of each metric and label.
Histogram metrics are exposed with the usual Prometheus `_bucket`,
`_sum`, and `_count` suffixes.

The `/metrics` endpoint also exposes standard metrics from the
Prometheus Go client, such as Go runtime and process metrics. These
are not documented here.

## Server metrics

The following HTTP server metrics are exposed by both primary and
secondary nodes.

### `http_req`

Counter for incoming HTTP requests.

Labels:

1. `logid`: hex-encoded log public key.

2. `endpoint`: HTTP endpoint handling the request, e.g., "get-tree-head".

### `http_rsp`

Counter for HTTP responses.

Labels:

1. `logid`: hex-encoded log public key.

2. `endpoint`: HTTP endpoint handling the request, e.g., "get-tree-head".

3. `status`: HTTP response status code.

### `http_latency`

Histogram for HTTP request-response latency, in seconds.

Labels:

1. `logid`: hex-encoded log public key.

2. `endpoint`: HTTP endpoint handling the request.

3. `status`: HTTP response status code.

## Witness metrics

The following witness metrics are exposed by the primary node. They are
recorded while the primary queries witnesses for cosignatures.

### `witness_checkpoint_requests_total`

Counter for witness add-checkpoint requests.

Labels:

1. `witness`: witness URL with the `http://` or `https://` prefix
   removed.

2. `status`: `200` on success, the HTTP status code for errors returned
   by the witness, or `other` for failures that are not witness HTTP
   errors (e.g., error occurred without getting a status code back).

3. `retried`: `true` if the log retried with a new add-checkpoint
   request as a result of seeing HTTP 409 Conflict, otherwise `false`.

### `witness_checkpoint_request_latency`

Histogram for successful witness add-checkpoint request latency, in
seconds. Failed requests are not recorded in this histogram.

**Note:** success includes 200 OK responses, but also 200-after-409.
Latency is end-to-end, i.e., the time to get the actual cosignature.

Labels:

1. `witness`: witness URL with the `http://` or `https://` prefix
   removed.

### `witness_quorum_total`

Counter that tracks if the log was able to collect enough cosignatures to
satisfy the configured quorum (if any).

Labels:

1. `status`: `true` if the primary reached witness quorum, otherwise
   `false`.

### `witness_quorum_latency`

Histogram for the time needed to reach witness quorum, in seconds. This
metric is recorded only for successful quorum attempts.
