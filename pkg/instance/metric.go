package instance

import (
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/prometheus"
)

var (
	reqcnt  monitoring.Counter   // number of incoming http requests
	rspcnt  monitoring.Counter   // number of valid http responses
	latency monitoring.Histogram // request-response latency
)

func init() {
	mf := prometheus.MetricFactory{}
	reqcnt = mf.NewCounter("http_req", "number of http requests", "logid", "endpoint")
	rspcnt = mf.NewCounter("http_rsp", "number of http requests", "logid", "endpoint", "status")
	latency = mf.NewHistogram("http_latency", "http request-response latency", "logid", "endpoint", "status")
}
