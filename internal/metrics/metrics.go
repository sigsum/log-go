package metrics

import (
	"fmt"
	"time"

	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/prometheus"

	"sigsum.org/log-go/internal/witness"
	"sigsum.org/sigsum-go/pkg/server"
)

type serverMetrics struct {
	LogID   string
	reqcnt  monitoring.Counter   // number of incoming http requests
	rspcnt  monitoring.Counter   // number of valid http responses
	latency monitoring.Histogram // request-response latency
}

func (m *serverMetrics) OnRequest(endpoint string) {
	m.reqcnt.Inc(m.LogID, endpoint)

}

func (m *serverMetrics) OnResponse(endpoint string, statusCode int, t time.Duration) {
	sc := fmt.Sprintf("%d", statusCode)
	m.rspcnt.Inc(m.LogID, endpoint, sc)
	m.latency.Observe(t.Seconds(), m.LogID, endpoint, sc)
}

func NewServerMetrics(logID string) server.Metrics {
	mf := prometheus.MetricFactory{}
	// Interval 1ms to 10s, with thresholds roughly a factor
	// 10^{1/4} \appr 1.8 apart.
	buckets := []float64{1e-3, 2e-3, 3e-3, 6e-3, 10e-3, 20e-3, 30e-3, 60e-3, 0.1, 0.2, 0.3, 0.6, 1, 2, 3, 6, 10}

	return &serverMetrics{
		LogID:  logID,
		reqcnt: mf.NewCounter("http_req", "number of http requests", "logid", "endpoint"),
		rspcnt: mf.NewCounter("http_rsp", "number of http requests", "logid", "endpoint", "status"),
		latency: mf.NewHistogramWithBuckets("http_latency", "http request-response latency",
			buckets, "logid", "endpoint", "status"),
	}
}

type witnessMetrics struct {
	probeCount    monitoring.Counter   // number of cosignature requests (grouped by witness and status)
	probeLatency  monitoring.Histogram // latency of successful cosignature requests (grouped by witness)
	quorumLatency monitoring.Histogram // latency until reaching a witness quorum (if configured)
}

func (m *witnessMetrics) RecordWitnessProbe(witnessID string, status string) {
	m.probeCount.Inc(witnessID, status)
}

func (m *witnessMetrics) RecordWitnessLatency(witnessID string, d time.Duration) {
	m.probeLatency.Observe(d.Seconds(), witnessID)
}

func (m *witnessMetrics) RecordWitnessQuorumLatency(d time.Duration) {
	m.quorumLatency.Observe(d.Seconds())
}

func NewWitnessMetrics() witness.WitnessMetrics {
	mf := prometheus.MetricFactory{}
	// Interval 1ms to 10s, with thresholds roughly a factor
	// 10^{1/4} \appr 1.8 apart.
	buckets := []float64{1e-3, 2e-3, 3e-3, 6e-3, 10e-3, 20e-3, 30e-3, 60e-3, 0.1, 0.2, 0.3, 0.6, 1, 2, 3, 6, 10}

	return &witnessMetrics{
		probeCount:    mf.NewCounter("witness_probe_total", "number of witness add-checkpoint probes", "witness", "status"),
		probeLatency:  mf.NewHistogramWithBuckets("witness_probe_latency", "witness add-checkpoint latency on success", buckets, "witness"),
		quorumLatency: mf.NewHistogramWithBuckets("witness_quorum_latency", "witness quorum latency", buckets),
	}
}
