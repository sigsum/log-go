package metrics

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/monitoring/prometheus"

	"sigsum.org/log-go/internal/witness"
	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/server"
)

const metricPrefix = "sigsum_log_go_"

func newMetricFactory() prometheus.MetricFactory {
	return prometheus.MetricFactory{Prefix: metricPrefix}
}

type serverMetrics struct {
	reqcnt   monitoring.Counter   // number of incoming http requests
	rspcnt   monitoring.Counter   // number of valid http responses
	duration monitoring.Histogram // request-response duration
}

func (m *serverMetrics) OnRequest(endpoint string) {
	m.reqcnt.Inc(endpointLabel(endpoint))
}

func (m *serverMetrics) OnResponse(endpoint string, statusCode int, t time.Duration) {
	sc := fmt.Sprintf("%d", statusCode)
	el := endpointLabel(endpoint)
	m.rspcnt.Inc(el, sc)
	m.duration.Observe(t.Seconds(), el, sc)
}

func endpointLabel(endpoint string) string {
	return strings.TrimSuffix(endpoint, "/")
}

func NewServerMetrics() server.Metrics {
	mf := newMetricFactory()
	// Interval 1ms to 10s, with thresholds roughly a factor
	// 10^{1/4} \appr 1.8 apart.
	buckets := []float64{1e-3, 2e-3, 3e-3, 6e-3, 10e-3, 20e-3, 30e-3, 60e-3, 0.1, 0.2, 0.3, 0.6, 1, 2, 3, 6, 10}

	return &serverMetrics{
		reqcnt: mf.NewCounter("http_requests_total", "number of http requests", "endpoint"),
		rspcnt: mf.NewCounter("http_responses_total", "number of http responses", "endpoint", "status"),
		duration: mf.NewHistogramWithBuckets("http_request_duration_seconds", "http request-response durations",
			buckets, "endpoint", "status"),
	}
}

type witnessMetrics struct {
	checkpointRequests monitoring.Counter   // number of checkpoint requests (grouped by witness and status)
	checkpointDuration monitoring.Histogram // duration of successful checkpoint requests (200; 200 after 409 retry)
	quorum             monitoring.Counter   // number of witness quorum attempts (grouped by success/failure)
	quorumDuration     monitoring.Histogram // duration to reach quorum (not recorded if quorum is not reached)
}

func (m *witnessMetrics) RecordCheckpointRequest(witnessID string, retried bool, err error, elapsed time.Duration) {
	name := strings.TrimPrefix(strings.TrimPrefix(witnessID, "https://"), "http://")
	status := "200"
	if err != nil {
		var apiErr *api.Error
		if errors.As(err, &apiErr) {
			status = strconv.Itoa(apiErr.StatusCode())
		} else {
			status = "other"
		}
	}

	m.checkpointRequests.Inc(name, status, strconv.FormatBool(retried))
	if err == nil {
		m.checkpointDuration.Observe(elapsed.Seconds(), name)
	}
}

func (m *witnessMetrics) RecordQuorum(haveQuorum bool, d time.Duration) {
	m.quorum.Inc(strconv.FormatBool(haveQuorum))
	if haveQuorum {
		m.quorumDuration.Observe(d.Seconds())
	}
}

func NewWitnessMetrics() witness.WitnessMetrics {
	mf := newMetricFactory()
	// Interval 1ms to 10s, with thresholds roughly a factor
	// 10^{1/4} \appr 1.8 apart.
	buckets := []float64{1e-3, 2e-3, 3e-3, 6e-3, 10e-3, 20e-3, 30e-3, 60e-3, 0.1, 0.2, 0.3, 0.6, 1, 2, 3, 6, 10}

	return &witnessMetrics{
		checkpointRequests: mf.NewCounter("witness_checkpoint_requests_total", "number of witness add-checkpoint requests", "witness", "status", "retried"),
		checkpointDuration: mf.NewHistogramWithBuckets("witness_checkpoint_request_duration_seconds", "witness add-checkpoint request durations on success", buckets, "witness"),
		quorum:             mf.NewCounter("witness_quorum_total", "number of witness quorum attempts", "success"),
		quorumDuration:     mf.NewHistogramWithBuckets("witness_quorum_duration_seconds", "duration to reach witness quorum", buckets),
	}
}
