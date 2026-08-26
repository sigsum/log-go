package metrics

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"sigsum.org/log-go/internal/witness"
	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/types"
)

type ServerMetrics struct {
	reqInFlight prometheus.Gauge
	reqCount    *prometheus.CounterVec
	reqDuration *prometheus.HistogramVec
}

func NewServerMetrics(reg prometheus.Registerer) *ServerMetrics {
	m := &ServerMetrics{
		reqInFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "http_in_flight_requests",
				Help: "Current number of HTTP requests being served.",
			},
		),
		reqCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests served.",
			},
			[]string{"endpoint", "code"},
		),
		reqDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request serving latencies in seconds.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"endpoint", "code"},
		),
	}
	reg.MustRegister(m.reqInFlight, m.reqCount, m.reqDuration)

	return m
}

func (m *ServerMetrics) Decorator(next http.Handler, endpoint types.Endpoint) http.Handler {
	labels := prometheus.Labels{"endpoint": strings.TrimSuffix(string(endpoint), "/")}
	chain := next
	chain = promhttp.InstrumentHandlerCounter(m.reqCount.MustCurryWith(labels), chain)
	chain = promhttp.InstrumentHandlerDuration(m.reqDuration.MustCurryWith(labels), chain)
	chain = promhttp.InstrumentHandlerInFlight(m.reqInFlight, chain)
	return chain
}

type witnessMetrics struct {
	checkpointRequests *prometheus.CounterVec   // number of checkpoint requests (grouped by witness and status)
	checkpointDuration *prometheus.HistogramVec // duration of successful checkpoint requests (200; 200 after 409 retry)
	quorum             *prometheus.CounterVec   // number of witness quorum attempts (grouped by success/failure)
	quorumDuration     prometheus.Histogram     // duration to reach quorum (not recorded if quorum is not reached)
}

func NewWitnessMetrics(reg prometheus.Registerer) witness.WitnessMetrics {
	m := &witnessMetrics{
		checkpointRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "witness_checkpoint_requests_total",
				Help: "Total number of witness add-checkpoint requests.",
			},
			[]string{"witness", "status", "retried"},
		),
		checkpointDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "witness_checkpoint_request_duration_seconds",
				Help:    "Witness add-checkpoint request durations on success.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"witness"},
		),
		quorum: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "witness_quorum_total",
				Help: "Total number of witness quorum attempts.",
			},
			[]string{"success"},
		),
		quorumDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "witness_quorum_duration_seconds",
				Help:    "Duration to reach witness quorum.",
				Buckets: prometheus.DefBuckets,
			},
		),
	}
	reg.MustRegister(m.checkpointRequests, m.checkpointDuration, m.quorum, m.quorumDuration)

	return m
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

	m.checkpointRequests.WithLabelValues(name, status, strconv.FormatBool(retried)).Inc()
	if err == nil {
		m.checkpointDuration.WithLabelValues(name).Observe(elapsed.Seconds())
	}
}

func (m *witnessMetrics) RecordQuorum(haveQuorum bool, d time.Duration) {
	m.quorum.WithLabelValues(strconv.FormatBool(haveQuorum)).Inc()
	if haveQuorum {
		m.quorumDuration.Observe(d.Seconds())
	}
}
