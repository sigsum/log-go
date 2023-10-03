package primary

import (
	"net/http"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/sigsum-go/pkg/server"
	"sigsum.org/sigsum-go/pkg/submit-token"
//	"sigsum.org/sigsum-go/pkg/types"
)

// Primary is an instance of the log's primary node
type Primary struct {
	Config        handler.Config
	MaxRange      int                // Maximum number of leaves per get-leaves request
	DbClient      db.Client          // provides access to the backend, usually Trillian
	Stateman      state.StateManager // coordinates access to (co)signed tree heads
	TokenVerifier *token.DnsVerifier // checks if domain name knows a public key
	RateLimiter   rateLimit.Limiter
}

// PublicHTTPHandler registers all external handlers
func (p Primary) PublicHTTPHandler(prefix string) http.Handler {
	return server.NewLog(&server.Config{
		Prefix: prefix,
		Timeout: p.Config.Timeout,
		Metrics: handler.NewServerMetrics(p.Config.LogID),
	}, p)
}

// InternalHTTPMux() registers all internal handlers
func (p Primary) InternalHTTPHandler(prefix string) http.Handler {
	s := server.NewServer(&server.Config{
		Prefix: prefix,
		Timeout: p.Config.Timeout,
		// Uses same log id, but different endpoints.
		Metrics: handler.NewServerMetrics(p.Config.LogID),
	})
	server.RegisterGetLeavesHandler(s, p.getLeavesInternal)
	return s
}
