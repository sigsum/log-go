package primary

import (
	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/sigsum-go/pkg/submit-token"
)

// Primary is an instance of the log's primary node
type Primary struct {
	MaxRange      int                // Maximum number of leaves per get-leaves request
	DbClient      db.Client          // provides access to the backend, usually Trillian
	Stateman      state.StateManager // coordinates access to (co)signed tree heads
	TokenVerifier *token.DnsVerifier // checks if domain name knows a public key
	RateLimiter   rateLimit.Limiter
}
