package primary

import (
	"net/http"
	"time"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

// Config is a collection of log parameters
type Config struct {
	LogID    string        // Hex-encoded public key, used as id for metrics
	MaxRange int64         // Maximum number of leaves per get-leaves request
	Timeout  time.Duration // Timeout used for gRPC requests
}

// Primary is an instance of the log's primary node
type Primary struct {
	Config
	PublicHTTPMux   *http.ServeMux
	InternalHTTPMux *http.ServeMux
	DbClient        db.Client          // provides access to the backend, usually Trillian
	Signer          crypto.Signer      // provides access to Ed25519 private key
	Stateman        state.StateManager // coordinates access to (co)signed tree heads
	TokenVerifier   token.Verifier     // checks if domain name knows a public key
	RateLimiter     rateLimit.Limiter
}

// Implementing handler.Config
func (p Primary) LogID() string {
	return p.Config.LogID
}
func (p Primary) Timeout() time.Duration {
	return p.Config.Timeout
}

// PublicHTTPHandlers returns all external handlers
func (p Primary) PublicHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{p, addLeaf(p), types.EndpointAddLeaf, http.MethodPost},
		handler.Handler{p, addCosignature(p), types.EndpointAddCosignature, http.MethodPost},
		handler.Handler{p, getTreeHeadToCosign(p), types.EndpointGetTreeHeadToCosign, http.MethodGet},
		handler.Handler{p, getTreeHeadCosigned(p), types.EndpointGetTreeHeadCosigned, http.MethodGet},
		handler.Handler{p, getConsistencyProof(p), types.EndpointGetConsistencyProof, http.MethodGet},
		handler.Handler{p, getInclusionProof(p), types.EndpointGetInclusionProof, http.MethodGet},
		handler.Handler{p, getLeavesExternal(p), types.EndpointGetLeaves, http.MethodGet},
	}
}

// InternalHTTPHandlers() returns all internal handlers
func (p Primary) InternalHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{p, getTreeHeadUnsigned(p), types.EndpointGetTreeHeadUnsigned, http.MethodGet},
		handler.Handler{p, getConsistencyProof(p), types.EndpointGetConsistencyProof, http.MethodGet},
		handler.Handler{p, getLeavesInternal(p), types.EndpointGetLeaves, http.MethodGet},
	}
}
