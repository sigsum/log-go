package primary

import (
	"net/http"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

// Primary is an instance of the log's primary node
type Primary struct {
	Config          handler.Config
	MaxRange        int64 // Maximum number of leaves per get-leaves request
	PublicHTTPMux   *http.ServeMux
	InternalHTTPMux *http.ServeMux
	DbClient        db.Client          // provides access to the backend, usually Trillian
	Stateman        state.StateManager // coordinates access to (co)signed tree heads
	TokenVerifier   token.Verifier     // checks if domain name knows a public key
	RateLimiter     rateLimit.Limiter
}

// PublicHTTPHandlers returns all external handlers
func (p Primary) PublicHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{p.Config, p.addLeaf, types.EndpointAddLeaf, http.MethodPost},
		handler.Handler{p.Config, p.addCosignature, types.EndpointAddCosignature, http.MethodPost},
		handler.Handler{p.Config, p.getNextTreeHead, types.EndpointGetNextTreeHead, http.MethodGet},
		handler.Handler{p.Config, p.getTreeHead, types.EndpointGetTreeHead, http.MethodGet},
		handler.Handler{p.Config, p.getConsistencyProof, types.EndpointGetConsistencyProof, http.MethodGet},
		handler.Handler{p.Config, p.getInclusionProof, types.EndpointGetInclusionProof, http.MethodGet},
		handler.Handler{p.Config, p.getLeavesExternal, types.EndpointGetLeaves, http.MethodGet},
	}
}

// InternalHTTPHandlers() returns all internal handlers
func (p Primary) InternalHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{p.Config, p.getTreeHeadUnsigned, types.EndpointGetTreeHeadUnsigned, http.MethodGet},
		handler.Handler{p.Config, p.getConsistencyProof, types.EndpointGetConsistencyProof, http.MethodGet},
		handler.Handler{p.Config, p.getLeavesInternal, types.EndpointGetLeaves, http.MethodGet},
	}
}
