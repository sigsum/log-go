package primary

import (
	"net/http"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/sigsum-go/pkg/crypto"
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
	Signer          crypto.Signer      // provides access to Ed25519 private key
	Stateman        state.StateManager // coordinates access to (co)signed tree heads
	TokenVerifier   token.Verifier     // checks if domain name knows a public key
	RateLimiter     rateLimit.Limiter
}

// PublicHTTPHandlers returns all external handlers
func (p Primary) PublicHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{p.Config, addLeaf(p), types.EndpointAddLeaf, http.MethodPost},
		handler.Handler{p.Config, addCosignature(p), types.EndpointAddCosignature, http.MethodPost},
		handler.Handler{p.Config, getTreeHeadToCosign(p), types.EndpointGetTreeHeadToCosign, http.MethodGet},
		handler.Handler{p.Config, getTreeHeadCosigned(p), types.EndpointGetTreeHeadCosigned, http.MethodGet},
		handler.Handler{p.Config, getConsistencyProof(p), types.EndpointGetConsistencyProof, http.MethodGet},
		handler.Handler{p.Config, getInclusionProof(p), types.EndpointGetInclusionProof, http.MethodGet},
		handler.Handler{p.Config, getLeavesExternal(p), types.EndpointGetLeaves, http.MethodGet},
	}
}

// InternalHTTPHandlers() returns all internal handlers
func (p Primary) InternalHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{p.Config, getTreeHeadUnsigned(p), types.EndpointGetTreeHeadUnsigned, http.MethodGet},
		handler.Handler{p.Config, getConsistencyProof(p), types.EndpointGetConsistencyProof, http.MethodGet},
		handler.Handler{p.Config, getLeavesInternal(p), types.EndpointGetLeaves, http.MethodGet},
	}
}
