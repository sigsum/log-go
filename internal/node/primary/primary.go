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
	Config        handler.Config
	MaxRange      int64              // Maximum number of leaves per get-leaves request
	DbClient      db.Client          // provides access to the backend, usually Trillian
	Stateman      state.StateManager // coordinates access to (co)signed tree heads
	TokenVerifier token.Verifier     // checks if domain name knows a public key
	RateLimiter   rateLimit.Limiter
}

// PublicHTTPHandler registers all external handlers
func (p Primary) PublicHTTPMux(prefix string) *http.ServeMux {
	mux := http.NewServeMux()
	handler.Handler{p.Config, p.addLeaf, types.EndpointAddLeaf, http.MethodPost}.Register(mux, prefix)
	handler.Handler{p.Config, p.addCosignature, types.EndpointAddCosignature, http.MethodPost}.Register(mux, prefix)
	handler.Handler{p.Config, p.getNextTreeHead, types.EndpointGetNextTreeHead, http.MethodGet}.Register(mux, prefix)
	handler.Handler{p.Config, p.getTreeHead, types.EndpointGetTreeHead, http.MethodGet}.Register(mux, prefix)
	handler.Handler{p.Config, p.getConsistencyProof, types.EndpointGetConsistencyProof, http.MethodGet}.Register(mux, prefix)
	handler.Handler{p.Config, p.getInclusionProof, types.EndpointGetInclusionProof, http.MethodGet}.Register(mux, prefix)
	handler.Handler{p.Config, p.getLeavesExternal, types.EndpointGetLeaves, http.MethodGet}.Register(mux, prefix)
	return mux
}

// InternalHTTPMux() regsiters all internal handlers
func (p Primary) InternalHTTPMux(prefix string) *http.ServeMux {
	mux := http.NewServeMux()
	handler.Handler{p.Config, p.getTreeHeadUnsigned, types.EndpointGetTreeHeadUnsigned, http.MethodGet}.Register(mux, prefix)
	handler.Handler{p.Config, p.getConsistencyProof, types.EndpointGetConsistencyProof, http.MethodGet}.Register(mux, prefix)
	handler.Handler{p.Config, p.getLeavesInternal, types.EndpointGetLeaves, http.MethodGet}.Register(mux, prefix)
	return mux
}
