package primary

import (
	"crypto"
	"net/http"
	"time"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

// Config is a collection of log parameters
type Config struct {
	LogID      string        // Hex-encoded public key, used as id for metrics
	TreeID     int64         // Merkle tree identifier used by Trillian
	Prefix     string        // The portion between base URL and /<endpoint> (may be "")
	MaxRange   int64         // Maximum number of leaves per get-leaves request
	Timeout    time.Duration // Timeout used for gRPC requests
	Interval   time.Duration // Cosigning frequency
}

// Primary is an instance of the log's primary node
type Primary struct {
	Config
	PublicHTTPMux   *http.ServeMux
	InternalHTTPMux *http.ServeMux
	TrillianClient  db.Client          // provides access to the Trillian backend
	Signer          crypto.Signer      // provides access to Ed25519 private key
	Stateman        state.StateManager // coordinates access to (co)signed tree heads
	TokenVerifier   token.Verifier     // checks if domain name knows a public key
	Secondary       client.Client
}

// Implementing handler.Config
func (p Primary) Prefix() string {
	return p.Config.Prefix
}
func (p Primary) LogID() string {
	return p.Config.LogID
}
func (p Primary) Timeout() time.Duration {
	return p.Config.Timeout
}

// PublicHTTPHandlers returns all external handlers
func (p Primary) PublicHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{p, addLeaf, types.EndpointAddLeaf, http.MethodPost},
		handler.Handler{p, addCosignature, types.EndpointAddCosignature, http.MethodPost},
		handler.Handler{p, getTreeHeadToCosign, types.EndpointGetTreeHeadToCosign, http.MethodGet},
		handler.Handler{p, getTreeHeadCosigned, types.EndpointGetTreeHeadCosigned, http.MethodGet},
		handler.Handler{p, getConsistencyProof, types.EndpointGetConsistencyProof, http.MethodGet},
		handler.Handler{p, getInclusionProof, types.EndpointGetInclusionProof, http.MethodGet},
		handler.Handler{p, getLeavesExternal, types.EndpointGetLeaves, http.MethodGet},
	}
}

// InternalHTTPHandlers() returns all internal handlers
func (p Primary) InternalHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{p, getTreeHeadUnsigned, types.EndpointGetTreeHeadUnsigned, http.MethodGet},
		handler.Handler{p, getConsistencyProof, types.EndpointGetConsistencyProof, http.MethodGet},
		handler.Handler{p, getLeavesInternal, types.EndpointGetLeaves, http.MethodGet},
	}
}
