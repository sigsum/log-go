package primary

import (
	"crypto"
	"net/http"
	"time"

	"git.sigsum.org/log-go/internal/db"
	"git.sigsum.org/log-go/internal/node/handler"
	"git.sigsum.org/log-go/internal/state"
	"git.sigsum.org/sigsum-go/pkg/client"
	"git.sigsum.org/sigsum-go/pkg/dns"
	"git.sigsum.org/sigsum-go/pkg/merkle"
	"git.sigsum.org/sigsum-go/pkg/types"
)

// Config is a collection of log parameters
type Config struct {
	LogID      string        // H(public key), then hex-encoded
	TreeID     int64         // Merkle tree identifier used by Trillian
	Prefix     string        // The portion between base URL and st/v0 (may be "")
	MaxRange   int64         // Maximum number of leaves per get-leaves request
	Deadline   time.Duration // Deadline used for gRPC requests
	Interval   time.Duration // Cosigning frequency
	ShardStart uint64        // Shard interval start (num seconds since UNIX epoch)

	// Witnesses map trusted witness identifiers to public keys
	Witnesses map[merkle.Hash]types.PublicKey
}

// Primary is an instance of the log's primary node
type Primary struct {
	Config
	PublicHTTPMux   *http.ServeMux
	InternalHTTPMux *http.ServeMux
	TrillianClient  db.Client          // provides access to the Trillian backend
	Signer          crypto.Signer      // provides access to Ed25519 private key
	Stateman        state.StateManager // coordinates access to (co)signed tree heads
	DNS             dns.Verifier       // checks if domain name knows a public key
	Secondary       client.Client
}

// Implementing handler.Config
func (p Primary) Prefix() string {
	return p.Config.Prefix
}
func (p Primary) LogID() string {
	return p.Config.LogID
}
func (p Primary) Deadline() time.Duration {
	return p.Config.Deadline
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
