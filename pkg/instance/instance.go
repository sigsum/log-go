package instance

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"time"

	"git.sigsum.org/sigsum-lib-go/pkg/requests"
	"git.sigsum.org/sigsum-lib-go/pkg/types"
	"git.sigsum.org/sigsum-log-go/pkg/db"
	"git.sigsum.org/sigsum-log-go/pkg/dns"
	"git.sigsum.org/sigsum-log-go/pkg/state"
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

	// Witnesses map trusted witness identifiers to public verification keys
	Witnesses map[types.Hash]types.PublicKey
}

// Instance is an instance of the log's front-end
type Instance struct {
	Config                      // configuration parameters
	Client   db.Client          // provides access to the Trillian backend
	Signer   crypto.Signer      // provides access to Ed25519 private key
	Stateman state.StateManager // coordinates access to (co)signed tree heads
	DNS      dns.Verifier       // checks if domain name knows a public key
}

// Handlers returns a list of sigsum handlers
func (i *Instance) Handlers() []Handler {
	return []Handler{
		Handler{Instance: i, Handler: addLeaf, Endpoint: types.EndpointAddLeaf, Method: http.MethodPost},
		Handler{Instance: i, Handler: addCosignature, Endpoint: types.EndpointAddCosignature, Method: http.MethodPost},
		Handler{Instance: i, Handler: getTreeHeadToCosign, Endpoint: types.EndpointGetTreeHeadToSign, Method: http.MethodGet}, // XXX: ToCosign
		Handler{Instance: i, Handler: getTreeHeadCosigned, Endpoint: types.EndpointGetTreeHeadCosigned, Method: http.MethodGet},
		Handler{Instance: i, Handler: getCheckpoint, Endpoint: types.Endpoint("get-checkpoint"), Method: http.MethodGet},
		Handler{Instance: i, Handler: getConsistencyProof, Endpoint: types.EndpointGetConsistencyProof, Method: http.MethodPost},
		Handler{Instance: i, Handler: getInclusionProof, Endpoint: types.EndpointGetInclusionProof, Method: http.MethodPost},
		Handler{Instance: i, Handler: getLeaves, Endpoint: types.EndpointGetLeaves, Method: http.MethodPost},
	}
}

// checkHTTPMethod checks if an HTTP method is supported
func (i *Instance) checkHTTPMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodPost
}

func (i *Instance) leafRequestFromHTTP(ctx context.Context, r *http.Request) (*requests.Leaf, error) {
	var req requests.Leaf
	if err := req.FromASCII(r.Body); err != nil {
		return nil, fmt.Errorf("FromASCII: %v", err)
	}
	stmt := types.Statement{
		ShardHint: req.ShardHint,
		Checksum:  *types.HashFn(req.Preimage[:]),
	}
	if !stmt.Verify(&req.VerificationKey, &req.Signature) {
		return nil, fmt.Errorf("invalid signature")
	}
	shardEnd := uint64(time.Now().Unix())
	if req.ShardHint < i.ShardStart {
		return nil, fmt.Errorf("invalid shard hint: %d not in [%d, %d]", req.ShardHint, i.ShardStart, shardEnd)
	}
	if req.ShardHint > shardEnd {
		return nil, fmt.Errorf("invalid shard hint: %d not in [%d, %d]", req.ShardHint, i.ShardStart, shardEnd)
	}
	if err := i.DNS.Verify(ctx, req.DomainHint, &req.VerificationKey); err != nil {
		return nil, fmt.Errorf("invalid domain hint: %v", err)
	}
	return &req, nil
}

func (i *Instance) cosignatureRequestFromHTTP(r *http.Request) (*requests.Cosignature, error) {
	var req requests.Cosignature
	if err := req.FromASCII(r.Body); err != nil {
		return nil, fmt.Errorf("FromASCII: %v", err)
	}
	if _, ok := i.Witnesses[req.KeyHash]; !ok {
		return nil, fmt.Errorf("Unknown witness: %x", req.KeyHash)
	}
	return &req, nil
}

func (i *Instance) consistencyProofRequestFromHTTP(r *http.Request) (*requests.ConsistencyProof, error) {
	var req requests.ConsistencyProof
	if err := req.FromASCII(r.Body); err != nil {
		return nil, fmt.Errorf("FromASCII: %v", err)
	}
	if req.OldSize < 1 {
		return nil, fmt.Errorf("OldSize(%d) must be larger than zero", req.OldSize)
	}
	if req.NewSize <= req.OldSize {
		return nil, fmt.Errorf("NewSize(%d) must be larger than OldSize(%d)", req.NewSize, req.OldSize)
	}
	return &req, nil
}

func (i *Instance) inclusionProofRequestFromHTTP(r *http.Request) (*requests.InclusionProof, error) {
	var req requests.InclusionProof
	if err := req.FromASCII(r.Body); err != nil {
		return nil, fmt.Errorf("FromASCII: %v", err)
	}
	if req.TreeSize < 2 {
		// TreeSize:0 => not possible to prove inclusion of anything
		// TreeSize:1 => you don't need an inclusion proof (it is always empty)
		return nil, fmt.Errorf("TreeSize(%d) must be larger than one", req.TreeSize)
	}
	return &req, nil
}

func (i *Instance) leavesRequestFromHTTP(r *http.Request) (*requests.Leaves, error) {
	var req requests.Leaves
	if err := req.FromASCII(r.Body); err != nil {
		return nil, fmt.Errorf("FromASCII: %v", err)
	}

	if req.StartSize > req.EndSize {
		return nil, fmt.Errorf("StartSize(%d) must be less than or equal to EndSize(%d)", req.StartSize, req.EndSize)
	}
	if req.EndSize-req.StartSize+1 > uint64(i.MaxRange) {
		req.EndSize = req.StartSize + uint64(i.MaxRange) - 1
	}
	return &req, nil
}
