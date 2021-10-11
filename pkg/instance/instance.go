package instance

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"time"

	"git.sigsum.org/sigsum-log-go/pkg/dns"
	"git.sigsum.org/sigsum-log-go/pkg/state"
	"git.sigsum.org/sigsum-log-go/pkg/trillian"
	"git.sigsum.org/sigsum-log-go/pkg/types"
	"github.com/golang/glog"
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
	ShardEnd   uint64        // Shard interval end (num seconds since UNIX epoch)

	// Witnesses map trusted witness identifiers to public verification keys
	Witnesses map[[types.HashSize]byte][types.VerificationKeySize]byte
}

// Instance is an instance of the log's front-end
type Instance struct {
	Config                      // configuration parameters
	Client   trillian.Client    // provides access to the Trillian backend
	Signer   crypto.Signer      // provides access to Ed25519 private key
	Stateman state.StateManager // coordinates access to (co)signed tree heads
	DNS      dns.Verifier       // checks if domain name knows a public key
}

// Handler implements the http.Handler interface, and contains a reference
// to a sigsum server instance as well as a function that uses it.
type Handler struct {
	Instance *Instance
	Endpoint types.Endpoint
	Method   string
	Handler  func(context.Context, *Instance, http.ResponseWriter, *http.Request) (int, error)
}

// Handlers returns a list of sigsum handlers
func (i *Instance) Handlers() []Handler {
	return []Handler{
		Handler{Instance: i, Handler: addLeaf, Endpoint: types.EndpointAddLeaf, Method: http.MethodPost},
		Handler{Instance: i, Handler: addCosignature, Endpoint: types.EndpointAddCosignature, Method: http.MethodPost},
		Handler{Instance: i, Handler: getTreeHeadLatest, Endpoint: types.EndpointGetTreeHeadLatest, Method: http.MethodGet},
		Handler{Instance: i, Handler: getTreeHeadToSign, Endpoint: types.EndpointGetTreeHeadToSign, Method: http.MethodGet},
		Handler{Instance: i, Handler: getTreeHeadCosigned, Endpoint: types.EndpointGetTreeHeadCosigned, Method: http.MethodGet},
		Handler{Instance: i, Handler: getConsistencyProof, Endpoint: types.EndpointGetConsistencyProof, Method: http.MethodPost},
		Handler{Instance: i, Handler: getInclusionProof, Endpoint: types.EndpointGetInclusionProof, Method: http.MethodPost},
		Handler{Instance: i, Handler: getLeaves, Endpoint: types.EndpointGetLeaves, Method: http.MethodPost},
	}
}

// Path returns a path that should be configured for this handler
func (h Handler) Path() string {
	if len(h.Instance.Prefix) == 0 {
		return h.Endpoint.Path("", "sigsum", "v0")
	}
	return h.Endpoint.Path("", h.Instance.Prefix, "sigsum", "v0")
}

// ServeHTTP is part of the http.Handler interface
func (a Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// export prometheus metrics
	var now time.Time = time.Now()
	var statusCode int
	defer func() {
		rspcnt.Inc(a.Instance.LogID, string(a.Endpoint), fmt.Sprintf("%d", statusCode))
		latency.Observe(time.Now().Sub(now).Seconds(), a.Instance.LogID, string(a.Endpoint), fmt.Sprintf("%d", statusCode))
	}()
	reqcnt.Inc(a.Instance.LogID, string(a.Endpoint))

	ctx, cancel := context.WithDeadline(r.Context(), now.Add(a.Instance.Deadline))
	defer cancel()

	if r.Method != a.Method {
		glog.Warningf("%s/%s: got HTTP %s, wanted HTTP %s", a.Instance.Prefix, string(a.Endpoint), r.Method, a.Method)
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	statusCode, err := a.Handler(ctx, a.Instance, w, r)
	if err != nil {
		glog.Warningf("handler error %s/%s: %v", a.Instance.Prefix, a.Endpoint, err)
		http.Error(w, fmt.Sprintf("%s%s%s%s", "Error", types.Delim, err.Error(), types.EOL), statusCode)
	}
}

func (i *Instance) leafRequestFromHTTP(ctx context.Context, r *http.Request) (*types.LeafRequest, error) {
	var req types.LeafRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}

	vk := ed25519.PublicKey(req.VerificationKey[:])
	msg := req.Message.Marshal()
	sig := req.Signature[:]
	if !ed25519.Verify(vk, msg, sig) {
		return nil, fmt.Errorf("invalid signature")
	}
	if req.ShardHint < i.ShardStart {
		return nil, fmt.Errorf("invalid shard hint: %d not in [%d, %d]", req.ShardHint, i.ShardStart, i.ShardEnd)
	}
	if req.ShardHint > i.ShardEnd {
		return nil, fmt.Errorf("invalid shard hint: %d not in [%d, %d]", req.ShardHint, i.ShardStart, i.ShardEnd)
	}
	if err := i.DNS.Verify(ctx, req.DomainHint, req.VerificationKey); err != nil {
		return nil, fmt.Errorf("invalid domain hint: %v", err)
	}
	return &req, nil
}

func (i *Instance) cosignatureRequestFromHTTP(r *http.Request) (*types.CosignatureRequest, error) {
	var req types.CosignatureRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}
	if _, ok := i.Witnesses[*req.KeyHash]; !ok {
		return nil, fmt.Errorf("Unknown witness: %x", req.KeyHash)
	}
	return &req, nil
}

func (i *Instance) consistencyProofRequestFromHTTP(r *http.Request) (*types.ConsistencyProofRequest, error) {
	var req types.ConsistencyProofRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}
	if req.OldSize < 1 {
		return nil, fmt.Errorf("OldSize(%d) must be larger than zero", req.OldSize)
	}
	if req.NewSize <= req.OldSize {
		return nil, fmt.Errorf("NewSize(%d) must be larger than OldSize(%d)", req.NewSize, req.OldSize)
	}
	return &req, nil
}

func (i *Instance) inclusionProofRequestFromHTTP(r *http.Request) (*types.InclusionProofRequest, error) {
	var req types.InclusionProofRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}
	if req.TreeSize < 2 {
		// TreeSize:0 => not possible to prove inclusion of anything
		// TreeSize:1 => you don't need an inclusion proof (it is always empty)
		return nil, fmt.Errorf("TreeSize(%d) must be larger than one", req.TreeSize)
	}
	return &req, nil
}

func (i *Instance) leavesRequestFromHTTP(r *http.Request) (*types.LeavesRequest, error) {
	var req types.LeavesRequest
	if err := req.UnmarshalASCII(r.Body); err != nil {
		return nil, fmt.Errorf("UnmarshalASCII: %v", err)
	}

	if req.StartSize > req.EndSize {
		return nil, fmt.Errorf("StartSize(%d) must be less than or equal to EndSize(%d)", req.StartSize, req.EndSize)
	}
	if req.EndSize-req.StartSize+1 > uint64(i.MaxRange) {
		req.EndSize = req.StartSize + uint64(i.MaxRange) - 1
	}
	return &req, nil
}
