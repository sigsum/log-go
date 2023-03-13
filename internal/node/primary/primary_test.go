package primary

import (
	"fmt"
	"net/http"
	"testing"

	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

var (
	testWitVK  = crypto.PublicKey{}
	testConfig = handler.Config{
		LogID:   fmt.Sprintf("%x", crypto.HashBytes([]byte("logid"))),
		Timeout: 10,
	}
	testMaxRange = 3
)

// TestPublicHandlers checks that the expected external handlers are configured
func TestPublicHandlers(t *testing.T) {
	node := Primary{
		Config:   testConfig,
		MaxRange: testMaxRange,
	}
	mux := node.PublicHTTPMux("")
	for _, endpoint := range []types.Endpoint{
		types.EndpointAddLeaf,
		types.EndpointAddCosignature,
		types.EndpointGetNextTreeHead,
		types.EndpointGetTreeHead,
		types.EndpointGetConsistencyProof,
		types.EndpointGetInclusionProof,
		types.EndpointGetLeaves,
	} {
		req, err := http.NewRequest(http.MethodGet, endpoint.Path(""), nil)
		if err != nil {
			t.Fatalf("create http request failed: %v", err)
		}
		if _, pattern := mux.Handler(req); pattern == "" {
			t.Errorf("endpoint %s not registered", endpoint)
		}
	}
}

// TestIntHandlers checks that the expected internal handlers are configured
func TestIntHandlers(t *testing.T) {
	node := Primary{
		Config:   testConfig,
		MaxRange: testMaxRange,
	}
	prefix := "int"
	mux := node.InternalHTTPMux(prefix)
	for _, endpoint := range []types.Endpoint{
		types.EndpointGetLeaves,
	} {
		req, err := http.NewRequest(http.MethodGet, "/"+endpoint.Path(prefix), nil)
		if err != nil {
			t.Fatalf("create http request failed: %v", err)
		}
		if _, pattern := mux.Handler(req); pattern == "" {
			t.Errorf("internal endpoint %s not registered", endpoint)
		}
	}
}
