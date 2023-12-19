package primary

import (
	// "sigsum.org/log-go/internal/node/handler"
	"sigsum.org/sigsum-go/pkg/crypto"
	// "sigsum.org/sigsum-go/pkg/types"
)

var (
	testWitVK  = crypto.PublicKey{}
	testMaxRange = 3
)

// TODO: Move tests to sigsum server pkg, log_test.go.

// // TestPublicHandlers checks that the expected external handlers are configured
// func TestPublicHandlers(t *testing.T) {
// 	node := Primary{
// 		Config:   testConfig,
// 		MaxRange: testMaxRange,
// 	}
// 	mux := node.PublicHTTPHandler("")
// 	for _, endpoint := range []types.Endpoint{
// 		types.EndpointAddLeaf,
// 		types.EndpointGetTreeHead,
// 		types.EndpointGetConsistencyProof,
// 		types.EndpointGetInclusionProof,
// 		types.EndpointGetLeaves,
// 	} {
// 		req, err := http.NewRequest(http.MethodGet, endpoint.Path(""), nil)
// 		if err != nil {
// 			t.Fatalf("create http request failed: %v", err)
// 		}
// 		if _, pattern := mux.Handler(req); pattern == "" {
// 			t.Errorf("endpoint %s not registered", endpoint)
// 		}
// 	}
// }
//
// // TestIntHandlers checks that the expected internal handlers are configured
// func TestIntHandlers(t *testing.T) {
// 	node := Primary{
// 		Config:   testConfig,
// 		MaxRange: testMaxRange,
// 	}
// 	prefix := "int"
// 	mux := node.InternalHTTPMux(prefix)
// 	for _, endpoint := range []types.Endpoint{
// 		types.EndpointGetLeaves,
// 	} {
// 		req, err := http.NewRequest(http.MethodGet, "/"+endpoint.Path(prefix), nil)
// 		if err != nil {
// 			t.Fatalf("create http request failed: %v", err)
// 		}
// 		if _, pattern := mux.Handler(req); pattern == "" {
// 			t.Errorf("internal endpoint %s not registered", endpoint)
// 		}
// 	}
// }
