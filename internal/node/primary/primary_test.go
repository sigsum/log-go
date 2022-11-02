package primary

import (
	"fmt"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

var (
	testWitVK  = crypto.PublicKey{}
	testConfig = Config{
		LogID:    fmt.Sprintf("%x", crypto.HashBytes([]byte("logid"))),
		TreeID:   0,
		Prefix:   "testonly",
		MaxRange: 3,
		Timeout:  10,
		Interval: 10,
	}
)

// TestPublicHandlers checks that the expected external handlers are configured
func TestPublicHandlers(t *testing.T) {
	endpoints := map[types.Endpoint]bool{
		types.EndpointAddLeaf:             false,
		types.EndpointAddCosignature:      false,
		types.EndpointGetTreeHeadToCosign: false,
		types.EndpointGetTreeHeadCosigned: false,
		types.EndpointGetConsistencyProof: false,
		types.EndpointGetInclusionProof:   false,
		types.EndpointGetLeaves:           false,
	}
	node := Primary{
		Config: testConfig,
	}
	for _, handler := range node.PublicHTTPHandlers() {
		if _, ok := endpoints[handler.Endpoint]; !ok {
			t.Errorf("got unexpected endpoint: %s", handler.Endpoint)
		}
		endpoints[handler.Endpoint] = true
	}
	for endpoint, ok := range endpoints {
		if !ok {
			t.Errorf("endpoint %s is not configured", endpoint)
		}
	}
}

// TestIntHandlers checks that the expected internal handlers are configured
func TestIntHandlers(t *testing.T) {
	endpoints := map[types.Endpoint]bool{
		types.EndpointGetTreeHeadUnsigned: false,
		types.EndpointGetConsistencyProof: false,
		types.EndpointGetLeaves:           false,
	}
	node := Primary{
		Config: testConfig,
	}
	for _, handler := range node.InternalHTTPHandlers() {
		if _, ok := endpoints[handler.Endpoint]; !ok {
			t.Errorf("got unexpected endpoint: %s", handler.Endpoint)
		}
		endpoints[handler.Endpoint] = true
	}
	for endpoint, ok := range endpoints {
		if !ok {
			t.Errorf("endpoint %s is not configured", endpoint)
		}
	}
}
