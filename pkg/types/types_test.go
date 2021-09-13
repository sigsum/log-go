package types

import (
	"testing"
)

func TestEndpointPath(t *testing.T) {
	base, prefix, proto := "example.com", "log", "sigsum/v0"
	for _, table := range []struct {
		endpoint Endpoint
		want     string
	}{
		{
			endpoint: EndpointAddLeaf,
			want:     "example.com/log/sigsum/v0/add-leaf",
		},
		{
			endpoint: EndpointAddCosignature,
			want:     "example.com/log/sigsum/v0/add-cosignature",
		},
		{
			endpoint: EndpointGetTreeHeadLatest,
			want:     "example.com/log/sigsum/v0/get-tree-head-latest",
		},
		{
			endpoint: EndpointGetTreeHeadToSign,
			want:     "example.com/log/sigsum/v0/get-tree-head-to-sign",
		},
		{
			endpoint: EndpointGetTreeHeadCosigned,
			want:     "example.com/log/sigsum/v0/get-tree-head-cosigned",
		},
		{
			endpoint: EndpointGetConsistencyProof,
			want:     "example.com/log/sigsum/v0/get-consistency-proof",
		},
		{
			endpoint: EndpointGetInclusionProof,
			want:     "example.com/log/sigsum/v0/get-inclusion-proof",
		},
		{
			endpoint: EndpointGetLeaves,
			want:     "example.com/log/sigsum/v0/get-leaves",
		},
	} {
		if got, want := table.endpoint.Path(base+"/"+prefix+"/"+proto), table.want; got != want {
			t.Errorf("got endpoint\n%s\n\tbut wanted\n%s\n\twith one component", got, want)
		}
		if got, want := table.endpoint.Path(base, prefix, proto), table.want; got != want {
			t.Errorf("got endpoint\n%s\n\tbut wanted\n%s\n\tmultiple components", got, want)
		}
	}
}

func TestTreeHeadSign(t *testing.T)           {}
func TestTreeHeadVerify(t *testing.T)         {}
func TestInclusionProofVerify(t *testing.T)   {}
func TestConsistencyProofVerify(t *testing.T) {}
