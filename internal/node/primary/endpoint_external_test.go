package primary

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"sigsum.org/log-go/internal/db"
	mocksDB "sigsum.org/log-go/internal/mocks/db"
	mocksState "sigsum.org/log-go/internal/mocks/state"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestAddLeaf(t *testing.T) {
	// TODO: Add tests for rate limiting.
	for _, table := range []struct {
		description string
		req         requests.Leaf
		errTrillian error // error from Trillian client
		wantCode    int   // HTTP status
		committed   bool
		leafStatus  db.AddLeafStatus // return value from db.AddLeaf()
	}{
		{
			description: "invalid: bad request (signature error)",
			req:         mustLeaf(t, crypto.Hash{}, false),
			wantCode:    http.StatusForbidden,
		},
		{
			description: "invalid: backend failure",
			req:         mustLeaf(t, crypto.Hash{}, true),
			errTrillian: fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid: 202",
			req:         mustLeaf(t, crypto.Hash{}, true),
		},
		{
			description: "valid: 200",
			req:         mustLeaf(t, crypto.Hash{}, true),
			leafStatus:  db.AddLeafStatus{IsSequenced: true},
			committed:   true,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksDB.NewMockClient(ctrl)
			client.EXPECT().AddLeaf(gomock.Any(), gomock.Any(), gomock.Any()).Return(table.leafStatus, table.errTrillian).AnyTimes()

			stateman := mocksState.NewMockStateManager(ctrl)
			stateman.EXPECT().SignedTreeHead().Return(types.SignedTreeHead{}).AnyTimes()
			node := Primary{
				DbClient:    client,
				Stateman:    stateman,
				RateLimiter: rateLimit.NoLimit{},
			}

			committed, err := node.AddLeaf(context.Background(), table.req, nil)
			if err := checkError(err, table.wantCode); err != nil {
				t.Errorf("in test %q: %v", table.description, err)
			} else if got, want := committed, table.committed; got != want {
				t.Errorf("unexpected commit status, got %v, wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeHead(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	stateman := mocksState.NewMockStateManager(ctrl)

	cth := types.CosignedTreeHead{}
	cth.Size = 10

	stateman.EXPECT().CosignedTreeHead().Return(cth)

	node := Primary{
		Stateman: stateman,
	}

	got, err := node.GetTreeHead(context.Background())
	if err != nil {
		t.Fatalf("GetTreeHead failed: %v", err)
	}
	// For simplicity, doesn't compare the (nil) cosignature lists.
	if got.SignedTreeHead != cth.SignedTreeHead {
		t.Errorf("Bad result from GetTreeHead: got %v, expected %v", got, cth)
	}
}

func TestGetConsistencyProof(t *testing.T) {
	for _, table := range []struct {
		description string
		req         requests.ConsistencyProof
		sthSize     uint64
		rsp         types.ConsistencyProof // consistency proof from Trillian client
		err         error                  // error from Trillian client
		wantCode    int                    // HTTP status ok
	}{
		{
			description: "invalid: bad request (OldSize is zero)",
			req:         requests.ConsistencyProof{OldSize: 0, NewSize: 1},
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (OldSize > NewSize)",
			req:         requests.ConsistencyProof{OldSize: 2, NewSize: 1},
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (NewSize > tree size)",
			req:         requests.ConsistencyProof{OldSize: 1, NewSize: 2},
			sthSize:     1,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			req:         requests.ConsistencyProof{OldSize: 1, NewSize: 2},
			sthSize:     2,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			req:         requests.ConsistencyProof{OldSize: 1, NewSize: 2},
			sthSize:     2,
			rsp: types.ConsistencyProof{
				Path: []crypto.Hash{
					crypto.HashBytes([]byte{}),
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksDB.NewMockClient(ctrl)
			if table.err != nil || table.rsp.Path != nil {
				client.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			stateman := mocksState.NewMockStateManager(ctrl)
			stateman.EXPECT().CosignedTreeHead().Return(
				types.CosignedTreeHead{SignedTreeHead: types.SignedTreeHead{TreeHead: types.TreeHead{Size: table.sthSize}}}).AnyTimes()

			node := Primary{
				DbClient: client,
				Stateman: stateman,
			}

			proof, err := node.GetConsistencyProof(context.Background(), table.req)
			if err := checkError(err, table.wantCode); err != nil {
				t.Errorf("in test %q: %v", table.description, err)
			} else if !pathIsEqual(proof.Path, table.rsp.Path) {
				t.Errorf("unexpected proof, got %x, wanted %x", proof, table.rsp)
			}
		}()
	}
}

func TestGetInclusionProof(t *testing.T) {
	for _, table := range []struct {
		description string
		req         requests.InclusionProof
		sthSize     uint64
		rsp         types.InclusionProof // inclusion proof from Trillian client
		err         error                // error from Trillian client
		wantCode    int                  // HTTP status ok
	}{
		{
			description: "invalid: bad request (no proof available for tree size 1)",
			req:         requests.InclusionProof{Size: 1},
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (request outside current tree size)",
			req:         requests.InclusionProof{Size: 2},
			sthSize:     1,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			req:         requests.InclusionProof{Size: 2},
			sthSize:     2,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "invalid: not included",
			req:         requests.InclusionProof{Size: 2},
			sthSize:     2,
			err:         db.ErrNotIncluded,
			wantCode:    http.StatusNotFound,
		},
		{
			description: "valid",
			req:         requests.InclusionProof{Size: 2},
			sthSize:     2,
			rsp: types.InclusionProof{
				LeafIndex: 0,
				Path: []crypto.Hash{
					crypto.HashBytes([]byte{}),
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksDB.NewMockClient(ctrl)
			if table.err != nil || table.rsp.Path != nil {
				client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			stateman := mocksState.NewMockStateManager(ctrl)
			stateman.EXPECT().CosignedTreeHead().Return(
				types.CosignedTreeHead{SignedTreeHead: types.SignedTreeHead{TreeHead: types.TreeHead{Size: table.sthSize}}}).AnyTimes()

			node := Primary{
				DbClient: client,
				Stateman: stateman,
			}

			proof, err := node.GetInclusionProof(context.Background(), table.req)
			if err := checkError(err, table.wantCode); err != nil {
				t.Errorf("in test %q: %v", table.description, err)
			} else if proof.LeafIndex != table.rsp.LeafIndex || !pathIsEqual(proof.Path, table.rsp.Path) {
				t.Errorf("unexpected proof, got %x, wanted %x", proof, table.rsp)
			}
		}()
	}
}

func TestGetLeaves(t *testing.T) {
	const testMaxRange = 3

	for _, table := range []struct {
		description string
		req         requests.Leaves
		sthSize     uint64
		leafCount   int   // expected number of leaves
		err         error // error from Trillian client
		wantCode    int   // HTTP status ok
	}{
		{
			description: "invalid: bad request (StartIndex >= EndIndex)",
			req:         requests.Leaves{StartIndex: 1, EndIndex: 1},
			sthSize:     2,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (EndIndex > current tree size)",
			req:         requests.Leaves{StartIndex: 0, EndIndex: 3},
			sthSize:     2,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			req:         requests.Leaves{StartIndex: 0, EndIndex: 1},
			sthSize:     2,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "invalid: empty tree",
			req:         requests.Leaves{StartIndex: 0, EndIndex: 1},
			sthSize:     0,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid: three middle elements",
			req:         requests.Leaves{StartIndex: 1, EndIndex: 4},
			sthSize:     5,
			leafCount:   3,
		},
		{
			description: "valid: one more entry than the configured MaxRange",
			req:         requests.Leaves{StartIndex: 0, EndIndex: testMaxRange + 1}, // query will be pruned
			sthSize:     5,                                                          // > testMaxRange
			leafCount:   testMaxRange,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksDB.NewMockClient(ctrl)
			if table.err != nil || table.leafCount > 0 {
				client.EXPECT().GetLeaves(gomock.Any(), gomock.Any()).DoAndReturn(
					func(_ context.Context, req *requests.Leaves) ([]types.Leaf, error) {
						if table.err != nil {
							return nil, table.err
						}
						if req.EndIndex <= req.StartIndex {
							t.Fatalf("invalid call to GetLeaves")
						}
						count := int(req.EndIndex - req.StartIndex)
						var list []types.Leaf
						for i := 0; i < count; i++ {
							list = append(list, types.Leaf{
								Checksum:  crypto.Hash{},
								Signature: crypto.Signature{},
								KeyHash:   crypto.Hash{},
							})
						}
						return list, nil
					})
			}
			stateman := mocksState.NewMockStateManager(ctrl)
			stateman.EXPECT().CosignedTreeHead().Return(
				types.CosignedTreeHead{SignedTreeHead: types.SignedTreeHead{TreeHead: types.TreeHead{Size: table.sthSize}}}).AnyTimes()

			node := Primary{
				DbClient: client,
				Stateman: stateman,
				MaxRange: testMaxRange,
			}

			leaves, err := node.GetLeaves(context.Background(), table.req)
			if err := checkError(err, table.wantCode); err != nil {
				t.Errorf("in test %q: %v", table.description, err)
			} else if got, want := len(leaves), table.leafCount; got != want {
				t.Errorf("got %d leaves, but wanted %d in test %q", got, want, table.description)
			}
		}()
	}
}

func mustLeaf(t *testing.T, msg crypto.Hash, wantSig bool) requests.Leaf {
	t.Helper()

	vk, sk, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("must generate ed25519 keys: %v", err)
	}
	sig, err := types.SignLeafMessage(sk, msg[:])
	if err != nil {
		t.Fatalf("must have an ed25519 signature: %v", err)
	}
	if !wantSig {
		sig[0] += 1
	}
	return requests.Leaf{
		Message:   msg,
		Signature: sig,
		PublicKey: vk,
	}
}

func pathIsEqual(a []crypto.Hash, b []crypto.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i, h := range a {
		if h != b[i] {
			return false
		}
	}
	return true
}

func checkError(err error, code int) error {
	if err != nil {
		if got := api.ErrorStatusCode(err); got != code || code == 0 {
			return fmt.Errorf("got HTTP status code %v but wanted %v: %v", got, code, err)
		}
		return nil
	}
	if code != 0 {
		return fmt.Errorf("no error, expected error with status %d", code)
	}
	return nil
}
