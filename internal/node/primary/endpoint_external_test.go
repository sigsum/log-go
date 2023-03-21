package primary

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"sigsum.org/log-go/internal/db"
	mocksDB "sigsum.org/log-go/internal/mocks/db"
	mocksState "sigsum.org/log-go/internal/mocks/state"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// TODO: remove tests that are now located in internal/requests instead

func TestAddLeaf(t *testing.T) {
	// TODO: Set up a mock rate limiter.
	for _, table := range []struct {
		description string
		ascii       string           // body of HTTP request
		errTrillian error            // error from Trillian client
		wantCode    int              // HTTP status ok
		leafStatus  db.AddLeafStatus // return value from db.AddLeaf()
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       "key=value\n",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (signature error)",
			ascii:       mustLeafAscii(t, crypto.Hash{}, false),
			wantCode:    http.StatusForbidden,
		},
		{
			description: "invalid: backend failure",
			ascii:       mustLeafAscii(t, crypto.Hash{}, true),
			errTrillian: fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid: 202",
			ascii:       mustLeafAscii(t, crypto.Hash{}, true),
			wantCode:    http.StatusAccepted,
		},
		{
			description: "valid: 200",
			ascii:       mustLeafAscii(t, crypto.Hash{}, true),
			leafStatus:  db.AddLeafStatus{IsSequenced: true},
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksDB.NewMockClient(ctrl)
			client.EXPECT().AddLeaf(gomock.Any(), gomock.Any(), gomock.Any()).Return(table.leafStatus, table.errTrillian).AnyTimes()

			stateman := mocksState.NewMockStateManager(ctrl)
			stateman.EXPECT().SignedTreeHead().Return(types.CosignedTreeHead{}).AnyTimes()
			node := Primary{
				Config:      testConfig,
				DbClient:    client,
				Stateman:    stateman,
				RateLimiter: rateLimit.NoLimit{},
			}

			// Create HTTP request
			url := types.EndpointAddLeaf.Path("http://example.com")
			req, err := http.NewRequest("POST", url, bytes.NewBufferString(table.ascii))
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			node.PublicHTTPMux("").ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeHead(t *testing.T) {
	for _, table := range []struct {
		description string
		err         error // error from Trillian client
		wantCode    int   // HTTP status ok
	}{
		{
			description: "valid",
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			stateman := mocksState.NewMockStateManager(ctrl)
			stateman.EXPECT().SignedTreeHead().Return(types.CosignedTreeHead{})

			node := Primary{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHead.Path("http://example.com")
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			node.PublicHTTPMux("").ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetConsistencyProof(t *testing.T) {
	for _, table := range []struct {
		description string
		params      string // params is the query's url params
		sthSize     uint64
		rsp         types.ConsistencyProof // consistency proof from Trillian client
		err         error                  // error from Trillian client
		wantCode    int                    // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			params:      "a/1",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (OldSize is zero)",
			params:      "0/1",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (OldSize > NewSize)",
			params:      "2/1",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (NewSize > tree size)",
			params:      "1/2",
			sthSize:     1,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			params:      "1/2",
			sthSize:     2,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			params:      "1/2",
			sthSize:     2,
			rsp: types.ConsistencyProof{
				Path: []crypto.Hash{
					crypto.HashBytes([]byte{}),
				},
			},
			wantCode: http.StatusOK,
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
			stateman.EXPECT().SignedTreeHead().Return(
				types.CosignedTreeHead{SignedTreeHead: types.SignedTreeHead{TreeHead: types.TreeHead{Size: table.sthSize}}}).AnyTimes()

			node := Primary{
				Config:   testConfig,
				DbClient: client,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetConsistencyProof.Path("http://example.com")
			req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			node.PublicHTTPMux("").ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetInclusionProof(t *testing.T) {
	for _, table := range []struct {
		description string
		params      string // params is the query's url params
		sthSize     uint64
		rsp         types.InclusionProof // inclusion proof from Trillian client
		err         error                // error from Trillian client
		wantCode    int                  // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			params:      "a/0000000000000000000000000000000000000000000000000000000000000000",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (no proof available for tree size 1)",
			params:      "1/0000000000000000000000000000000000000000000000000000000000000000",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (request outside current tree size)",
			params:      "2/0000000000000000000000000000000000000000000000000000000000000000",
			sthSize:     1,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			params:      "2/0000000000000000000000000000000000000000000000000000000000000000",
			sthSize:     2,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "invalid: not included",
			params:      "2/0000000000000000000000000000000000000000000000000000000000000000",
			sthSize:     2,
			err:         db.ErrNotIncluded,
			wantCode:    http.StatusNotFound,
		},
		{
			description: "valid",
			params:      "2/0000000000000000000000000000000000000000000000000000000000000000",
			sthSize:     2,
			rsp: types.InclusionProof{
				LeafIndex: 0,
				Path: []crypto.Hash{
					crypto.HashBytes([]byte{}),
				},
			},
			wantCode: http.StatusOK,
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
			stateman.EXPECT().SignedTreeHead().Return(
				types.CosignedTreeHead{SignedTreeHead: types.SignedTreeHead{TreeHead: types.TreeHead{Size: table.sthSize}}}).AnyTimes()

			node := Primary{
				Config:   testConfig,
				DbClient: client,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetInclusionProof.Path("http://example.com")
			req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			node.PublicHTTPMux("").ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetLeaves(t *testing.T) {
	for _, table := range []struct {
		description string
		params      string // params is the query's url params
		sthSize     uint64
		leafCount   int   // expected number of leaves
		err         error // error from Trillian client
		wantCode    int   // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			params:      "a/1",
			sthSize:     2,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (StartIndex >= EndIndex)",
			params:      "1/1",
			sthSize:     2,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (EndIndex > current tree size)",
			params:      "0/3",
			sthSize:     2,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			params:      "0/1",
			sthSize:     2,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "invalid: empty tree",
			params:      "0/1",
			sthSize:     0,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid: three middle elements",
			params:      "1/4",
			sthSize:     5,
			leafCount:   3,
			wantCode:    http.StatusOK,
		},
		{
			description: "valid: one more entry than the configured MaxRange",
			params:      fmt.Sprintf("%d/%d", 0, testMaxRange+1), // query will be pruned
			sthSize:     5,                                       // >= testConfig.MaxRange+1
			leafCount:   testMaxRange,
			wantCode:    http.StatusOK,
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
			stateman.EXPECT().SignedTreeHead().Return(
				types.CosignedTreeHead{SignedTreeHead: types.SignedTreeHead{TreeHead: types.TreeHead{Size: table.sthSize}}})

			node := Primary{
				Config:   testConfig,
				DbClient: client,
				Stateman: stateman,
				MaxRange: testMaxRange,
			}

			// Create HTTP request
			url := types.EndpointGetLeaves.Path("http://example.com")
			req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			node.PublicHTTPMux("").ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
			if w.Code != http.StatusOK {
				return
			}

			list, err := types.LeavesFromASCII(w.Body)
			if err != nil {
				t.Fatalf("must unmarshal leaf list: %v", err)
			}
			if got, want := len(list), table.leafCount; got != want {
				t.Errorf("got %d leaves, but wanted %d in test %q", got, want, table.description)
			}
		}()
	}
}

func mustLeafAscii(t *testing.T, message crypto.Hash, wantSig bool) string {
	t.Helper()

	vk, sk, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("must generate ed25519 keys: %v", err)
	}
	sig, err := types.SignLeafMessage(sk, message[:])
	if err != nil {
		t.Fatalf("must have an ed25519 signature: %v", err)
	}
	if !wantSig {
		sig[0] += 1
	}
	return fmt.Sprintf(
		"%s=%x\n"+"%s=%x\n"+"%s=%x\n",
		"message", message[:],
		"signature", sig,
		"public_key", vk,
	)
}
