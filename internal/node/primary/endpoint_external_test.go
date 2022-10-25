package primary

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"sigsum.org/log-go/internal/db"
	mocksDB "sigsum.org/log-go/internal/mocks/db"
	mocksState "sigsum.org/log-go/internal/mocks/state"
	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/sigsum-go/pkg/types"
)

var (
	testSTH = &types.SignedTreeHead{
		TreeHead:  *testTH,
		Signature: crypto.Signature{},
	}
	testCTH = &types.CosignedTreeHead{
		SignedTreeHead: *testSTH,
		Cosignatures:   make([]types.Cosignature, 1),
	}
	sth0 = types.SignedTreeHead{TreeHead: types.TreeHead{TreeSize: 0}}
	sth1 = types.SignedTreeHead{TreeHead: types.TreeHead{TreeSize: 1}}
	sth2 = types.SignedTreeHead{TreeHead: types.TreeHead{TreeSize: 2}} // 2 < testConfig.MaxRange
	sth5 = types.SignedTreeHead{TreeHead: types.TreeHead{TreeSize: 5}} // 5 >= testConfig.MaxRange+1
)

// TODO: remove tests that are now located in internal/requests instead

func TestAddLeaf(t *testing.T) {
	// TODO: Set up a mock rate limiter.
	for _, table := range []struct {
		description    string
		ascii          io.Reader // buffer used to populate HTTP request
		expectTrillian bool      // expect Trillian client code path
		errTrillian    error     // error from Trillian client
		expectToken    bool      // expect token verifier code path
		errToken       error     // error from token verifier
		wantCode       int       // HTTP status ok
		expectStateman bool
		leafStatus     db.AddLeafStatus // return value from db.AddLeaf()
		sthStateman    *types.SignedTreeHead
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (signature error)",
			ascii:       mustLeafBuffer(t, crypto.Hash{}, false),
			wantCode:    http.StatusBadRequest,
		},
		{
			description:    "invalid: backend failure",
			ascii:          mustLeafBuffer(t, crypto.Hash{}, true),
			expectStateman: true,
			sthStateman:    testSTH,
			expectTrillian: true,
			errTrillian:    fmt.Errorf("something went wrong"),
			wantCode:       http.StatusInternalServerError,
		},
		{
			description:    "valid: 202",
			ascii:          mustLeafBuffer(t, crypto.Hash{}, true),
			expectStateman: true,
			sthStateman:    testSTH,
			expectTrillian: true,
			wantCode:       http.StatusAccepted,
		},
		{
			description:    "valid: 200",
			ascii:          mustLeafBuffer(t, crypto.Hash{}, true),
			expectStateman: true,
			sthStateman:    testSTH,
			expectTrillian: true,
			leafStatus:     db.AddLeafStatus{IsSequenced: true},
			wantCode:       http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksDB.NewMockClient(ctrl)
			if table.expectTrillian {
				client.EXPECT().AddLeaf(gomock.Any(), gomock.Any(), gomock.Any()).Return(table.leafStatus, table.errTrillian)
			}
			stateman := mocksState.NewMockStateManager(ctrl)
			if table.expectStateman {
				stateman.EXPECT().ToCosignTreeHead().Return(table.sthStateman)
			}
			node := Primary{
				Config:         testConfig,
				TrillianClient: client,
				Stateman:       stateman,
				RateLimiter:    rateLimit.NoLimit{},
			}

			// Create HTTP request
			url := types.EndpointAddLeaf.Path("http://example.com", node.Prefix())
			req, err := http.NewRequest("POST", url, table.ascii)
			fmt.Printf("ascii: %q\n", table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandlePublic(t, node, types.EndpointAddLeaf).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestAddCosignature(t *testing.T) {
	buf := func() io.Reader {
		return bytes.NewBufferString(fmt.Sprintf("%s=%x %x\n",
			"cosignature",
			crypto.HashBytes(testWitVK[:]),
			crypto.Signature{},
		))
	}
	for _, table := range []struct {
		description string
		ascii       io.Reader // buffer used to populate HTTP request
		expect      bool      // set if a mock answer is expected
		err         error     // error from Trillian client
		wantCode    int       // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			ascii:       buf(),
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid",
			ascii:       buf(),
			expect:      true,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			stateman := mocksState.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().AddCosignature(gomock.Any(), gomock.Any()).Return(table.err)
			}
			node := Primary{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointAddCosignature.Path("http://example.com", node.Prefix())
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandlePublic(t, node, types.EndpointAddCosignature).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeToCosign(t *testing.T) {
	for _, table := range []struct {
		description string
		expect      bool                  // set if a mock answer is expected
		rsp         *types.SignedTreeHead // signed tree head from Trillian client
		err         error                 // error from Trillian client
		wantCode    int                   // HTTP status ok
	}{
		{
			description: "valid",
			expect:      true,
			rsp:         testSTH,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			stateman := mocksState.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().ToCosignTreeHead().Return(table.rsp)
			}
			node := Primary{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadToCosign.Path("http://example.com", node.Prefix())
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandlePublic(t, node, types.EndpointGetTreeHeadToCosign).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeCosigned(t *testing.T) {
	for _, table := range []struct {
		description string
		expect      bool                    // set if a mock answer is expected
		rsp         *types.CosignedTreeHead // cosigned tree head from Trillian client
		err         error                   // error from Trillian client
		wantCode    int                     // HTTP status ok
	}{
		{
			description: "invalid: no cosigned STH",
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			expect:      true,
			rsp:         testCTH,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			stateman := mocksState.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().CosignedTreeHead().Return(table.rsp, table.err)
			}
			node := Primary{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadCosigned.Path("http://example.com", node.Prefix())
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandlePublic(t, node, types.EndpointGetTreeHeadCosigned).ServeHTTP(w, req)
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
		sth         *types.SignedTreeHead
		expect      bool                    // set if a mock answer is expected
		rsp         *types.ConsistencyProof // consistency proof from Trillian client
		err         error                   // error from Trillian client
		wantCode    int                     // HTTP status ok
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
			sth:         &sth1,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			params:      "1/2",
			sth:         &sth2,
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			params:      "1/2",
			sth:         &sth2,
			expect:      true,
			rsp: &types.ConsistencyProof{
				OldSize: 1,
				NewSize: 2,
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
			if table.expect {
				client.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			stateman := mocksState.NewMockStateManager(ctrl)
			if table.sth != nil {
				stateman.EXPECT().ToCosignTreeHead().Return(table.sth)
			}
			node := Primary{
				Config:         testConfig,
				TrillianClient: client,
				Stateman:       stateman,
			}

			// Create HTTP request
			url := types.EndpointGetConsistencyProof.Path("http://example.com", node.Prefix())
			req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandlePublic(t, node, types.EndpointGetConsistencyProof).ServeHTTP(w, req)
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
		sth         *types.SignedTreeHead
		expect      bool                  // set if a mock answer is expected
		rsp         *types.InclusionProof // inclusion proof from Trillian client
		err         error                 // error from Trillian client
		wantCode    int                   // HTTP status ok
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
			sth:         &sth1,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			params:      "2/0000000000000000000000000000000000000000000000000000000000000000",
			sth:         &sth2,
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			params:      "2/0000000000000000000000000000000000000000000000000000000000000000",
			sth:         &sth2,
			expect:      true,
			rsp: &types.InclusionProof{
				TreeSize:  2,
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
			if table.expect {
				client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			stateman := mocksState.NewMockStateManager(ctrl)
			if table.sth != nil {
				stateman.EXPECT().ToCosignTreeHead().Return(table.sth)
			}
			node := Primary{
				Config:         testConfig,
				TrillianClient: client,
				Stateman:       stateman,
			}

			// Create HTTP request
			url := types.EndpointGetInclusionProof.Path("http://example.com", node.Prefix())
			req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandlePublic(t, node, types.EndpointGetInclusionProof).ServeHTTP(w, req)
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
		sth         *types.SignedTreeHead
		expect      bool          // set if a mock answer is expected
		rsp         *[]types.Leaf // list of leaves from Trillian client
		err         error         // error from Trillian client
		wantCode    int           // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			params:      "a/1",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (StartSize > EndSize)",
			params:      "1/0",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (EndSize >= current tree size)",
			params:      "0/2",
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			params:      "0/0",
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "invalid: empty tree",
			params:      "0/0",
			sth:         &sth0,
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid: three middle elements",
			params:      "1/3",
			sth:         &sth5,
			expect:      true,
			rsp: func() *[]types.Leaf {
				var list []types.Leaf
				for i := int64(0); i < testConfig.MaxRange; i++ {
					list = append(list[:], types.Leaf{
						Checksum:  crypto.Hash{},
						Signature: crypto.Signature{},
						KeyHash:   crypto.Hash{},
					})
				}
				return &list
			}(),
			wantCode: http.StatusOK,
		},
		{
			description: "valid: one more entry than the configured MaxRange",
			params:      fmt.Sprintf("%d/%d", 0, testConfig.MaxRange), // query will be pruned
			sth:         &sth5,
			expect:      true,
			rsp: func() *[]types.Leaf {
				var list []types.Leaf
				for i := int64(0); i < testConfig.MaxRange; i++ {
					list = append(list[:], types.Leaf{
						Checksum:  crypto.Hash{},
						Signature: crypto.Signature{},
						KeyHash:   crypto.Hash{},
					})
				}
				return &list
			}(),
			wantCode: http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksDB.NewMockClient(ctrl)
			if table.expect {
				client.EXPECT().GetLeaves(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			stateman := mocksState.NewMockStateManager(ctrl)
			if table.sth != nil {
				stateman.EXPECT().ToCosignTreeHead().Return(table.sth)
			} else {
				stateman.EXPECT().ToCosignTreeHead().Return(&sth2)
			}
			node := Primary{
				Config:         testConfig,
				TrillianClient: client,
				Stateman:       stateman,
			}

			// Create HTTP request
			url := types.EndpointGetLeaves.Path("http://example.com", node.Prefix())
			req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandlePublic(t, node, types.EndpointGetLeaves).ServeHTTP(w, req)
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
			if got, want := &list, table.rsp; !reflect.DeepEqual(got, want) {
				t.Errorf("got leaf list\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
		}()
	}
}

func mustHandlePublic(t *testing.T, p Primary, e types.Endpoint) handler.Handler {
	for _, handler := range p.PublicHTTPHandlers() {
		if handler.Endpoint == e {
			return handler
		}
	}
	t.Fatalf("must handle endpoint: %v", e)
	return handler.Handler{}
}

func mustLeafBuffer(t *testing.T, message crypto.Hash, wantSig bool) io.Reader {
	t.Helper()

	vk, sk, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("must generate ed25519 keys: %v", err)
	}
	sig, err := types.SignLeafMessage(sk, message[:])
	if err != nil {
		t.Fatalf("must have an ed25519 signature: %v", err)
	}
	fmt.Printf("sig: %x\n", sig)
	if !wantSig {
		sig[0] += 1
	}
	return bytes.NewBufferString(fmt.Sprintf(
		"%s=%x\n"+"%s=%x\n"+"%s=%x\n",
		"message", message[:],
		"signature", sig,
		"public_key", vk,
	))
}
