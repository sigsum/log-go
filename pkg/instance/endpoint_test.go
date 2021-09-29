package instance

import (
	//"reflect"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"git.sigsum.org/sigsum-log-go/pkg/mocks"
	"git.sigsum.org/sigsum-log-go/pkg/types"
)

var (
	testWitVK  = [types.VerificationKeySize]byte{}
	testConfig = Config{
		LogID:      hex.EncodeToString(types.Hash([]byte("logid"))[:]),
		TreeID:     0,
		Prefix:     "testonly",
		MaxRange:   3,
		Deadline:   10,
		Interval:   10,
		ShardStart: 10,
		ShardEnd:   20,
		Witnesses: map[[types.HashSize]byte][types.VerificationKeySize]byte{
			*types.Hash(testWitVK[:]): testWitVK,
		},
	}
	testSTH = &types.SignedTreeHead{
		TreeHead: types.TreeHead{
			Timestamp: 0,
			TreeSize:  0,
			RootHash:  types.Hash(nil),
		},
		Signature: &[types.SignatureSize]byte{},
	}
	testCTH = &types.CosignedTreeHead{
		SignedTreeHead: *testSTH,
		SigIdent: []*types.SigIdent{
			&types.SigIdent{
				KeyHash:   &[types.HashSize]byte{},
				Signature: &[types.SignatureSize]byte{},
			},
		},
	}
)

func mustHandle(t *testing.T, i Instance, e types.Endpoint) Handler {
	for _, handler := range i.Handlers() {
		if handler.Endpoint == e {
			return handler
		}
	}
	t.Fatalf("must handle endpoint: %v", e)
	return Handler{}
}

func TestAddLeaf(t *testing.T) {
	buf := func(shard uint64, sum, sig, vf string) io.Reader {
		// A valid leaf request that was created manually
		return bytes.NewBufferString(fmt.Sprintf(
			"%s%s%d%s"+"%s%s%s%s"+"%s%s%s%s"+"%s%s%s%s"+"%s%s%s%s",
			types.ShardHint, types.Delim, shard, types.EOL,
			types.Checksum, types.Delim, sum, types.EOL,
			types.Signature, types.Delim, sig, types.EOL,
			types.VerificationKey, types.Delim, vf, types.EOL,
			types.DomainHint, types.Delim, "example.com", types.EOL,
		))
	}
	for _, table := range []struct {
		description string
		ascii       io.Reader // buffer used to populate HTTP request
		expect      bool      // set if a mock answer is expected
		err         error     // error from Trillian client
		wantCode    int       // HTTP status ok
	}{
		// XXX introduce helper so that test params are not hardcoded
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (signature error)",
			ascii: buf(10,
				"0000000000000000000000000000000000000000000000000000000000000000",
				"11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
				"f6eef8e94ddf1396682871257e670a1d9b627cf460daade7c36d218b2866befb",
			),
			wantCode: http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (shard hint is before shard start)",
			ascii: buf(9,
				"0000000000000000000000000000000000000000000000000000000000000000",
				"20876ac8bf2c32d0c7f9b51b57f2de2f454c82c6b189ee30d5275361b657299b3e4e4d677646ec2586927a5a015ad349ae1ca4440e1bf6efbec875144d3a4009",
				"a70f95f1739834190ec9a2a2fcee8ba8e70eddeb825c9856edfb2d8c5dfda595",
			),
			wantCode: http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (shard hint is before shard start)",
			ascii: buf(21,
				"0000000000000000000000000000000000000000000000000000000000000000",
				"79c14f0ad9ab24ab98fe9d5ff59c3b91348789758aa092c6bfab2ac8890b41fb1d44d985e723184f9de42edb82b5ada14f494a96e361914d5366dd92379a1d04",
				"91347ef525e149765225d1341ae2e07ce0f2256a44ae20f04f143f11285c8031",
			),
			wantCode: http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			ascii: buf(10,
				"0000000000000000000000000000000000000000000000000000000000000000",
				"7df253d2578c6c20b90832245ad6f981077454667796b3d507336a89ee878a2eae6b96e6d8de84fe8c1acf4b3aaffd482b657b65d94ed5e6be6320492147f90c",
				"f6eef8e94ddf1396682871257e670a1d9b627cf460daade7c36d218b2866befb",
			),
			expect:   true,
			err:      fmt.Errorf("something went wrong"),
			wantCode: http.StatusInternalServerError,
		},
		{
			description: "valid",
			ascii: buf(10,
				"0000000000000000000000000000000000000000000000000000000000000000",
				"7df253d2578c6c20b90832245ad6f981077454667796b3d507336a89ee878a2eae6b96e6d8de84fe8c1acf4b3aaffd482b657b65d94ed5e6be6320492147f90c",
				"f6eef8e94ddf1396682871257e670a1d9b627cf460daade7c36d218b2866befb",
			),
			expect:   true,
			wantCode: http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocks.NewMockClient(ctrl)
			if table.expect {
				client.EXPECT().AddLeaf(gomock.Any(), gomock.Any()).Return(table.err)
			}
			i := Instance{
				Config: testConfig,
				Client: client,
			}

			// Create HTTP request
			url := types.EndpointAddLeaf.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointAddLeaf).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestAddCosignature(t *testing.T) {
	buf := func() io.Reader {
		return bytes.NewBufferString(fmt.Sprintf(
			"%s%s%x%s"+"%s%s%x%s",
			types.Cosignature, types.Delim, make([]byte, types.SignatureSize), types.EOL,
			types.KeyHash, types.Delim, *types.Hash(testWitVK[:]), types.EOL,
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
			description: "invalid: bad request (unknown witness)",
			ascii: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%x%s"+"%s%s%x%s",
				types.Signature, types.Delim, make([]byte, types.SignatureSize), types.EOL,
				types.KeyHash, types.Delim, *types.Hash(testWitVK[1:]), types.EOL,
			)),
			wantCode: http.StatusBadRequest,
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
			stateman := mocks.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().AddCosignature(gomock.Any(), gomock.Any(), gomock.Any()).Return(table.err)
			}
			i := Instance{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointAddCosignature.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointAddCosignature).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeHeadLatest(t *testing.T) {
	for _, table := range []struct {
		description string
		expect      bool                  // set if a mock answer is expected
		rsp         *types.SignedTreeHead // signed tree head from Trillian client
		err         error                 // error from Trillian client
		wantCode    int                   // HTTP status ok
	}{
		{
			description: "invalid: backend failure",
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
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
			stateman := mocks.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().Latest(gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadLatest.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetTreeHeadLatest).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetTreeToSign(t *testing.T) {
	for _, table := range []struct {
		description string
		expect      bool                  // set if a mock answer is expected
		rsp         *types.SignedTreeHead // signed tree head from Trillian client
		err         error                 // error from Trillian client
		wantCode    int                   // HTTP status ok
	}{
		{
			description: "invalid: backend failure",
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
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
			stateman := mocks.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().ToSign(gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadToSign.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetTreeHeadToSign).ServeHTTP(w, req)
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
			description: "invalid: backend failure",
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
			stateman := mocks.NewMockStateManager(ctrl)
			if table.expect {
				stateman.EXPECT().Cosigned(gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config:   testConfig,
				Stateman: stateman,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadCosigned.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetTreeHeadCosigned).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetConsistencyProof(t *testing.T) {
	buf := func(oldSize, newSize int) io.Reader {
		return bytes.NewBufferString(fmt.Sprintf(
			"%s%s%d%s"+"%s%s%d%s",
			types.OldSize, types.Delim, oldSize, types.EOL,
			types.NewSize, types.Delim, newSize, types.EOL,
		))
	}
	for _, table := range []struct {
		description string
		ascii       io.Reader               // buffer used to populate HTTP request
		expect      bool                    // set if a mock answer is expected
		rsp         *types.ConsistencyProof // consistency proof from Trillian client
		err         error                   // error from Trillian client
		wantCode    int                     // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (OldSize is zero)",
			ascii:       buf(0, 1),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (OldSize > NewSize)",
			ascii:       buf(2, 1),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			ascii:       buf(1, 2),
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			ascii:       buf(1, 2),
			expect:      true,
			rsp: &types.ConsistencyProof{
				OldSize: 1,
				NewSize: 2,
				Path: []*[types.HashSize]byte{
					types.Hash(nil),
				},
			},
			wantCode: http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocks.NewMockClient(ctrl)
			if table.expect {
				client.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config: testConfig,
				Client: client,
			}

			// Create HTTP request
			url := types.EndpointGetConsistencyProof.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetConsistencyProof).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetInclusionProof(t *testing.T) {
	buf := func(hash *[types.HashSize]byte, treeSize int) io.Reader {
		return bytes.NewBufferString(fmt.Sprintf(
			"%s%s%x%s"+"%s%s%d%s",
			types.LeafHash, types.Delim, hash[:], types.EOL,
			types.TreeSize, types.Delim, treeSize, types.EOL,
		))
	}
	for _, table := range []struct {
		description string
		ascii       io.Reader             // buffer used to populate HTTP request
		expect      bool                  // set if a mock answer is expected
		rsp         *types.InclusionProof // inclusion proof from Trillian client
		err         error                 // error from Trillian client
		wantCode    int                   // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (no proof for tree size)",
			ascii:       buf(types.Hash(nil), 1),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			ascii:       buf(types.Hash(nil), 2),
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			ascii:       buf(types.Hash(nil), 2),
			expect:      true,
			rsp: &types.InclusionProof{
				TreeSize:  2,
				LeafIndex: 0,
				Path: []*[types.HashSize]byte{
					types.Hash(nil),
				},
			},
			wantCode: http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocks.NewMockClient(ctrl)
			if table.expect {
				client.EXPECT().GetInclusionProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config: testConfig,
				Client: client,
			}

			// Create HTTP request
			url := types.EndpointGetInclusionProof.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetInclusionProof).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetLeaves(t *testing.T) {
	buf := func(startSize, endSize int64) io.Reader {
		return bytes.NewBufferString(fmt.Sprintf(
			"%s%s%d%s"+"%s%s%d%s",
			types.StartSize, types.Delim, startSize, types.EOL,
			types.EndSize, types.Delim, endSize, types.EOL,
		))
	}
	for _, table := range []struct {
		description string
		ascii       io.Reader       // buffer used to populate HTTP request
		expect      bool            // set if a mock answer is expected
		rsp         *types.LeafList // list of leaves from Trillian client
		err         error           // error from Trillian client
		wantCode    int             // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			ascii:       bytes.NewBufferString("key=value\n"),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (StartSize > EndSize)",
			ascii:       buf(1, 0),
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: backend failure",
			ascii:       buf(0, 0),
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid: one more entry than the configured MaxRange",
			ascii:       buf(0, testConfig.MaxRange), // query will be pruned
			expect:      true,
			rsp: func() *types.LeafList {
				var list types.LeafList
				for i := int64(0); i < testConfig.MaxRange; i++ {
					list = append(list[:], &types.Leaf{
						Message: types.Message{
							ShardHint: 0,
							Checksum:  types.Hash(nil),
						},
						SigIdent: types.SigIdent{
							Signature: &[types.SignatureSize]byte{},
							KeyHash:   types.Hash(nil),
						},
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
			client := mocks.NewMockClient(ctrl)
			if table.expect {
				client.EXPECT().GetLeaves(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			}
			i := Instance{
				Config: testConfig,
				Client: client,
			}

			// Create HTTP request
			url := types.EndpointGetLeaves.Path("http://example.com", i.Prefix)
			req, err := http.NewRequest("POST", url, table.ascii)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandle(t, i, types.EndpointGetLeaves).ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
			if w.Code != http.StatusOK {
				return
			}

			// TODO: check that we got the right leaves back.  It is especially
			// important that we check that we got the right number of leaves.
			//
			// Pseuducode for when we have types.LeafList.UnmarshalASCII()
			//
			//list := &types.LeafList{}
			//if err := list.UnmarshalASCII(w.Body); err != nil {
			//	t.Fatalf("must unmarshal leaf list: %v", err)
			//}
			//if got, want := list, table.rsp; !reflect.DeepEqual(got, want) {
			//	t.Errorf("got leaf list\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			//}
		}()
	}
}
