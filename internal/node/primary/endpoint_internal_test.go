package primary

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

var (
	testTH = types.TreeHead{
		Size:     0,
		RootHash: crypto.HashBytes([]byte("root hash")),
	}
)

func TestInternalGetLeaves(t *testing.T) {
	for _, table := range []struct {
		description string
		params      string // params is the query's url params
		th          types.TreeHead
		expect      bool  // set if a mock answer is expected
		leafCount   int   // expected number of leaves
		err         error // error from Trillian client
		wantCode    int   // HTTP status ok
	}{
		{
			description: "invalid: bad request (parser error)",
			params:      "a/1",
			th:          types.TreeHead{Size: 2},
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "invalid: bad request (StartIndex >= EndIndex)",
			params:      "1/1",
			th:          types.TreeHead{Size: 2},
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid: (EndIndex > current tree size)",
			params:      "0/3",
			th:          types.TreeHead{Size: 2},
			expect:      true,
			leafCount:   2,
			wantCode:    http.StatusOK,
		},
		{
			description: "valid: StartIndex == current tree size",
			params:      "2/3",
			th:          types.TreeHead{Size: 2},
			wantCode:    http.StatusNotFound,
		},
		{
			description: "invalid: backend failure",
			params:      "0/1",
			th:          types.TreeHead{Size: 2},
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid: empty tree",
			params:      "0/1",
			th:          types.TreeHead{Size: 0},
			wantCode:    http.StatusNotFound,
		},
		{
			description: "valid: three middle elements",
			params:      "1/4",
			th:          types.TreeHead{Size: 5},
			expect:      true,
			leafCount:   3,
			wantCode:    http.StatusOK,
		},
		{
			description: "valid: one more entry than the configured MaxRange",
			params:      fmt.Sprintf("%d/%d", 0, testMaxRange+1), // query will be pruned
			th:          types.TreeHead{Size: 5},
			expect:      true,
			leafCount:   testMaxRange,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := db.NewMockClient(ctrl)
			client.EXPECT().GetTreeHead(gomock.Any()).Return(table.th, nil)
			if table.expect {
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
			node := Primary{
				Config:   testConfig,
				DbClient: client,
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
			node.InternalHTTPMux("").ServeHTTP(w, req)
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
