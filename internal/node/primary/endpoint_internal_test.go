package primary

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestInternalGetLeaves(t *testing.T) {
	const testMaxRange = 3

	for _, table := range []struct {
		description string
		req         requests.Leaves
		th          types.TreeHead
		leafCount   int   // expected number of leaves
		err         error // error from Trillian client
		wantCode    int   // HTTP status ok
	}{
		{
			description: "invalid: bad request (StartIndex >= EndIndex)",
			req:         requests.Leaves{StartIndex: 1, EndIndex: 1},
			th:          types.TreeHead{Size: 2},
			wantCode:    http.StatusBadRequest,
		},
		{
			description: "valid: (EndIndex > current tree size)",
			req:         requests.Leaves{StartIndex: 0, EndIndex: 3},
			th:          types.TreeHead{Size: 2},
			leafCount:   2,
		},
		{
			description: "valid: StartIndex == current tree size",
			req:         requests.Leaves{StartIndex: 2, EndIndex: 3},
			th:          types.TreeHead{Size: 2},
			wantCode:    http.StatusNotFound,
		},
		{
			description: "invalid: backend failure",
			req:         requests.Leaves{StartIndex: 0, EndIndex: 1},
			th:          types.TreeHead{Size: 2},
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid: empty tree",
			req:         requests.Leaves{StartIndex: 0, EndIndex: 1},
			th:          types.TreeHead{Size: 0},
			wantCode:    http.StatusNotFound,
		},
		{
			description: "valid: three middle elements",
			req:         requests.Leaves{StartIndex: 1, EndIndex: 4},
			th:          types.TreeHead{Size: 5},
			leafCount:   3,
		},
		{
			description: "valid: one more entry than the configured MaxRange",
			req:         requests.Leaves{StartIndex: 0, EndIndex: 4},
			th:          types.TreeHead{Size: 5},
			leafCount:   testMaxRange,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := db.NewMockClient(ctrl)
			client.EXPECT().GetTreeHead(gomock.Any()).Return(table.th, nil).AnyTimes()
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
			node := Primary{
				DbClient: client,
				MaxRange: testMaxRange,
			}

			leaves, err := node.GetLeavesInternal(context.Background(), table.req)
			if err := checkError(err, table.wantCode); err != nil {
				t.Errorf("in test %q: %v", table.description, err)
			} else if got, want := len(leaves), table.leafCount; got != want {
				t.Errorf("got %d leaves, but wanted %d in test %q", got, want, table.description)
			}
		}()
	}
}
