package secondary

import (
	"context"
	"fmt"
	"testing"

	mocksClient "git.sigsum.org/log-go/internal/mocks/client"
	mocksDB "git.sigsum.org/log-go/internal/mocks/db"
	"git.sigsum.org/sigsum-go/pkg/merkle"
	"git.sigsum.org/sigsum-go/pkg/types"
	"github.com/golang/mock/gomock"
)

var (
	testConfig = Config{
		LogID:    fmt.Sprintf("%x", merkle.HashFn([]byte("logid"))[:]),
		TreeID:   0,
		Prefix:   "testonly",
		Deadline: 10,
	}
)

// TestHandlers checks that the expected internal handlers are configured
func TestIntHandlers(t *testing.T) {
	endpoints := map[types.Endpoint]bool{
		types.EndpointGetTreeHeadToCosign: false,
	}
	node := Secondary{
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

func TestFetchLeavesFromPrimary(t *testing.T) {
	for _, tbl := range []struct {
		desc string
		// client.GetUnsignedTreeHead()
		primaryTHRet types.TreeHead
		primaryTHErr error
		// db.GetTreeHead()
		trillianTHRet *types.TreeHead
		trillianTHErr error
		// client.GetLeaves()
		primaryGetLeavesRet types.Leaves
		primaryGetLeavesErr error
		// db.AddSequencedLeaves()
		trillianAddLeavesExp bool
		trillianAddLeavesErr error
	}{
		{
			desc:         "no tree head from primary",
			primaryTHErr: fmt.Errorf("mocked error"),
		},
		{
			desc:          "no tree head from trillian",
			primaryTHRet:  types.TreeHead{},
			trillianTHErr: fmt.Errorf("mocked error"),
		},
		{
			desc:                "error fetching leaves",
			primaryTHRet:        types.TreeHead{TreeSize: 6},
			trillianTHRet:       &types.TreeHead{TreeSize: 5}, // 6-5 => 1 expected GetLeaves
			primaryGetLeavesErr: fmt.Errorf("mocked error"),
		},
		{
			desc:          "error adding leaves",
			primaryTHRet:  types.TreeHead{TreeSize: 6},
			trillianTHRet: &types.TreeHead{TreeSize: 5}, // 6-5 => 1 expected GetLeaves
			primaryGetLeavesRet: types.Leaves{
				types.Leaf{},
			},
			trillianAddLeavesErr: fmt.Errorf("mocked error"),
		},
		{
			desc:          "success",
			primaryTHRet:  types.TreeHead{TreeSize: 10},
			trillianTHRet: &types.TreeHead{TreeSize: 5},
			primaryGetLeavesRet: types.Leaves{
				types.Leaf{},
			},
			trillianAddLeavesExp: true,
		},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			primaryClient := mocksClient.NewMockClient(ctrl)
			primaryClient.EXPECT().GetUnsignedTreeHead(gomock.Any()).Return(tbl.primaryTHRet, tbl.primaryTHErr)

			trillianClient := mocksDB.NewMockClient(ctrl)
			if tbl.trillianTHErr != nil || tbl.trillianTHRet != nil {
				trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(tbl.trillianTHRet, tbl.trillianTHErr)
			}

			if tbl.primaryGetLeavesErr != nil || tbl.primaryGetLeavesRet != nil {
				primaryClient.EXPECT().GetLeaves(gomock.Any(), gomock.Any()).Return(tbl.primaryGetLeavesRet, tbl.primaryGetLeavesErr)
				if tbl.trillianAddLeavesExp {
					for i := tbl.trillianTHRet.TreeSize; i < tbl.primaryTHRet.TreeSize-1; i++ {
						primaryClient.EXPECT().GetLeaves(gomock.Any(), gomock.Any()).Return(tbl.primaryGetLeavesRet, tbl.primaryGetLeavesErr)
					}
				}
			}

			if tbl.trillianAddLeavesErr != nil || tbl.trillianAddLeavesExp {
				trillianClient.EXPECT().AddSequencedLeaves(gomock.Any(), gomock.Any(), gomock.Any()).Return(tbl.trillianAddLeavesErr)
				if tbl.trillianAddLeavesExp {
					for i := tbl.trillianTHRet.TreeSize; i < tbl.primaryTHRet.TreeSize-1; i++ {
						trillianClient.EXPECT().AddSequencedLeaves(gomock.Any(), gomock.Any(), gomock.Any()).Return(tbl.trillianAddLeavesErr)
					}
				}
			}

			node := Secondary{
				Config:         testConfig,
				Primary:        primaryClient,
				TrillianClient: trillianClient,
			}

			node.fetchLeavesFromPrimary(context.Background())

			// NOTE: We are not verifying that
			// AddSequencedLeaves() is being called with
			// the right data.
		}()
	}
}
