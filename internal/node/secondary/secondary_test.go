package secondary

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	mocksClient "sigsum.org/log-go/internal/mocks/client"
	mocksDB "sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

var (
	testConfig = Config{
		LogID:   fmt.Sprintf("%x", crypto.HashBytes([]byte("logid"))),
		Prefix:  "testonly",
		Timeout: 10,
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
		trillianGetTHExp bool
		trillianTHRet    types.TreeHead
		trillianTHErr    error
		// client.GetLeaves()
		primaryGetLeavesRet []types.Leaf
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
			desc:             "no tree head from trillian",
			primaryTHRet:     types.TreeHead{},
			trillianGetTHExp: true,
			trillianTHErr:    fmt.Errorf("mocked error"),
		},
		{
			desc:                "error fetching leaves",
			primaryTHRet:        types.TreeHead{TreeSize: 6},
			trillianGetTHExp:    true,
			trillianTHRet:       types.TreeHead{TreeSize: 5}, // 6-5 => 1 expected GetLeaves
			primaryGetLeavesErr: fmt.Errorf("mocked error"),
		},
		{
			desc:             "error adding leaves",
			primaryTHRet:     types.TreeHead{TreeSize: 6},
			trillianGetTHExp: true,
			trillianTHRet:    types.TreeHead{TreeSize: 5}, // 6-5 => 1 expected GetLeaves
			primaryGetLeavesRet: []types.Leaf{
				types.Leaf{},
			},
			trillianAddLeavesErr: fmt.Errorf("mocked error"),
		},
		{
			desc:             "success",
			primaryTHRet:     types.TreeHead{TreeSize: 10},
			trillianGetTHExp: true,
			trillianTHRet:    types.TreeHead{TreeSize: 5},
			primaryGetLeavesRet: []types.Leaf{
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
			if tbl.trillianGetTHExp {
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
				Config:   testConfig,
				Primary:  primaryClient,
				DbClient: trillianClient,
			}

			node.fetchLeavesFromPrimary(context.Background())

			// NOTE: We are not verifying that
			// AddSequencedLeaves() is being called with
			// the right data.
		}()
	}
}
