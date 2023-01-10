package secondary

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	mocksClient "sigsum.org/log-go/internal/mocks/client"
	mocksDB "sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

var (
	testConfig = handler.Config{
		LogID:   fmt.Sprintf("%x", crypto.HashBytes([]byte("logid"))),
		Timeout: 10,
	}
)

// TestHandlers checks that the expected internal handlers are configured
func TestIntHandlers(t *testing.T) {
	node := Secondary{
		Config: testConfig,
	}
	mux := node.InternalHTTPMux("")
	for _, endpoint := range []types.Endpoint{
		types.EndpointGetNextTreeHead,
	} {
		req, err := http.NewRequest(http.MethodGet, endpoint.Path(""), nil)
		if err != nil {
			t.Fatalf("create http request failed: %v", err)
		}
		if _, pattern := mux.Handler(req); pattern == "" {
			t.Errorf("endpoint %s not registered", endpoint)
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
			primaryTHRet:        types.TreeHead{Size: 6},
			trillianGetTHExp:    true,
			trillianTHRet:       types.TreeHead{Size: 5}, // 6-5 => 1 expected GetLeaves
			primaryGetLeavesErr: fmt.Errorf("mocked error"),
		},
		{
			desc:             "error adding leaves",
			primaryTHRet:     types.TreeHead{Size: 6},
			trillianGetTHExp: true,
			trillianTHRet:    types.TreeHead{Size: 5}, // 6-5 => 1 expected GetLeaves
			primaryGetLeavesRet: []types.Leaf{
				types.Leaf{},
			},
			trillianAddLeavesErr: fmt.Errorf("mocked error"),
		},
		{
			desc:             "success",
			primaryTHRet:     types.TreeHead{Size: 10},
			trillianGetTHExp: true,
			trillianTHRet:    types.TreeHead{Size: 5},
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
					for i := tbl.trillianTHRet.Size; i < tbl.primaryTHRet.Size-1; i++ {
						primaryClient.EXPECT().GetLeaves(gomock.Any(), gomock.Any()).Return(tbl.primaryGetLeavesRet, tbl.primaryGetLeavesErr)
					}
				}
			}

			if tbl.trillianAddLeavesErr != nil || tbl.trillianAddLeavesExp {
				trillianClient.EXPECT().AddSequencedLeaves(gomock.Any(), gomock.Any(), gomock.Any()).Return(tbl.trillianAddLeavesErr)
				if tbl.trillianAddLeavesExp {
					for i := tbl.trillianTHRet.Size; i < tbl.primaryTHRet.Size-1; i++ {
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
