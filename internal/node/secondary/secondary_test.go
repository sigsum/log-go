package secondary

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	mocksDB "sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/sigsum-go/pkg/mocks"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestFetchLeavesFromPrimary(t *testing.T) {
	for _, tbl := range []struct {
		desc string
		// db.GetTreeHead()
		trillianTHRet types.TreeHead
		trillianTHErr error
		// client.GetLeaves()
		primaryGetLeavesRet []types.Leaf
		primaryGetLeavesErr error
		// db.AddSequencedLeaves()
		trillianAddLeavesExp bool
		trillianAddLeavesErr error
	}{
		{
			desc:          "no tree head from trillian",
			trillianTHErr: fmt.Errorf("mocked error"),
		},
		{
			desc:                "error fetching leaves",
			trillianTHRet:       types.TreeHead{Size: 5}, // 6-5 => 1 expected GetLeaves
			primaryGetLeavesErr: fmt.Errorf("mocked error"),
		},
		{
			desc:          "error adding leaves",
			trillianTHRet: types.TreeHead{Size: 5}, // 6-5 => 1 expected GetLeaves
			primaryGetLeavesRet: []types.Leaf{
				types.Leaf{},
			},
			trillianAddLeavesErr: fmt.Errorf("mocked error"),
		},
		{
			desc:          "success",
			trillianTHRet: types.TreeHead{Size: 5},
			primaryGetLeavesRet: []types.Leaf{
				types.Leaf{},
			},
			trillianAddLeavesExp: true,
		},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			fmt.Printf("desc: %s\n", tbl.desc)
			primaryClient := mocks.NewMockLog(ctrl)

			trillianClient := mocksDB.NewMockClient(ctrl)
			trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(tbl.trillianTHRet, tbl.trillianTHErr)
			if tbl.trillianTHErr == nil && tbl.primaryGetLeavesErr == nil && tbl.trillianAddLeavesErr == nil {
				updatedSize := tbl.trillianTHRet.Size + uint64(len(tbl.primaryGetLeavesRet))
				trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(
					types.TreeHead{Size: updatedSize}, tbl.trillianTHErr)
			}

			if tbl.primaryGetLeavesErr != nil || tbl.primaryGetLeavesRet != nil {
				primaryClient.EXPECT().GetLeaves(gomock.Any(), gomock.Any()).Return(tbl.primaryGetLeavesRet, tbl.primaryGetLeavesErr)
				if tbl.trillianAddLeavesExp {
					// XXX End-of-data condition
					primaryClient.EXPECT().GetLeaves(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("mocked error"))
				}
			}

			if tbl.trillianAddLeavesErr != nil || tbl.trillianAddLeavesExp {
				trillianClient.EXPECT().AddSequencedLeaves(gomock.Any(), gomock.Any(), gomock.Any()).Return(tbl.trillianAddLeavesErr)
			}

			node := Secondary{
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
