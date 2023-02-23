package state

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"sigsum.org/log-go/internal/mocks/client"
	"sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestGetPrimaryTreeHead(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	th := types.TreeHead{Size: 5}

	primary := db.NewMockClient(ctrl)
	primary.EXPECT().GetTreeHead(gomock.Any()).MinTimes(1).Return(
		types.TreeHead{Size: 5}, nil)

	state := ReplicationState{primary: primary}
	ctx := context.Background()

	for minSize := uint64(0); minSize < 7; minSize++ {
		got, err := state.getPrimaryTreeHead(ctx, minSize)
		if minSize <= 5 {
			if err != nil {
				t.Errorf("getPrimaryTreeHead size %d failed: %v",
					minSize, err)
			} else if got != th {
				t.Errorf("unexpected tree head %v, expected %v",
					got, th)
			}
		} else {
			if err == nil {
				t.Errorf("getPrimaryTreeHead size %d returned unexpected tree head %v",
					minSize, got)
			}
		}
	}
}

func TestGetSecondaryTreeHead(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pub, signer, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	th := types.TreeHead{Size: 5}
	sth, err := th.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}

	secondary := client.NewMockClient(ctrl)
	secondary.EXPECT().GetNextTreeHead(gomock.Any()).MinTimes(1).Return(sth, nil)

	state := ReplicationState{secondary: secondary, secondaryPub: pub}
	ctx := context.Background()

	for minSize := uint64(3); minSize < 7; minSize++ {
		for maxSize := uint64(4); maxSize < 8; maxSize++ {
			got, err := state.getSecondaryTreeHead(ctx, minSize, maxSize)
			if minSize <= 5 && 5 <= maxSize {
				if err != nil {
					t.Errorf("getSecondaryTreeHead size %d..%d failed: %v",
						minSize, maxSize, err)
				} else if got != th {
					t.Errorf("unexpected tree head %v, expected %v",
						got, th)
				}
			} else {
				if err == nil {
					t.Errorf("getSecondaryTreeHead size %d..%d returned unexpected tree head %v",
						minSize, maxSize, got)
				}
			}
		}
	}
}

func TestCheckConsistency(t *testing.T) {
	withConsistencyProof := func(old types.TreeHead, new types.TreeHead, consistencyProof []crypto.Hash) error {
		t.Helper()

		state := ReplicationState{}
		if consistencyProof != nil {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			primary := db.NewMockClient(ctrl)
			primary.EXPECT().GetConsistencyProof(gomock.Any(),
				&requests.ConsistencyProof{
					OldSize: old.Size,
					NewSize: new.Size,
				}).Return(
				types.ConsistencyProof{
					OldSize: old.Size,
					NewSize: new.Size,
					Path:    consistencyProof,
				}, nil)
			state.primary = primary
		}
		return state.checkConsistency(context.Background(), old, new)
	}

	// Build a tree, record tree heads as we go.
	tree := merkle.NewTree()
	// Tree heads indexed by tree size.
	treeHeads := []types.TreeHead{types.TreeHead{RootHash: tree.GetRootHash()}}
	for i := uint64(1); i < 10; i++ {
		leafHash := crypto.Hash{uint8(i)}
		tree.AddLeafHash(&leafHash)
		treeHeads = append(treeHeads, types.TreeHead{
			Size:     i,
			RootHash: tree.GetRootHash(),
		})
	}
	for oldSize := uint64(0); oldSize < 10; oldSize++ {
		for newSize := oldSize; newSize < 10; newSize++ {
			var consistencyProof []crypto.Hash
			if oldSize > 0 && newSize > oldSize {
				var err error
				consistencyProof, err = tree.ProveConsistency(oldSize, newSize)
				if err != nil {
					t.Fatalf("no consistency %d %d: %v", oldSize, newSize, err)
				}
			}
			if err := withConsistencyProof(
				treeHeads[oldSize], treeHeads[newSize], consistencyProof); err != nil {
				t.Errorf("consistency check %d..%d failed: %v", oldSize, newSize, err)
			}

			// Invalidate consistency proof.
			if consistencyProof != nil {
				consistencyProof[0][0] ^= 1

				if withConsistencyProof(
					treeHeads[oldSize], treeHeads[newSize], consistencyProof) == nil {
					t.Errorf("consistency check %d..%d succeeded, with bad proof: ", oldSize, newSize)
				}
			}

		}
	}
}
