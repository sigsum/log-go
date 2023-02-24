package db

import (
	"encoding/binary"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestMemoryAddLeaf(t *testing.T) {
	leaves := newLeaves(2)
	db := NewMemoryDb()

	for _, table := range []struct {
		desc string
		leaf *types.Leaf
		size uint64
		want AddLeafStatus
	}{
		{"new leaf", &leaves[0], 0, AddLeafStatus{}},
		{"existing leaf", &leaves[0], 0, AddLeafStatus{AlreadyExists: true}},
		{"sequenced leaf", &leaves[0], 1, AddLeafStatus{AlreadyExists: true, IsSequenced: true}},
		// Corner case; this backend sequences leaves immediately.
		{"second leaf", &leaves[1], 1, AddLeafStatus{}},
	} {
		status, err := db.AddLeaf(nil, table.leaf, table.size)
		if err != nil {
			t.Fatalf("AddLeaf failed in test: %q: %v", table.desc, err)
		}
		if status != table.want {
			t.Errorf("got status %#v, wanted %#v in test: %q", status, table.want, table.desc)
		}
	}
}

func TestMemoryAddSequencedLeaves(t *testing.T) {
	leaves := newLeaves(5)
	db := NewMemoryDb()
	if _, err := db.AddLeaf(nil, &leaves[0], 0); err != nil {
		t.Fatalf("AddLeaf of initial leaf failed: %v", err)
	}
	if err := db.AddSequencedLeaves(nil, leaves[1:], 0); err == nil {
		t.Fatalf("AddSequencedLeaves with bad index unexpectedly succeeded")
	}
	if err := db.AddSequencedLeaves(nil, leaves[1:], 1); err != nil {
		t.Fatalf("AddSequencedLeaves (1:5) failed: %v", err)
	}
}

func TestMemoryGetLeaves(t *testing.T) {
	leaves := newLeaves(5)
	db := NewMemoryDb()
	if err := db.AddSequencedLeaves(nil, leaves[:], 0); err != nil {
		t.Fatalf("AddSequencedLeaves failed: %v", err)
	}
	for start := 0; start <= 5; start++ {
		for end := 0; start <= 5; start++ {
			res, err := db.GetLeaves(nil, &requests.Leaves{uint64(start), uint64(end)})
			if start >= end {
				if err == nil {
					t.Errorf("no error for invalid range start %d, end %d", start, end)
				}
			} else if err != nil {
				t.Errorf("GetLeaves failed for range start %d, end %d: %v", start, end, err)
			} else if len(res) != end-start+1 {
				t.Errorf("unexpected result len %d for range start %d, end %d", len(res), start, end)
			} else {
				for i := start; i <= end; i++ {
					if res[i] != leaves[start+i] {
						t.Errorf("wrong leaf data for leaf %d (start %d): got %#v, wanted: %#v",
							start+i, start, res[i], leaves[start+i])
					}
				}
			}
		}
	}
}

func TestMemoryInclusionProof(t *testing.T) {
	leaves := newLeaves(5)
	db := NewMemoryDb()
	for i, leaf := range leaves {
		if _, err := db.AddLeaf(nil, &leaf, 0); err != nil {
			t.Fatalf("AddLeaf failed of leaf %d failed: %v", i, err)
		}
	}
	th, err := db.GetTreeHead(nil)
	if err != nil {
		t.Fatalf("GetTreeHead failed: %v", err)
	}
	if th.Size != 5 {
		t.Fatalf("unexpected tree size, got %d, expected 5", th.Size)
	}
	for i, leaf := range leaves {
		leafHash := merkle.HashLeafNode(leaf.ToBinary())
		proof, err := db.GetInclusionProof(nil, &requests.InclusionProof{
			LeafHash: leafHash,
			Size:     5,
		})
		if err != nil {
			t.Errorf("GetInclusionProof for leaf %d failed: %v", i, err)
		} else if proof.Size != 5 {
			t.Errorf("GetInclusionProof size: got %d, wanted 5", proof.Size)
		} else if proof.LeafIndex != uint64(i) {
			t.Errorf("GetInclusionProof index: got %d, wanted %d", proof.LeafIndex, i)
		} else if err := merkle.VerifyInclusion(&leafHash, uint64(i), 5, &th.RootHash, proof.Path); err != nil {
			t.Errorf("inclusion path for leaf %d is invalid: %v", i, err)
		}
	}
}

func TestMemoryconsistencyProof(t *testing.T) {
	leaves := newLeaves(5)
	rootHashes := []crypto.Hash{}

	db := NewMemoryDb()
	for i, leaf := range leaves {
		if _, err := db.AddLeaf(nil, &leaf, 0); err != nil {
			t.Fatalf("AddLeaf failed of leaf %d failed: %v", i, err)
		}
		th, err := db.GetTreeHead(nil)
		if err != nil {
			t.Fatalf("GetTreeHead failed after leaf %d: %v", i, err)
		}
		if th.Size != uint64(i)+1 {
			t.Fatalf("GetTreeHead return unexpected tree size %d after leaf %d", th.Size, i)
		}
		rootHashes = append(rootHashes, th.RootHash)
	}
	for oldSize := 1; oldSize <= 5; oldSize++ {
		for newSize := oldSize; newSize <= 5; newSize++ {
			proof, err := db.GetConsistencyProof(nil, &requests.ConsistencyProof{
				OldSize: uint64(oldSize),
				NewSize: uint64(newSize),
			})
			if err != nil {
				t.Errorf("GetConsistencyProof failed for oldSize %d, newSize %d: %v", oldSize, newSize, err)
			} else if err := merkle.VerifyConsistency(uint64(oldSize), uint64(newSize), &rootHashes[oldSize-1], &rootHashes[newSize-1],
				proof.Path); err != nil {
				t.Errorf("consistent path for oldSize %d, newSize %d is invalid: %v", oldSize, newSize, err)
			}
		}
	}
}

func newLeaves(n int) []types.Leaf {
	leaves := make([]types.Leaf, n)
	for i := 0; i < n; i++ {
		var blob [8]byte
		binary.BigEndian.PutUint64(blob[:], uint64(i))
		leaves[i].Checksum = crypto.HashBytes(blob[:])
	}
	return leaves
}
