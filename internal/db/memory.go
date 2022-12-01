package db

import (
	"context"
	"fmt"
	"sync"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type leafBlob [2*crypto.HashSize + crypto.SignatureSize]byte

type MemoryDb struct {
	mu    sync.RWMutex
	leafs []leafBlob
	tree  merkle.Tree
}

func NewMemoryDb() Client {
	return &MemoryDb{tree: merkle.NewTree()}
}

func (db *MemoryDb) AddLeaf(_ context.Context, leaf *types.Leaf, treeSize uint64) (AddLeafStatus, error) {
	var blob leafBlob
	copy(blob[:], leaf.ToBinary())
	h := merkle.HashLeafNode(blob[:])
	db.mu.Lock()
	defer db.mu.Unlock()
	if !db.tree.AddLeafHash(&h) {
		i, err := db.tree.GetLeafIndex(&h)
		return AddLeafStatus{
			AlreadyExists: true,
			IsSequenced:   err == nil && i < treeSize,
		}, nil
	}
	db.leafs = append(db.leafs, blob)
	return AddLeafStatus{}, nil
}

func (db *MemoryDb) AddSequencedLeaves(_ context.Context, leaves []types.Leaf, index int64) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.tree.Size() != uint64(index) {
		return fmt.Errorf("incorrect index %d, tree size %d", index, db.tree.Size())
	}
	for i, leaf := range leaves {
		var blob leafBlob
		copy(blob[:], leaf.ToBinary())
		h := merkle.HashLeafNode(blob[:])
		if !db.tree.AddLeafHash(&h) {
			// TODO: What state can callers expect on error?
			return fmt.Errorf("unexpected duplicate at index %d", index+int64(i))
		}
		db.leafs = append(db.leafs, blob)
	}
	return nil
}

func (db *MemoryDb) GetTreeHead(_ context.Context) (types.TreeHead, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return types.TreeHead{
		TreeSize: uint64(db.tree.Size()),
		RootHash: db.tree.GetRootHash(),
	}, nil
}

func (db *MemoryDb) GetConsistencyProof(_ context.Context, req *requests.ConsistencyProof) (types.ConsistencyProof, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	path, err := db.tree.ProveConsistency(req.OldSize, req.NewSize)
	if err != nil {
		return types.ConsistencyProof{}, err
	}
	return types.ConsistencyProof{
		OldSize: req.OldSize,
		NewSize: req.NewSize,
		Path:    path,
	}, nil
}

func (db *MemoryDb) GetInclusionProof(_ context.Context, req *requests.InclusionProof) (types.InclusionProof, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	index, err := db.tree.GetLeafIndex(&req.LeafHash)
	if err != nil {
		return types.InclusionProof{}, ErrNotIncluded
	}
	path, err := db.tree.ProveInclusion(index, req.TreeSize)
	if err != nil {
		return types.InclusionProof{}, err
	}
	return types.InclusionProof{
		TreeSize:  req.TreeSize,
		LeafIndex: index,
		Path:      path,
	}, nil
}

func (db *MemoryDb) GetLeaves(_ context.Context, req *requests.Leaves) ([]types.Leaf, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	size := db.tree.Size()
	if req.StartIndex >= size || req.EndIndex > size || req.StartIndex >= req.EndIndex {
		return nil, fmt.Errorf("out of range request: start %d, end %d, size %d\n",
			req.StartIndex, req.EndIndex, size)
	}
	list := make([]types.Leaf, req.EndIndex-req.StartIndex)
	for i, _ := range list {
		if err := list[i].FromBinary(db.leafs[i+int(req.StartIndex)][:]); err != nil {
			panic(fmt.Errorf("internal error: %v", err))
		}
	}
	return list, nil
}
