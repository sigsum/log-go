package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/trillian"
	trillianTypes "github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// TrillianClient implements the Client interface for Trillian's gRPC backend
type TrillianClient struct {
	// TreeID is a Merkle tree identifier that Trillian uses
	TreeID int64

	// GRPC is a Trillian gRPC client
	GRPC trillian.TrillianLogClient
}

// AddLeaf adds a leaf to the tree and returns true if the leaf has
// been sequenced into the tree of size treeSize.
func (c *TrillianClient) AddLeaf(ctx context.Context, leaf *types.Leaf, treeSize uint64) (AddLeafStatus, error) {
	serialized := leaf.ToBinary()

	log.Debug("queueing leaf request: %x", merkle.HashLeafNode(serialized))
	_, err := c.GRPC.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: c.TreeID,
		Leaf: &trillian.LogLeaf{
			LeafValue: serialized,
		},
	})
	var alreadyExists bool
	switch status.Code(err) {
	case codes.OK:
		alreadyExists = false
	case codes.AlreadyExists:
		alreadyExists = true
	default:
		log.Warning("gRPC error: %v", err)
		return AddLeafStatus{}, fmt.Errorf("back-end failure")
	}
	_, err = c.GetInclusionProof(ctx, &requests.InclusionProof{treeSize, merkle.HashLeafNode(serialized)})
	return AddLeafStatus{AlreadyExists: alreadyExists, IsSequenced: err == nil}, nil
}

// AddSequencedLeaves adds a set of already sequenced leaves to the tree.
func (c *TrillianClient) AddSequencedLeaves(ctx context.Context, leaves []types.Leaf, index int64) error {
	trilLeaves := make([]*trillian.LogLeaf, len(leaves))
	for i, leaf := range leaves {
		trilLeaves[i] = &trillian.LogLeaf{
			LeafValue: leaf.ToBinary(),
			LeafIndex: index + int64(i),
		}
	}

	req := trillian.AddSequencedLeavesRequest{
		LogId:  c.TreeID,
		Leaves: trilLeaves,
	}
	log.Debug("adding sequenced leaves: count %d", len(trilLeaves))
	var err error
	for wait := 1; wait < 30; wait *= 2 {
		var rsp *trillian.AddSequencedLeavesResponse
		rsp, err = c.GRPC.AddSequencedLeaves(ctx, &req)
		switch status.Code(err) {
		case codes.ResourceExhausted:
			log.Info("waiting %d seconds before retrying to add %d leaves, reason: %v", wait, len(trilLeaves), err)
			time.Sleep(time.Second * time.Duration(wait))
			continue
		case codes.OK:
			if rsp == nil {
				return fmt.Errorf("GRPC.AddSequencedLeaves no response")
			}
			// FIXME: check rsp.Results.QueuedLogLeaf
			return nil
		default:
			return fmt.Errorf("GRPC.AddSequencedLeaves error: %v", err)
		}
	}

	return fmt.Errorf("giving up on adding %d leaves", len(trilLeaves))
}

func (c *TrillianClient) GetTreeHead(ctx context.Context) (types.TreeHead, error) {
	rsp, err := c.GRPC.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: c.TreeID,
	})
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return types.TreeHead{}, fmt.Errorf("no response")
	}
	if rsp.SignedLogRoot == nil {
		return types.TreeHead{}, fmt.Errorf("no signed log root")
	}
	if rsp.SignedLogRoot.LogRoot == nil {
		return types.TreeHead{}, fmt.Errorf("no log root")
	}
	var r trillianTypes.LogRootV1
	if err := r.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return types.TreeHead{}, fmt.Errorf("no log root: unmarshal failed: %v", err)
	}
	if len(r.RootHash) != crypto.HashSize {
		return types.TreeHead{}, fmt.Errorf("unexpected hash length: %d", len(r.RootHash))
	}
	return treeHeadFromLogRoot(&r), nil
}

func (c *TrillianClient) GetConsistencyProof(ctx context.Context, req *requests.ConsistencyProof) (types.ConsistencyProof, error) {
	rsp, err := c.GRPC.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
		LogId:          c.TreeID,
		FirstTreeSize:  int64(req.OldSize),
		SecondTreeSize: int64(req.NewSize),
	})
	if err != nil {
		return types.ConsistencyProof{}, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return types.ConsistencyProof{}, fmt.Errorf("no response")
	}
	if rsp.Proof == nil {
		return types.ConsistencyProof{}, fmt.Errorf("no consistency proof")
	}
	if len(rsp.Proof.Hashes) == 0 {
		return types.ConsistencyProof{}, fmt.Errorf("not a consistency proof: empty")
	}
	path, err := nodePathFromHashes(rsp.Proof.Hashes)
	if err != nil {
		return types.ConsistencyProof{}, fmt.Errorf("not a consistency proof: %v", err)
	}
	return types.ConsistencyProof{
		OldSize: req.OldSize,
		NewSize: req.NewSize,
		Path:    path,
	}, nil
}

func (c *TrillianClient) GetInclusionProof(ctx context.Context, req *requests.InclusionProof) (types.InclusionProof, error) {
	rsp, err := c.GRPC.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:           c.TreeID,
		LeafHash:        req.LeafHash[:],
		TreeSize:        int64(req.TreeSize),
		OrderBySequence: true,
	})
	if err != nil {
		return types.InclusionProof{}, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return types.InclusionProof{}, fmt.Errorf("no response")
	}
	if len(rsp.Proof) != 1 {
		return types.InclusionProof{}, fmt.Errorf("bad proof count: %d", len(rsp.Proof))
	}
	proof := rsp.Proof[0]
	if len(proof.Hashes) == 0 {
		return types.InclusionProof{}, fmt.Errorf("not an inclusion proof: empty")
	}
	path, err := nodePathFromHashes(proof.Hashes)
	if err != nil {
		return types.InclusionProof{}, fmt.Errorf("not an inclusion proof: %v", err)
	}
	return types.InclusionProof{
		TreeSize:  req.TreeSize,
		LeafIndex: uint64(proof.LeafIndex),
		Path:      path,
	}, nil
}

func (c *TrillianClient) GetLeaves(ctx context.Context, req *requests.Leaves) ([]types.Leaf, error) {
	rsp, err := c.GRPC.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
		LogId:      c.TreeID,
		StartIndex: int64(req.StartSize),
		Count:      int64(req.EndSize-req.StartSize) + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return nil, fmt.Errorf("no response")
	}
	if got, want := len(rsp.Leaves), int(req.EndSize-req.StartSize+1); got != want {
		return nil, fmt.Errorf("unexpected number of leaves: %d", got)
	}
	list := make([]types.Leaf, 0, len(rsp.Leaves))
	for i, leaf := range rsp.Leaves {
		leafIndex := int64(req.StartSize + uint64(i))
		if leafIndex != leaf.LeafIndex {
			return nil, fmt.Errorf("unexpected leaf(%d): got index %d", leafIndex, leaf.LeafIndex)
		}

		var l types.Leaf
		if err := l.FromBinary(leaf.LeafValue); err != nil {
			return nil, fmt.Errorf("unexpected leaf(%d): %v", leafIndex, err)
		}
		list = append(list[:], l)
	}
	return list, nil
}

func treeHeadFromLogRoot(lr *trillianTypes.LogRootV1) types.TreeHead {
	th := types.TreeHead{
		TreeSize: uint64(lr.TreeSize),
	}
	copy(th.RootHash[:], lr.RootHash)
	return th
}

func nodePathFromHashes(hashes [][]byte) ([]crypto.Hash, error) {
	path := make([]crypto.Hash, len(hashes))
	for i := 0; i < len(hashes); i++ {
		if len(hashes[i]) != crypto.HashSize {
			return nil, fmt.Errorf("unexpected hash length: %v", len(hashes[i]))
		}

		copy(path[i][:], hashes[i])
	}
	return path, nil
}
