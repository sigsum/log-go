package db

import (
	"context"
	"fmt"
	"time"

	"git.sigsum.org/sigsum-go/pkg/requests"
	"git.sigsum.org/sigsum-go/pkg/types"
	"github.com/golang/glog"
	"github.com/google/trillian"
	trillianTypes "github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
)

// TrillianClient implements the Client interface for Trillian's gRPC backend
type TrillianClient struct {
	// TreeID is a Merkle tree identifier that Trillian uses
	TreeID int64

	// GRPC is a Trillian gRPC client
	GRPC trillian.TrillianLogClient
}

func (c *TrillianClient) AddLeaf(ctx context.Context, req *requests.Leaf) error {
	leaf := types.Leaf{
		Statement: types.Statement{
			ShardHint: req.ShardHint,
			Checksum:  *types.HashFn(req.Preimage[:]),
		},
		Signature: req.Signature,
		KeyHash:   *types.HashFn(req.VerificationKey[:]),
	}
	serialized := leaf.ToBinary()

	glog.V(3).Infof("queueing leaf request: %x", types.LeafHash(serialized))
	rsp, err := c.GRPC.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: c.TreeID,
		Leaf: &trillian.LogLeaf{
			LeafValue: serialized,
		},
	})
	if err != nil {
		return fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return fmt.Errorf("no response")
	}
	if rsp.QueuedLeaf == nil {
		return fmt.Errorf("no queued leaf")
	}
	if codes.Code(rsp.QueuedLeaf.GetStatus().GetCode()) == codes.AlreadyExists {
		return fmt.Errorf("leaf is already queued or included")
	}
	return nil
}

func (c *TrillianClient) GetTreeHead(ctx context.Context) (*types.TreeHead, error) {
	rsp, err := c.GRPC.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: c.TreeID,
	})
	if err != nil {
		return nil, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return nil, fmt.Errorf("no response")
	}
	if rsp.SignedLogRoot == nil {
		return nil, fmt.Errorf("no signed log root")
	}
	if rsp.SignedLogRoot.LogRoot == nil {
		return nil, fmt.Errorf("no log root")
	}
	var r trillianTypes.LogRootV1
	if err := r.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return nil, fmt.Errorf("no log root: unmarshal failed: %v", err)
	}
	if len(r.RootHash) != types.HashSize {
		return nil, fmt.Errorf("unexpected hash length: %d", len(r.RootHash))
	}
	return treeHeadFromLogRoot(&r), nil
}

func (c *TrillianClient) GetConsistencyProof(ctx context.Context, req *requests.ConsistencyProof) (*types.ConsistencyProof, error) {
	rsp, err := c.GRPC.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
		LogId:          c.TreeID,
		FirstTreeSize:  int64(req.OldSize),
		SecondTreeSize: int64(req.NewSize),
	})
	if err != nil {
		return nil, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return nil, fmt.Errorf("no response")
	}
	if rsp.Proof == nil {
		return nil, fmt.Errorf("no consistency proof")
	}
	if len(rsp.Proof.Hashes) == 0 {
		return nil, fmt.Errorf("not a consistency proof: empty")
	}
	path, err := nodePathFromHashes(rsp.Proof.Hashes)
	if err != nil {
		return nil, fmt.Errorf("not a consistency proof: %v", err)
	}
	return &types.ConsistencyProof{
		OldSize: req.OldSize,
		NewSize: req.NewSize,
		Path:    path,
	}, nil
}

func (c *TrillianClient) GetInclusionProof(ctx context.Context, req *requests.InclusionProof) (*types.InclusionProof, error) {
	rsp, err := c.GRPC.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:           c.TreeID,
		LeafHash:        req.LeafHash[:],
		TreeSize:        int64(req.TreeSize),
		OrderBySequence: true,
	})
	if err != nil {
		return nil, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return nil, fmt.Errorf("no response")
	}
	if len(rsp.Proof) != 1 {
		return nil, fmt.Errorf("bad proof count: %d", len(rsp.Proof))
	}
	proof := rsp.Proof[0]
	if len(proof.Hashes) == 0 {
		return nil, fmt.Errorf("not an inclusion proof: empty")
	}
	path, err := nodePathFromHashes(proof.Hashes)
	if err != nil {
		return nil, fmt.Errorf("not an inclusion proof: %v", err)
	}
	return &types.InclusionProof{
		TreeSize:  req.TreeSize,
		LeafIndex: uint64(proof.LeafIndex),
		Path:      path,
	}, nil
}

func (c *TrillianClient) GetLeaves(ctx context.Context, req *requests.Leaves) (*types.Leaves, error) {
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
	var list types.Leaves = make([]types.Leaf, 0, len(rsp.Leaves))
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
	return &list, nil
}

func treeHeadFromLogRoot(lr *trillianTypes.LogRootV1) *types.TreeHead {
	th := types.TreeHead{
		Timestamp: uint64(time.Now().Unix()),
		TreeSize:  uint64(lr.TreeSize),
	}
	copy(th.RootHash[:], lr.RootHash)
	return &th
}

func nodePathFromHashes(hashes [][]byte) ([]types.Hash, error) {
	path := make([]types.Hash, len(hashes))
	for i := 0; i < len(hashes); i++ {
		if len(hashes[i]) != types.HashSize {
			return nil, fmt.Errorf("unexpected hash length: %v", len(hashes[i]))
		}

		copy(path[i][:], hashes[i])
	}
	return path, nil
}
