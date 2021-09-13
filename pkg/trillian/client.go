package trillian

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"golang.sigsum.org/sigsum-log-go/pkg/types"
	"google.golang.org/grpc/codes"
)

type Client interface {
	AddLeaf(context.Context, *types.LeafRequest) error
	GetConsistencyProof(context.Context, *types.ConsistencyProofRequest) (*types.ConsistencyProof, error)
	GetTreeHead(context.Context) (*types.TreeHead, error)
	GetInclusionProof(context.Context, *types.InclusionProofRequest) (*types.InclusionProof, error)
	GetLeaves(context.Context, *types.LeavesRequest) (*types.LeafList, error)
}

// TrillianClient is a wrapper around the Trillian gRPC client.
type TrillianClient struct {
	// TreeID is a Merkle tree identifier that Trillian uses
	TreeID int64

	// GRPC is a Trillian gRPC client
	GRPC trillian.TrillianLogClient
}

func (c *TrillianClient) AddLeaf(ctx context.Context, req *types.LeafRequest) error {
	leaf := types.Leaf{
		Message: req.Message,
		SigIdent: types.SigIdent{
			Signature: req.Signature,
			KeyHash:   types.Hash(req.VerificationKey[:]),
		},
	}
	serialized := leaf.Marshal()

	glog.V(3).Infof("queueing leaf request: %x", types.HashLeaf(serialized))
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
	var r ttypes.LogRootV1
	if err := r.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return nil, fmt.Errorf("no log root: unmarshal failed: %v", err)
	}
	if len(r.RootHash) != types.HashSize {
		return nil, fmt.Errorf("unexpected hash length: %d", len(r.RootHash))
	}
	return treeHeadFromLogRoot(&r), nil
}

func (c *TrillianClient) GetConsistencyProof(ctx context.Context, req *types.ConsistencyProofRequest) (*types.ConsistencyProof, error) {
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

func (c *TrillianClient) GetInclusionProof(ctx context.Context, req *types.InclusionProofRequest) (*types.InclusionProof, error) {
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

func (c *TrillianClient) GetLeaves(ctx context.Context, req *types.LeavesRequest) (*types.LeafList, error) {
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
	var list types.LeafList
	for i, leaf := range rsp.Leaves {
		leafIndex := int64(req.StartSize + uint64(i))
		if leafIndex != leaf.LeafIndex {
			return nil, fmt.Errorf("unexpected leaf(%d): got index %d", leafIndex, leaf.LeafIndex)
		}

		var l types.Leaf
		if err := l.Unmarshal(leaf.LeafValue); err != nil {
			return nil, fmt.Errorf("unexpected leaf(%d): %v", leafIndex, err)
		}
		list = append(list[:], &l)
	}
	return &list, nil
}
