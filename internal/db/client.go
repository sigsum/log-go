package db

import (
	"context"

	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type AddLeafStatus struct {
	AlreadyExists bool
	IsSequenced   bool
}

// Client is an interface that interacts with a log's database backend
type Client interface {
	AddLeaf(context.Context, *requests.Leaf, uint64) (AddLeafStatus, error)
	AddSequencedLeaves(ctx context.Context, leaves []types.Leaf, index int64) error
	GetTreeHead(context.Context) (*types.TreeHead, error)
	GetConsistencyProof(context.Context, *requests.ConsistencyProof) (*types.ConsistencyProof, error)
	GetInclusionProof(context.Context, *requests.InclusionProof) (*types.InclusionProof, error)
	GetLeaves(context.Context, *requests.Leaves) (*[]types.Leaf, error)
}
