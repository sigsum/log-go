package db

import (
	"context"

	"git.sigsum.org/sigsum-go/pkg/requests"
	"git.sigsum.org/sigsum-go/pkg/types"
)

// Client is an interface that interacts with a log's database backend
type Client interface {
	AddLeaf(context.Context, *requests.Leaf, uint64) (bool, error)
	AddSequencedLeaves(ctx context.Context, leaves types.Leaves, index int64) error
	GetTreeHead(context.Context) (*types.TreeHead, error)
	GetConsistencyProof(context.Context, *requests.ConsistencyProof) (*types.ConsistencyProof, error)
	GetInclusionProof(context.Context, *requests.InclusionProof) (*types.InclusionProof, error)
	GetLeaves(context.Context, *requests.Leaves) (*types.Leaves, error)
}
