package db

import (
	"context"

	"git.sigsum.org/sigsum-lib-go/pkg/requests"
	"git.sigsum.org/sigsum-lib-go/pkg/types"
)

// Client is an interface that interacts with a log's database backend
type Client interface {
	AddLeaf(context.Context, *requests.Leaf) error
	GetTreeHead(context.Context) (*types.TreeHead, error)
	GetConsistencyProof(context.Context, *requests.ConsistencyProof) (*types.ConsistencyProof, error)
	GetInclusionProof(context.Context, *requests.InclusionProof) (*types.InclusionProof, error)
	GetLeaves(context.Context, *requests.Leaves) (*types.Leaves, error)
}
