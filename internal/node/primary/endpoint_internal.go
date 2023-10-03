package primary

// This file implements internal HTTP handler callbacks for primary nodes.

import (
	"context"
	"fmt"

	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func (p Primary) getLeavesInternal(ctx context.Context, req requests.Leaves) ([]types.Leaf, error) {
	th, err := p.DbClient.GetTreeHead(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting tree head: %v", err)
	}
	return getLeavesGeneral(ctx, p, req, th.Size, false)
}
