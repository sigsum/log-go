package secondary

// This file implements internal HTTP handler callbacks for secondary nodes.

import (
	"context"
	"fmt"

	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

func (s Secondary) GetSecondaryTreeHead(ctx context.Context) (types.SignedTreeHead, error) {
	log.Debug("handling get-secondary-tree-head request")

	th, err := s.DbClient.GetTreeHead(ctx)
	if err != nil {
		return types.SignedTreeHead{}, fmt.Errorf("getting tree head: %w", err)
	}
	return th.Sign(s.Signer)
}
