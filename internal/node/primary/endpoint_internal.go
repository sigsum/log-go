package primary

// This file implements internal HTTP handler callbacks for primary nodes.

import (
	"context"
	"fmt"
	"net/http"
)

func (p Primary) getLeavesInternal(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
	th, err := p.DbClient.GetTreeHead(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed getting tree head: %v", err)
	}
	return getLeavesGeneral(ctx, p, w, r, th.Size, false)
}
