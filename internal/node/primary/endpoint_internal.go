package primary

// This file implements internal HTTP handler callbacks for primary nodes.

import (
	"context"
	"fmt"
	"net/http"

	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

func getTreeHeadUnsigned(ctx context.Context, c handler.Config, w http.ResponseWriter, _ *http.Request) (int, error) {
	log.Debug("handling %s request", types.EndpointGetTreeHeadUnsigned)
	p := c.(Primary)
	th, err := p.DbClient.GetTreeHead(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed getting tree head: %v", err)
	}
	if err := th.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getLeavesInternal(ctx context.Context, c handler.Config, w http.ResponseWriter, r *http.Request) (int, error) {
	return getLeavesGeneral(ctx, c, w, r, false)
}
