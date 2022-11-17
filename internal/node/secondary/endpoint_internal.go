package secondary

// This file implements internal HTTP handler callbacks for secondary nodes.

import (
	"context"
	"fmt"
	"net/http"

	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

func getTreeHeadToCosign(ctx context.Context, c handler.Config, w http.ResponseWriter, _ *http.Request) (int, error) {
	s := c.(Secondary)
	log.Debug("handling get-tree-head-to-cosign request")

	signedTreeHead := func() (*types.SignedTreeHead, error) {
		tctx, cancel := context.WithTimeout(ctx, s.Config.Timeout)
		defer cancel()
		th, err := treeHeadFromTrillian(tctx, s.DbClient)
		if err != nil {
			return nil, fmt.Errorf("getting tree head: %w", err)
		}
		pub := s.Signer.Public()
		keyHash := crypto.HashBytes(pub[:])
		sth, err := th.Sign(s.Signer, &keyHash)
		if err != nil {
			return nil, fmt.Errorf("signing tree head: %w", err)
		}
		return sth, nil
	}

	sth, err := signedTreeHead()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := sth.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}
