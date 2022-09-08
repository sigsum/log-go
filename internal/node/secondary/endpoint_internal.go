package secondary

// This file implements internal HTTP handler callbacks for secondary nodes.

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"

	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

func getTreeHeadToCosign(ctx context.Context, c handler.Config, w http.ResponseWriter, _ *http.Request) (int, error) {
	s := c.(Secondary)
	log.Debug("handling get-tree-head-to-cosign request")

	signedTreeHead := func() (*types.SignedTreeHead, error) {
		tctx, cancel := context.WithTimeout(ctx, s.Config.Deadline)
		defer cancel()
		th, err := treeHeadFromTrillian(tctx, s.TrillianClient)
		if err != nil {
			return nil, fmt.Errorf("getting tree head: %w", err)
		}
		namespace := merkle.HashFn(s.Signer.Public().(ed25519.PublicKey))
		sth, err := th.Sign(s.Signer, namespace)
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
