package secondary

// This file implements internal HTTP handler callbacks for secondary nodes.

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

func (s Secondary) getTreeHeadToCosign(ctx context.Context, w http.ResponseWriter, _ *http.Request) (int, error) {
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
		sth, err := th.Sign(s.Signer, &keyHash, uint64(time.Now().Unix()))
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
