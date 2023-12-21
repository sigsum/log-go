package secondary

import (
	"context"
	"errors"
	"time"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/requests"
)

const (
	leavesBatchSize = 100
)

// Secondary is an instance of a secondary node
type Secondary struct {
	Interval time.Duration // Signing frequency
	DbClient db.Client     // provides access to the backend, usually Trillian
	Signer   crypto.Signer // provides access to Ed25519 private key
	Primary  api.Log
}

func (s Secondary) Run(ctx context.Context) {
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.fetchLeavesFromPrimary(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (s Secondary) fetchLeavesFromPrimary(ctx context.Context) {
	for {
		curTH, err := s.DbClient.GetTreeHead(ctx)
		if err != nil {
			log.Warning("unable to get tree head from trillian: %v", err)
			return
		}
		req := requests.Leaves{
			StartIndex: curTH.Size,
			EndIndex:   curTH.Size + leavesBatchSize,
		}
		leaves, err := s.Primary.GetLeaves(ctx, req)
		if err != nil {
			if errors.Is(api.ErrNotFound, err) {
				// Normal way to exit, so don't log at warning level.
				log.Debug("error fetching leaves [%d:%d] from primary: %v", req.StartIndex, req.EndIndex, err)
			} else {
				log.Warning("error fetching leaves [%d:%d] from primary: %v", req.StartIndex, req.EndIndex, err)
			}
			return
		}
		log.Debug("got %d leaves from primary when asking for [%d:%d]", len(leaves), req.StartIndex, req.EndIndex)
		if err := s.DbClient.AddSequencedLeaves(ctx, leaves, int64(req.StartIndex)); err != nil {
			log.Error("AddSequencedLeaves: %v", err)
			return
		}
	}
}
