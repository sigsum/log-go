package secondary

import (
	"context"
	"net/http"
	"time"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	leavesBatchSize = 100
)

// Secondary is an instance of a secondary node
type Secondary struct {
	Config   handler.Config
	Interval time.Duration // Signing frequency
	DbClient db.Client     // provides access to the backend, usually Trillian
	Signer   crypto.Signer // provides access to Ed25519 private key
	Primary  client.Client
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

// TODO: nit-pick: the internal endpoint is used by primaries to figure out how much can be signed; not cosigned - update name?

func (s Secondary) InternalHTTPMux(prefix string) *http.ServeMux {
	mux := http.NewServeMux()
	handler.Handler{s.Config, s.getTreeHeadToCosign, types.EndpointGetNextTreeHead, http.MethodGet}.Register(mux, prefix)
	return mux
}

func (s Secondary) fetchLeavesFromPrimary(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, s.Config.Timeout)
	defer cancel()

	for {
		curTH, err := s.DbClient.GetTreeHead(ctx)
		if err != nil {
			log.Warning("unable to get tree head from trillian: %v", err)
			return
		}
		// TODO: set context per request
		req := requests.Leaves{
			StartIndex: curTH.Size,
			EndIndex:   curTH.Size + leavesBatchSize,
		}
		leaves, err := s.Primary.GetLeaves(ctx, req)
		// Can we have a specific HTTP code for the case that StartSize equals size,
		// which would be the normal way to exit this loop?
		if err != nil {
			log.Warning("error fetching leaves [%d:%d] from primary: %v", req.StartIndex, req.EndIndex, err)
			return
		}
		log.Debug("got %d leaves from primary when asking for [%d:%d]", len(leaves), req.StartIndex, req.EndIndex)
		if err := s.DbClient.AddSequencedLeaves(ctx, leaves, int64(req.StartIndex)); err != nil {
			log.Error("AddSequencedLeaves: %v", err)
			return
		}
	}
}
