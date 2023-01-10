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

	prim, err := s.Primary.GetUnsignedTreeHead(ctx)
	if err != nil {
		log.Warning("unable to get tree head from primary: %v", err)
		return
	}
	log.Debug("got tree head from primary, size %d", prim.Size)

	curTH, err := s.DbClient.GetTreeHead(ctx)
	if err != nil {
		log.Warning("unable to get tree head from trillian: %v", err)
		return
	}
	log.Debug("got tree head from trillian, size %d", curTH.Size)
	var leaves []types.Leaf
	for index := int64(curTH.Size); index < int64(prim.Size); index += int64(len(leaves)) {
		req := requests.Leaves{
			StartIndex: uint64(index),
			EndIndex:   prim.Size,
		}
		// TODO: set context per request
		leaves, err = s.Primary.GetLeaves(ctx, req)
		if err != nil {
			log.Warning("error fetching leaves [%d:%d] from primary: %v", req.StartIndex, req.EndIndex, err)
			return
		}
		log.Debug("got %d leaves from primary when asking for [%d:%d]", len(leaves), req.StartIndex, req.EndIndex)
		if err := s.DbClient.AddSequencedLeaves(ctx, leaves, index); err != nil {
			log.Error("AddSequencedLeaves: %v", err)
			return
		}
	}
}
