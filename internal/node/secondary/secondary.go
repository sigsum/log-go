package secondary

import (
	"context"
	"fmt"
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
	Config          handler.Config
	Interval        time.Duration // Signing frequency
	PublicHTTPMux   *http.ServeMux
	InternalHTTPMux *http.ServeMux
	DbClient        db.Client     // provides access to the backend, usually Trillian
	Signer          crypto.Signer // provides access to Ed25519 private key
	Primary         client.Client
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

func (s Secondary) InternalHTTPHandlers() []handler.Handler {
	return []handler.Handler{
		handler.Handler{s.Config, s.getTreeHeadToCosign, types.EndpointGetTreeHeadToCosign, http.MethodGet},
	}
}

func (s Secondary) fetchLeavesFromPrimary(ctx context.Context) {
	prim, err := s.Primary.GetUnsignedTreeHead(ctx)
	if err != nil {
		log.Warning("unable to get tree head from primary: %v", err)
		return
	}
	log.Debug("got tree head from primary, size %d", prim.TreeSize)

	curTH, err := treeHeadFromTrillian(ctx, s.DbClient)
	if err != nil {
		log.Warning("unable to get tree head from trillian: %v", err)
		return
	}
	var leaves []types.Leaf
	for index := int64(curTH.TreeSize); index < int64(prim.TreeSize); index += int64(len(leaves)) {
		req := requests.Leaves{
			StartIndex: uint64(index),
			EndIndex:   prim.TreeSize,
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

func treeHeadFromTrillian(ctx context.Context, trillianClient db.Client) (types.TreeHead, error) {
	th, err := trillianClient.GetTreeHead(ctx)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("fetching tree head from trillian: %v", err)
	}
	log.Debug("got tree head from trillian, size %d", th.TreeSize)
	return th, nil
}
