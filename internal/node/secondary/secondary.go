package secondary

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"time"

	"git.sigsum.org/log-go/internal/db"
	"git.sigsum.org/log-go/internal/node/handler"
	"git.sigsum.org/sigsum-go/pkg/client"
	"git.sigsum.org/sigsum-go/pkg/log"
	"git.sigsum.org/sigsum-go/pkg/requests"
	"git.sigsum.org/sigsum-go/pkg/types"
)

// Config is a collection of log parameters
type Config struct {
	LogID    string        // H(public key), then hex-encoded
	TreeID   int64         // Merkle tree identifier used by Trillian
	Prefix   string        // The portion between base URL and st/v0 (may be "")
	Deadline time.Duration // Deadline used for gRPC requests
	Interval time.Duration // Signing frequency
}

// Secondary is an instance of a secondary node
type Secondary struct {
	Config
	PublicHTTPMux   *http.ServeMux
	InternalHTTPMux *http.ServeMux
	TrillianClient  db.Client     // provides access to the Trillian backend
	Signer          crypto.Signer // provides access to Ed25519 private key
	Primary         client.Client
}

// Implementing handler.Config
func (s Secondary) Prefix() string {
	return s.Config.Prefix
}
func (s Secondary) LogID() string {
	return s.Config.LogID
}
func (s Secondary) Deadline() time.Duration {
	return s.Config.Deadline
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
		handler.Handler{s, getTreeHeadToCosign, types.EndpointGetTreeHeadToCosign, http.MethodGet},
	}
}

func (s Secondary) fetchLeavesFromPrimary(ctx context.Context) {
	prim, err := s.Primary.GetUnsignedTreeHead(ctx)
	if err != nil {
		log.Warning("unable to get tree head from primary: %v", err)
		return
	}
	log.Debug("got tree head from primary, size %d", prim.TreeSize)

	curTH, err := treeHeadFromTrillian(ctx, s.TrillianClient)
	if err != nil {
		log.Warning("unable to get tree head from trillian: %v", err)
		return
	}
	var leaves types.Leaves
	for index := int64(curTH.TreeSize); index < int64(prim.TreeSize); index += int64(len(leaves)) {
		req := requests.Leaves{
			StartSize: uint64(index),
			EndSize:   prim.TreeSize - 1,
		}
		// TODO: set context per request
		leaves, err = s.Primary.GetLeaves(ctx, req)
		if err != nil {
			log.Warning("error fetching leaves [%d..%d] from primary: %v", req.StartSize, req.EndSize, err)
			return
		}
		log.Debug("got %d leaves from primary when asking for [%d..%d]", len(leaves), req.StartSize, req.EndSize)
		if err := s.TrillianClient.AddSequencedLeaves(ctx, leaves, index); err != nil {
			log.Error("AddSequencedLeaves: %v", err)
			return
		}
	}
}

func treeHeadFromTrillian(ctx context.Context, trillianClient db.Client) (*types.TreeHead, error) {
	th, err := trillianClient.GetTreeHead(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching tree head from trillian: %v", err)
	}
	log.Debug("got tree head from trillian, size %d", th.TreeSize)
	return th, nil
}
