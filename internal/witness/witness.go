package witness

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type GetConsistencyProofFunc func(ctx context.Context, req *requests.ConsistencyProof) (types.ConsistencyProof, error)

// Not concurrency safe, due to updates of prevSize.
type witness struct {
	client              client.Witness
	logKeyHash          crypto.Hash
	pubKey              crypto.PublicKey
	prevSize            uint64
	getConsistencyProof GetConsistencyProofFunc
}

func newWitness(w *policy.Entity, logKeyHash *crypto.Hash, getConsistencyProof GetConsistencyProofFunc) *witness {
	return &witness{
		client:              client.New(client.Config{URL: w.URL, UserAgent: "Sigsum log-go server"}),
		pubKey:              w.PublicKey,
		logKeyHash:          *logKeyHash,
		prevSize:            0,
		getConsistencyProof: getConsistencyProof,
	}
}

func (w *witness) getCosignature(ctx context.Context, sth *types.SignedTreeHead) (types.Cosignature, error) {
	for {
		proof, err := w.getConsistencyProof(ctx, &requests.ConsistencyProof{
			OldSize: w.prevSize,
			NewSize: sth.Size,
		})
		if err != nil {
			return types.Cosignature{}, err
		}
		cs, err := w.client.AddTreeHead(ctx, requests.AddTreeHead{
			KeyHash:  w.logKeyHash,
			TreeHead: *sth,
			OldSize:  w.prevSize,
			Proof:    proof,
		})
		if err == nil {
			if !cs.Verify(&w.pubKey, &w.logKeyHash, &sth.TreeHead) {
				return types.Cosignature{}, fmt.Errorf("invalid cosignature")
			}
			w.prevSize = sth.Size
			return cs, nil
		}
		if !errors.Is(api.ErrConflict, err) {
			return types.Cosignature{}, err
		}
		size, err := w.client.GetTreeSize(ctx, requests.GetTreeSize{KeyHash: w.logKeyHash})
		if err != nil {
			return types.Cosignature{}, err
		}
		w.prevSize = size
	}
}

type CosignatureCollector struct {
	witnesses []*witness
}

func NewCosignatureCollector(logKeyHash *crypto.Hash, witnesses []policy.Entity,
	getConsistencyProof GetConsistencyProofFunc) *CosignatureCollector {
	collector := CosignatureCollector{}
	for _, w := range witnesses {
		collector.witnesses = append(collector.witnesses,
			newWitness(&w, logKeyHash, getConsistencyProof))
	}
	return &collector
}

// Queries all witnesses in parallel, blocks until we have result or error from each of them.
// Must not be concurrently called.
func (c *CosignatureCollector) GetCosignatures(ctx context.Context, sth *types.SignedTreeHead) (cosignatures []types.Cosignature) {
	wg := sync.WaitGroup{}

	ch := make(chan types.Cosignature)

	// Query witnesses in parallel
	for i, w := range c.witnesses {
		i, w := i, w // New variables for each round through the loop.
		wg.Add(1)
		go func() {
			cs, err := w.getCosignature(ctx, sth)
			if err != nil {
				log.Error("Querying witness %d failed: %v", i, err)
				// TODO: Temporarily stop querying this witness?
			} else {
				ch <- cs
			}
			wg.Done()
		}()
	}
	go func() { wg.Wait(); close(ch) }()

	for cs := range ch {
		// TODO: Check that cosignature timestamp is reasonable?
		cosignatures = append(cosignatures, cs)
	}
	return
}
