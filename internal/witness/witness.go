package witness

import (
	"context"
	"sync"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func witnessClient(
	config *WitnessConfig, logKeyHash *crypto.Hash,
	getConsistencyProof func(
		ctx context.Context,
		req *requests.ConsistencyProof) (types.ConsistencyProof, error)) func(ctx context.Context, sth *types.SignedTreeHead) (types.Cosignature, error) {
	client := NewClient(config, logKeyHash)
	prevSize := uint64(0)

	return func(ctx context.Context, sth *types.SignedTreeHead) (types.Cosignature, error) {
		for {
			proof, err := getConsistencyProof(ctx, &requests.ConsistencyProof{
				OldSize: prevSize,
				NewSize: sth.Size,
			})
			if err != nil {
				return types.Cosignature{}, err
			}
			cs, err := client.AddTreeHead(ctx, sth, prevSize, &proof)
			if err == nil {
				prevSize = sth.Size
				return cs, nil
			}
			if err != errBadOldsize {
				return types.Cosignature{}, err
			}
			size, err := client.GetTreeSize(ctx)
			if err != nil {
				return types.Cosignature{}, err
			}
			prevSize = size
		}
	}
}

// Not concurrency safe
type CosignatureCollector struct {
	witnesses []func(ctx context.Context, sth *types.SignedTreeHead) (types.Cosignature, error)
}

func NewCosignatureCollector(logKeyHash *crypto.Hash, witnessConfigs []WitnessConfig,
	getConsistencyProof func(
		ctx context.Context,
		req *requests.ConsistencyProof) (types.ConsistencyProof, error)) *CosignatureCollector {
	collector := CosignatureCollector{}
	for _, w := range witnessConfigs {
		collector.witnesses = append(collector.witnesses,
			witnessClient(&w, logKeyHash, getConsistencyProof))
	}
	return &collector
}

// Queries all witnesses in parallel, blocks until we have result or error from each of them.
func (c *CosignatureCollector) GetCosignatures(ctx context.Context, sth *types.SignedTreeHead) (cosignatures []types.Cosignature) {
	wg := sync.WaitGroup{}

	ch := make(chan types.Cosignature)

	// Query witnesses in parallel
	for i, w := range c.witnesses {
		i, w := i, w // New variables for each round through the loop.
		wg.Add(1)
		go func() {
			cs, err := w(ctx, sth)
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
	close(ch)
	return
}
