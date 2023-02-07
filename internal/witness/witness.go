package witness

import (
	"context"
	"time"

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

type CosignatureResponse struct {
	Cosignature types.Cosignature
	Err         error
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
func (c *CosignatureCollector) GetCosignatures(sth *types.SignedTreeHead, timeout time.Duration) types.CosignedTreeHead {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cth := types.CosignedTreeHead{SignedTreeHead: *sth}
	ch := make(chan CosignatureResponse)

	// Query witnesses in parallel
	for _, w := range c.witnesses {
		go func(ctx context.Context, sth *types.SignedTreeHead) {
			cs, err := w(ctx, sth)
			ch <- CosignatureResponse{Cosignature: cs, Err: err}
		}(ctx, sth)
	}
	for i, _ := range c.witnesses {
		rsp := <-ch
		if rsp.Err != nil {
			log.Error("Querying witness %d failed: %v", i, rsp.Err)
			// TODO: Temporarily stop querying this witness?
			continue
		}
		cth.Cosignatures = append(cth.Cosignatures, rsp.Cosignature)
	}
	close(ch)
	return cth
}
