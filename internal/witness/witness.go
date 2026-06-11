package witness

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// WitnessMetrics collects /add-checkpoint probing outcomes.
type WitnessMetrics interface {
	RecordWitnessProbe(witnessID string, status string)
}

type GetConsistencyProofFunc func(ctx context.Context, req *requests.ConsistencyProof) (types.ConsistencyProof, error)

// Not concurrency safe, due to updates of prevSize.
type witness struct {
	client   api.Witness
	entity   policy.Entity
	keyHash  crypto.Hash
	prevSize uint64
	// Error from previous attempt.
	prevError error
}

func newWitness(w *policy.Entity) *witness {
	return &witness{
		client:   client.New(client.Config{URL: w.URL, UserAgent: "Sigsum log-go server"}),
		entity:   *w,
		keyHash:  crypto.HashBytes(w.PublicKey[:]),
		prevSize: 0,
	}
}

// Pack key hash and cosignature together, so they can be sent over a channel.
type cosignatureItem struct {
	keyHash crypto.Hash
	cs      types.Cosignature
	retried bool // true if a 409 retry occurred
}

func (w *witness) getCosignature(ctx context.Context, cp *checkpoint.Checkpoint, getConsistencyProof GetConsistencyProofFunc) (cosignatureItem, error) {
	freshOldSize := false
	for {
		proof, err := getConsistencyProof(ctx, &requests.ConsistencyProof{
			OldSize: w.prevSize,
			NewSize: cp.TreeHead.Size,
		})
		if err != nil {
			return cosignatureItem{retried: freshOldSize}, err
		}
		signatures, err := w.client.AddCheckpoint(ctx, requests.AddCheckpoint{
			OldSize:    w.prevSize,
			Proof:      proof,
			Checkpoint: *cp,
		})
		if err == nil {
			cs, err := cp.VerifyCosignatureByKey(signatures, &w.entity.PublicKey)
			if err != nil {
				return cosignatureItem{retried: freshOldSize}, err
			}
			w.prevSize = cp.Size
			return cosignatureItem{keyHash: w.keyHash, cs: cs, retried: freshOldSize}, nil
		}
		// Retry only once.
		if freshOldSize {
			return cosignatureItem{retried: true}, err
		}
		if oldSize, ok := api.ErrorConflictOldSize(err); ok {
			w.prevSize = oldSize
			freshOldSize = true
		} else {
			return cosignatureItem{}, err
		}
	}
}

type CosignatureCollector struct {
	origin              string
	keyId               checkpoint.KeyId
	getConsistencyProof GetConsistencyProofFunc
	witnesses           []*witness
	metrics             WitnessMetrics
}

func NewCosignatureCollector(logPublicKey *crypto.PublicKey, witnesses []policy.Entity,
	getConsistencyProof GetConsistencyProofFunc, metrics WitnessMetrics) *CosignatureCollector {
	origin := types.SigsumCheckpointOrigin(logPublicKey)

	collector := CosignatureCollector{
		origin:              origin,
		keyId:               checkpoint.NewLogKeyId(origin, logPublicKey),
		getConsistencyProof: getConsistencyProof,
		metrics:             metrics,
	}
	for _, w := range witnesses {
		collector.witnesses = append(collector.witnesses,
			newWitness(&w))
	}
	return &collector
}

// Queries all witnesses in parallel, blocks until we have result or error from each of them.
// Must not be concurrently called.
func (c *CosignatureCollector) GetCosignatures(ctx context.Context, sth *types.SignedTreeHead) map[crypto.Hash]types.Cosignature {
	cp := checkpoint.Checkpoint{
		SignedTreeHead: *sth,
		Origin:         c.origin,
		KeyId:          c.keyId,
	}

	wg := sync.WaitGroup{}

	ch := make(chan cosignatureItem)

	// Query witnesses in parallel
	for i, w := range c.witnesses {
		wg.Add(1)
		go func(i int, w *witness) {
			cs, err := w.getCosignature(ctx, &cp, c.getConsistencyProof)
			if c.metrics != nil {
				witnessID := strings.TrimPrefix(strings.TrimPrefix(w.entity.URL, "https://"), "http://")
				var status string
				if err == nil {
					status = "200"
					if cs.retried {
						status = "200-after-409"
					}
				} else {
					var apiErr *api.Error
					if errors.As(err, &apiErr) {
						status = strconv.Itoa(apiErr.StatusCode())
					} else {
						status = "other"
					}
				}
				c.metrics.RecordWitnessProbe(witnessID, status)
			}
			// On logging of errors: api.ErrorStatusCode
			// returns the explicitly associated status
			// code, if any, otherwise 500. To reduce
			// amount of logging at INFO level, log only
			// errors when there's a change of status
			// code. Repeated errors are deemed less
			// interesting, and logged at DEBUG level.
			if err != nil {
				if w.prevError == nil || (api.ErrorStatusCode(err) != api.ErrorStatusCode(w.prevError)) {
					log.Info("querying witness %q failed: %v", w.entity.URL, err)
				} else {
					log.Debug("querying witness %q failed: %v", w.entity.URL, err)
				}
			} else {
				if w.prevError != nil {
					log.Info("querying witness %q succeeded, previous attempt failed: %v", w.entity.URL, w.prevError)
				}
				ch <- cs
			}
			w.prevError = err
			wg.Done()
		}(i, w)
	}
	go func() { wg.Wait(); close(ch) }()

	cosignatures := make(map[crypto.Hash]types.Cosignature)
	for i := range ch {
		// TODO: Check that cosignature timestamp is reasonable?
		cosignatures[i.keyHash] = i.cs
	}
	return cosignatures
}
