package witness

import (
	"context"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

type WitnessConfig struct {
	Url     string // Base url
	PubKey  crypto.PublicKey
	Timeout time.Duration
}

type CosignatureResponse struct {
	Size        uint64 // Identifies the tree head being cosigned.
	Cosignature types.Cosignature
	Err         error
}

type CosignatureRequest struct {
	Sth types.SignedTreeHead
	ret chan<- CosignatureResponse
}

func witnessClient(
	config WitnessConfig, logKeyHash *crypto.Hash,
	getConsistencyProof func(
		ctx context.Context,
		req *requests.ConsistencyProof) (types.ConsistencyProof, error),
	ch <-chan CosignatureRequest) {
	client := NewClient(config.Url, &config.PubKey, logKeyHash)
	prevSize := uint64(0)
	one := func(sth *types.SignedTreeHead) (types.Cosignature, error) {
		ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
		defer cancel()
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
	for req := range ch {
		cosignature, err := one(&req.Sth)
		req.ret <- CosignatureResponse{Size: req.Sth.Size, Cosignature: cosignature, Err: err}
	}
}

func NewWitness(
	config WitnessConfig, logKeyHash *crypto.Hash,
	getConsistencyProof func(
		ctx context.Context,
		req *requests.ConsistencyProof) (types.ConsistencyProof, error)) chan<- CosignatureRequest {
	ch := make(chan CosignatureRequest)
	go witnessClient(config, logKeyHash, getConsistencyProof, ch)
	return ch
}
