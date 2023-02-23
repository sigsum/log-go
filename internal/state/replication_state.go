package state

import (
	"context"
	"fmt"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// Subset of the db/client interface.
type PrimaryTree interface {
	GetTreeHead(context.Context) (types.TreeHead, error)
	GetConsistencyProof(context.Context, *requests.ConsistencyProof) (types.ConsistencyProof, error)
}

// Subset of the sigsum-go pkg/client interface.
type SecondaryTree interface {
	GetNextTreeHead(context.Context) (types.SignedTreeHead, error)
}

type ReplicationState struct {
	// Timeout for interaction with primary and secondary.
	timeout      time.Duration
	primary      PrimaryTree
	secondaryPub crypto.PublicKey
	secondary    SecondaryTree
}

// Return the latest primary tree head with size at least minSize.
func (r ReplicationState) getPrimaryTreeHead(ctx context.Context, minSize uint64) (types.TreeHead, error) {
	primaryTreeHead, err := r.primary.GetTreeHead(ctx)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("get primary tree head: %w", err)
	}
	if primaryTreeHead.Size < minSize {
		return types.TreeHead{}, fmt.Errorf("primary is behind(!), %d < %d", primaryTreeHead.Size, minSize)
	}
	return primaryTreeHead, nil
}

// Return the latest secondary tree head with size at least minSize.
func (r ReplicationState) getSecondaryTreeHead(ctx context.Context, minSize uint64, maxSize uint64) (types.TreeHead, error) {
	sth, err := r.secondary.GetNextTreeHead(ctx)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("failed fetching tree head from secondary: %w", err)
	}
	if !sth.Verify(&r.secondaryPub) {
		return types.TreeHead{}, fmt.Errorf("invalid signature on secondary's tree head")
	}
	if sth.Size > maxSize {
		return types.TreeHead{}, fmt.Errorf("secondary is ahead: %d > %d", sth.Size, maxSize)
	}
	if sth.Size < minSize {
		return types.TreeHead{}, fmt.Errorf("secondary is behind: %d < %d", sth.Size, minSize)
	}
	// Responsiblity of GetToCosignTreeHead to check signature, now we no longer need it.
	return sth.TreeHead, nil
}

// Check consistency
func (r ReplicationState) checkConsistency(ctx context.Context, old types.TreeHead, new types.TreeHead) error {
	if old.Size > new.Size {
		panic(fmt.Errorf("internal error old.Size (%d) > new.Size (%d)", old.Size, new.Size))
	}
	if old.Size == new.Size {
		if old.RootHash != new.RootHash {
			return fmt.Errorf("primary and secondary root hash doesn't match at tree size %d", old.Size)
		}
		return nil
	}
	// Anything is consistent with an empty tree.
	if old.Size == 0 {
		return nil
	}
	proof, err := r.primary.GetConsistencyProof(ctx, &requests.ConsistencyProof{
		OldSize: old.Size,
		NewSize: new.Size,
	})
	if err != nil {
		return fmt.Errorf("unable to get consistency proof from %d to %d: %w", old.Size, new.Size, err)
	}
	return proof.Verify(&old.RootHash, &new.RootHash)
}

// Identifies the latest tree head replicated by the secondary, and
// with size >= minSize, or fails if priamry or secondary is in a bad
// or too old state.
func (r ReplicationState) ReplicatedTreeHead(ctx context.Context, minSize uint64) (types.TreeHead, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	primaryTreeHead, err := r.getPrimaryTreeHead(ctx, minSize)
	if err != nil {
		return types.TreeHead{}, err
	}
	if primaryTreeHead.Size == minSize || r.secondary == nil {
		return primaryTreeHead, nil
	}

	secTreeHead, err := r.getSecondaryTreeHead(ctx, minSize, primaryTreeHead.Size)
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("failed fetching tree head from secondary: %w", err)
	}

	if err := r.checkConsistency(ctx, secTreeHead, primaryTreeHead); err != nil {
		return types.TreeHead{}, err
	}
	log.Debug("using latest tree head from secondary: size %d", secTreeHead.Size)
	return secTreeHead, nil
}
