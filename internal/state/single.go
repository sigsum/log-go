package state

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

var ErrUnknownWitness = errors.New("unknown witness")

// StateManagerSingle implements a single-instance StateManagerPrimary for primary nodes
type StateManagerSingle struct {
	client   db.Client
	signer   crypto.Signer
	keyHash  crypto.Hash
	interval time.Duration
	// Timeout for interaction with the secondary.
	timeout   time.Duration
	secondary client.Client
	sthFile   sthFile

	// Witnesses map trusted witness identifiers to public keys
	witnesses map[crypto.Hash]crypto.PublicKey

	// Lock-protected access to pointers. The pointed-to values
	// must be treated as immutable. All endpoints are readers.
	sync.RWMutex
	signedTreeHead   *types.SignedTreeHead
	cosignedTreeHead *types.CosignedTreeHead

	// Syncronized and deduplicated witness cosignatures for signedTreeHead
	cosignatures map[crypto.Hash]*crypto.Signature
}

// NewStateManagerSingle() sets up a new state manager, in particular its
// signedTreeHead.  An optional secondary node can be used to ensure that
// a newer primary tree is not signed unless it has been replicated.
func NewStateManagerSingle(dbcli db.Client, signer crypto.Signer, interval, timeout time.Duration,
	secondary client.Client, sthFileName string, witnesses map[crypto.Hash]crypto.PublicKey) (*StateManagerSingle, error) {
	pub := signer.Public()
	sm := &StateManagerSingle{
		client:    dbcli,
		signer:    signer,
		keyHash:   crypto.HashBytes(pub[:]),
		interval:  interval,
		timeout:   timeout,
		secondary: secondary,
		sthFile:   sthFile{name: sthFileName},
		witnesses: witnesses,
	}
	sth, err := sm.sthFile.Load(&pub)
	if err != nil {
		return nil, err
	}
	// Re-sign, with current timestamp.
	if sm.signedTreeHead, err = sm.signTreeHead(&sth.TreeHead); err != nil {
		return nil, err
	}
	// No cosignatures available at startup.
	sm.cosignedTreeHead = &types.CosignedTreeHead{SignedTreeHead: *sm.signedTreeHead}

	ctx := context.Background()
	for {
		err := sm.tryRotate(ctx)
		if err == nil {
			break
		}
		log.Warning("restore signed tree head: %v", err)
		time.Sleep(time.Second * 3)
	}
	return sm, nil
}

func (sm *StateManagerSingle) NextTreeHead() *types.SignedTreeHead {
	sm.RLock()
	defer sm.RUnlock()
	return sm.signedTreeHead
}

func (sm *StateManagerSingle) CosignedTreeHead() *types.CosignedTreeHead {
	sm.RLock()
	defer sm.RUnlock()
	return sm.cosignedTreeHead
}

func (sm *StateManagerSingle) AddCosignature(keyHash *crypto.Hash, sig *crypto.Signature) error {
	// This mapping is immutable, no lock needed.
	pub, ok := sm.witnesses[*keyHash]
	if !ok {
		return ErrUnknownWitness
	}

	// Write lock, since cosignatures mapping is updated. Note
	// that we can't release lock in between access to
	// sm.signedTreeHead and sm.cosignatures, since on concurrent
	// rotate we might add a cosignature for an old tree head.
	sm.Lock()
	defer sm.Unlock()

	if !sm.signedTreeHead.Verify(&pub, sig, &sm.keyHash) {
		return fmt.Errorf("invalid cosignature")
	}
	sm.cosignatures[crypto.HashBytes(pub[:])] = sig
	return nil
}

func (sm *StateManagerSingle) Run(ctx context.Context) {
	ticker := time.NewTicker(sm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := sm.tryRotate(ctx); err != nil {
				log.Warning("failed rotating tree heads: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (sm *StateManagerSingle) tryRotate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, sm.timeout)
	defer cancel()

	replicatedTreeHead, err := replicatedTreeAfter(
		ctx, sm.signedTreeHead.Size,
		sm.client, sm.secondary)
	if err != nil {
		log.Error("no new replicated tree head: %v", err)
		replicatedTreeHead = &sm.signedTreeHead.TreeHead
	}
	nextSTH, err := sm.signTreeHead(replicatedTreeHead)
	if err != nil {
		return fmt.Errorf("sign tree head: %v", err)
	}

	if err := sm.sthFile.Store(nextSTH); err != nil {
		return err
	}

	sm.rotate(nextSTH)
	return nil
}

// Identifies the latest tree head replicated by all secondaries, and
// with size >= after, or fails if some secondary is in a bad or too
// old state.
func replicatedTreeAfter(ctx context.Context, after uint64, primary db.Client, secondary client.Client) (*types.TreeHead, error) {
	primaryTreeHead, err := primary.GetTreeHead(ctx)
	if err != nil {
		return nil, fmt.Errorf("get primary tree head: %w", err)
	}
	if primaryTreeHead.Size < after {
		return nil, fmt.Errorf("primary is behind(!), %d < %d", primaryTreeHead.Size, after)
	}
	if secondary == nil {
		return &primaryTreeHead, nil
	}

	secSTH, err := secondary.GetToCosignTreeHead(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed fetching tree head from secondary: %w", err)
	}
	if secSTH.Size > primaryTreeHead.Size {
		return nil, fmt.Errorf("secondary is ahead of us: %d > %d", secSTH.Size, primaryTreeHead.Size)
	}
	if secSTH.Size < after {
		return nil, fmt.Errorf("secondary is behind: %d <= %d", secSTH.Size, after)
	}
	if secSTH.Size == primaryTreeHead.Size {
		if secSTH.RootHash != primaryTreeHead.RootHash {
			return nil, fmt.Errorf("secondary root hash doesn't match our root hash at tree size %d", secSTH.Size)
		}
		log.Debug("secondary is up-to-date with primary tree head, using primary tree, size %d", primaryTreeHead.Size)
		return &primaryTreeHead, nil
	}
	// We now know that
	// * the primary tree is ahead of the secondary (including them not being equal)
	// * both trees have size > after >= 0.

	req := requests.ConsistencyProof{
		OldSize: secSTH.Size,
		NewSize: primaryTreeHead.Size,
	}
	proof, err := primary.GetConsistencyProof(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("unable to get consistency proof from %d to %d: %w", req.OldSize, req.NewSize, err)
	}
	if err := proof.Verify(&secSTH.RootHash, &primaryTreeHead.RootHash); err != nil {
		return nil, fmt.Errorf("invalid consistency proof from %d to %d: %v", req.OldSize, req.NewSize, err)
	}
	log.Debug("using latest tree head from secondary: size %d", secSTH.Size)
	return &secSTH.TreeHead, nil
}

func (sm *StateManagerSingle) rotate(nextSTH *types.SignedTreeHead) {
	sm.Lock()
	defer sm.Unlock()

	log.Debug("about to rotate tree heads, next at %d: %s", nextSTH.Size, sm.treeStatusString())
	sm.setCosignedTreeHead()
	sm.setToCosignTreeHead(nextSTH)
	log.Debug("tree heads rotated: %s", sm.treeStatusString())
}

func (sm *StateManagerSingle) setCosignedTreeHead() {
	var cth types.CosignedTreeHead
	cth.SignedTreeHead = *sm.signedTreeHead
	cth.Cosignatures = make([]types.Cosignature, 0, len(sm.cosignatures))
	for keyHash, cosignature := range sm.cosignatures {
		cth.Cosignatures = append(cth.Cosignatures, types.Cosignature{
			KeyHash:   keyHash,
			Signature: *cosignature})
	}
	sm.cosignedTreeHead = &cth
}

func (sm *StateManagerSingle) setToCosignTreeHead(nextSTH *types.SignedTreeHead) {
	sm.cosignatures = make(map[crypto.Hash]*crypto.Signature)
	sm.signedTreeHead = nextSTH
}

func (sm *StateManagerSingle) treeStatusString() string {
	var cosigned uint64
	if sm.cosignedTreeHead != nil {
		cosigned = sm.cosignedTreeHead.Size
	}
	return fmt.Sprintf("signed at %d, cosigned at %d", sm.signedTreeHead.Size, cosigned)
}

// Signs tree head, with current time as timestamp.
func (sm *StateManagerSingle) signTreeHead(th *types.TreeHead) (*types.SignedTreeHead, error) {
	return th.Sign(sm.signer, &sm.keyHash, uint64(time.Now().Unix()))
}
