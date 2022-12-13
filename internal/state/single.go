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
	th, err := sm.client.GetTreeHead(ctx)
	if err != nil {
		return fmt.Errorf("get tree head: %v", err)
	}
	nextSTH, err := sm.signTreeHead(sm.chooseTree(ctx, &th))
	if err != nil {
		return fmt.Errorf("sign tree head: %v", err)
	}
	log.Debug("wanted to advance to size %d, chose size %d", th.Size, nextSTH.Size)

	if err := sm.sthFile.Store(nextSTH); err != nil {
		return err
	}

	sm.rotate(nextSTH)
	return nil
}

// chooseTree picks a tree to publish, taking the state of a possible secondary node into account.
func (sm *StateManagerSingle) chooseTree(ctx context.Context, proposedTreeHead *types.TreeHead) *types.TreeHead {
	if sm.secondary == nil {
		return proposedTreeHead
	}

	secSTH, err := sm.secondary.GetToCosignTreeHead(ctx)
	if err != nil {
		log.Warning("failed fetching tree head from secondary: %v", err)
		return &sm.signedTreeHead.TreeHead
	}
	if secSTH.Size > proposedTreeHead.Size {
		log.Error("secondary is ahead of us: %d > %d", secSTH.Size, proposedTreeHead.Size)
		return &sm.signedTreeHead.TreeHead
	}
	if secSTH.Size == proposedTreeHead.Size {
		if secSTH.RootHash != proposedTreeHead.RootHash {
			log.Error("secondary root hash doesn't match our root hash at tree size %d", secSTH.Size)
			return &sm.signedTreeHead.TreeHead
		}
		log.Debug("secondary is up-to-date with matching tree head, using proposed tree, size %d", proposedTreeHead.Size)
		return proposedTreeHead
	}
	// We now know that
	// * the proposed tree is ahead of the secondary (including them not being equal)
	// * the minimal tree size is 0, so the proposed tree is at tree size 1 or greater

	// Consistency proofs can not be produced from a tree of size 0, so don't try when the secondary is at 0.
	if secSTH.Size == 0 {
		log.Debug("secondary tree size is zero, using latest published tree head: size %d", sm.signedTreeHead.Size)
		return &sm.signedTreeHead.TreeHead
	}
	if err := sm.verifyConsistency(ctx, &secSTH.TreeHead, proposedTreeHead); err != nil {
		log.Error("secondary tree not consistent with ours: %v", err)
		return &sm.signedTreeHead.TreeHead
	}
	// We now know that
	// * we have two candidates: latest published and secondary's tree
	// * secondary's tree is verified to be consistent with our proposed tree

	// Protect against going backwards by chosing the larger of secondary tree and latest published.
	if sm.signedTreeHead.Size > secSTH.TreeHead.Size {
		log.Debug("using latest published tree head: size %d", sm.signedTreeHead.Size)
		return &sm.signedTreeHead.TreeHead
	}

	log.Debug("using latest tree head from secondary: size %d", secSTH.Size)
	return &secSTH.TreeHead
}

func (sm *StateManagerSingle) verifyConsistency(ctx context.Context, from, to *types.TreeHead) error {
	req := &requests.ConsistencyProof{
		OldSize: from.Size,
		NewSize: to.Size,
	}
	proof, err := sm.client.GetConsistencyProof(ctx, req)
	if err != nil {
		return fmt.Errorf("unable to get consistency proof from %d to %d: %w", req.OldSize, req.NewSize, err)
	}
	if err := proof.Verify(&from.RootHash, &to.RootHash); err != nil {
		return fmt.Errorf("invalid consistency proof from %d to %d: %v", req.OldSize, req.NewSize, err)
	}
	log.Debug("consistency proof from %d to %d verified", req.OldSize, req.NewSize)
	return nil
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
