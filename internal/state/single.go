package state

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

var ErrUnknownWitness = errors.New("unknown witness")

// StateManagerSingle implements a single-instance StateManagerPrimary for primary nodes
type StateManagerSingle struct {
	signer           crypto.Signer
	keyHash          crypto.Hash
	storeSth         func(sth *types.SignedTreeHead) error
	replicationState ReplicationState

	// Witnesses map trusted witness identifiers to public keys
	witnesses map[crypto.Hash]crypto.PublicKey

	// Lock-protected access to pointers. All endpoints are readers.
	sync.RWMutex
	signedTreeHead   types.SignedTreeHead
	cosignedTreeHead types.CosignedTreeHead

	// Syncronized and deduplicated witness cosignatures for signedTreeHead
	cosignatures map[crypto.Hash]types.Cosignature
}

// NewStateManagerSingle() sets up a new state manager, in particular its
// signedTreeHead.  An optional secondary node can be used to ensure that
// a newer primary tree is not signed unless it has been replicated.
func NewStateManagerSingle(primary PrimaryTree, signer crypto.Signer, timeout time.Duration,
	secondary SecondaryTree, sthFileName string, witnesses map[crypto.Hash]crypto.PublicKey) (*StateManagerSingle, error) {
	pub := signer.Public()
	sthFile := sthFile{name: sthFileName}
	startupMode, err := sthFile.Startup()
	if err != nil {
		return nil, err
	}

	var sth types.SignedTreeHead
	switch startupMode {
	case startupSaved:
		sth, err = sthFile.Load(&pub)
		if err != nil {
			return nil, err
		}
	case startupEmpty:
		th := types.TreeHead{RootHash: crypto.HashBytes([]byte(""))}
		sth, err = th.Sign(signer)
		if err != nil {
			return nil, err
		}
		if err := sthFile.Create(&sth); err != nil {
			return nil, err
		}
	case startupLocalTree:
		th, err := primary.GetTreeHead(context.Background())
		if err != nil {
			return nil, err
		}
		sth, err = th.Sign(signer)
		if err != nil {
			return nil, err
		}
		if err := sthFile.Create(&sth); err != nil {
			return nil, err
		}
	default:
		panic(fmt.Sprintf("internal error, unknown startup mode %d", startupMode))
	}
	return &StateManagerSingle{
		signer:   signer,
		keyHash:  crypto.HashBytes(pub[:]),
		storeSth: sthFile.Store,
		replicationState: ReplicationState{
			primary:   primary,
			secondary: secondary,
			timeout:   timeout,
		},
		signedTreeHead: sth,
		// No cosignatures available at startup.
		cosignedTreeHead: types.CosignedTreeHead{SignedTreeHead: sth},
		witnesses:        witnesses,
	}, nil
}

func (sm *StateManagerSingle) NextTreeHead() types.SignedTreeHead {
	sm.RLock()
	defer sm.RUnlock()
	return sm.signedTreeHead
}

func (sm *StateManagerSingle) CosignedTreeHead() types.CosignedTreeHead {
	sm.RLock()
	defer sm.RUnlock()
	return sm.cosignedTreeHead
}

func (sm *StateManagerSingle) AddCosignature(sig *types.Cosignature) error {
	// This mapping is immutable, no lock needed.
	pub, ok := sm.witnesses[sig.KeyHash]
	if !ok {
		return ErrUnknownWitness
	}

	// TODO: Check that timestamp is resonable?
	// Write lock, since cosignatures mapping is updated. Note
	// that we can't release lock in between access to
	// sm.signedTreeHead and sm.cosignatures, since on concurrent
	// rotate we might add a cosignature for an old tree head.
	sm.Lock()
	defer sm.Unlock()

	if !sig.Verify(&pub, &sm.keyHash, &sm.signedTreeHead.TreeHead) {
		return fmt.Errorf("invalid cosignature")
	}
	sm.cosignatures[crypto.HashBytes(pub[:])] = *sig
	return nil
}

func (sm *StateManagerSingle) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
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
	nextTH, err := sm.replicationState.ReplicatedTreeHead(
		ctx, sm.signedTreeHead.Size)
	if err != nil {
		log.Error("no new replicated tree head: %v", err)
		nextTH = sm.signedTreeHead.TreeHead
	}
	return sm.rotate(&nextTH)
}

func (sm *StateManagerSingle) rotate(nextTH *types.TreeHead) error {
	nextSTH, err := nextTH.Sign(sm.signer)
	if err != nil {
		return fmt.Errorf("sign tree head: %v", err)
	}

	if err := sm.storeSth(&nextSTH); err != nil {
		return err
	}

	sm.Lock()
	defer sm.Unlock()

	log.Debug("about to rotate tree heads, next at %d: %s", nextSTH.Size, sm.treeStatusString())
	sm.setCosignedTreeHead()
	sm.setSignedTreeHead(&nextSTH)
	log.Debug("tree heads rotated: %s", sm.treeStatusString())
	return nil
}

// Must be called with write lock held.
func (sm *StateManagerSingle) setCosignedTreeHead() {
	sm.cosignedTreeHead = types.CosignedTreeHead{
		SignedTreeHead: sm.signedTreeHead,
		Cosignatures:   make([]types.Cosignature, 0, len(sm.cosignatures)),
	}
	for _, cosignature := range sm.cosignatures {
		sm.cosignedTreeHead.Cosignatures = append(sm.cosignedTreeHead.Cosignatures,
			cosignature)
	}
}

// Must be called with write lock held.
func (sm *StateManagerSingle) setSignedTreeHead(nextSTH *types.SignedTreeHead) {
	sm.cosignatures = make(map[crypto.Hash]types.Cosignature)
	sm.signedTreeHead = *nextSTH
}

func (sm *StateManagerSingle) treeStatusString() string {
	return fmt.Sprintf("signed at %d, cosigned at %d", sm.signedTreeHead.Size, sm.cosignedTreeHead.Size)
}
