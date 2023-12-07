package state

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sigsum.org/log-go/internal/witness"
	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/types"
)

// StateManagerSingle implements a single-instance StateManagerPrimary for primary nodes
type StateManagerSingle struct {
	signer           crypto.Signer
	keyHash          crypto.Hash
	storeSth         func(sth *types.SignedTreeHead) error
	replicationState ReplicationState

	// Lock-protected access to tree heads. All endpoints are readers.
	sync.RWMutex
	signedTreeHead   types.SignedTreeHead
	cosignedTreeHead types.CosignedTreeHead
}

// NewStateManagerSingle() sets up a new state manager, in particular its
// signedTreeHead.  An optional secondary node can be used to ensure that
// a newer primary tree is not signed unless it has been replicated.
func NewStateManagerSingle(primary PrimaryTree, signer crypto.Signer, timeout time.Duration,
	secondary api.Secondary, secondaryPub *crypto.PublicKey, sthFileName string) (*StateManagerSingle, error) {
	pub := signer.Public()
	sthFile := sthFile{name: sthFileName}
	startupMode, err := sthFile.Startup()
	if err != nil {
		return nil, err
	}

	var sth types.SignedTreeHead
	switch startupMode {
	case StartupSaved:
		sth, err = sthFile.Load(&pub)
		if err != nil {
			return nil, err
		}
	case StartupEmpty:
		th := types.TreeHead{RootHash: crypto.HashBytes([]byte(""))}
		sth, err = th.Sign(signer)
		if err != nil {
			return nil, err
		}
		if err := sthFile.Create(&sth); err != nil {
			return nil, err
		}
	case StartupLocalTree:
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
			primary:      primary,
			secondary:    secondary,
			secondaryPub: *secondaryPub,
			timeout:      timeout,
		},
		// No cosignatures available at startup.
		signedTreeHead:   sth,
		cosignedTreeHead: types.CosignedTreeHead{SignedTreeHead: sth},
	}, nil
}

func (sm *StateManagerSingle) SignedTreeHead() types.SignedTreeHead {
	sm.RLock()
	defer sm.RUnlock()
	return sm.signedTreeHead
}

func (sm *StateManagerSingle) CosignedTreeHead() types.CosignedTreeHead {
	sm.RLock()
	defer sm.RUnlock()
	return sm.cosignedTreeHead
}

func (sm *StateManagerSingle) Run(ctx context.Context, witnesses []policy.Entity, interval time.Duration) {
	collector := witness.NewCosignatureCollector(&sm.keyHash, witnesses,
		sm.replicationState.primary.GetConsistencyProof)

	for ctx.Err() == nil {
		rotateCtx, _ := context.WithTimeout(ctx, interval)

		currentTH := sm.SignedTreeHead().TreeHead
		nextTH, err := sm.replicationState.ReplicatedTreeHead(
			rotateCtx, currentTH.Size)
		if err != nil {
			log.Error("no new replicated tree head: %v", err)
			nextTH = currentTH
		}

		if err := sm.rotate(rotateCtx, &nextTH, collector.GetCosignatures); err != nil {
			log.Warning("failed rotating tree head: %v", err)
		}
		// Waits until end of interval
		<-rotateCtx.Done()
	}
}

func (sm *StateManagerSingle) rotate(ctx context.Context, nextTH *types.TreeHead,
	getCosignatures func(context.Context, *types.SignedTreeHead) []types.Cosignature) error {
	nextSTH, err := sm.signTreeHead(nextTH)
	if err != nil {
		return err
	}

	// Blocks (with no locks held), potentially until context times out.
	cosignatures := getCosignatures(ctx, &nextSTH)

	sm.Lock()
	defer sm.Unlock()

	log.Debug("rotating cosigned tree head: previous size %d, new size %d", sm.cosignedTreeHead.Size, nextSTH.Size)
	sm.cosignedTreeHead = types.CosignedTreeHead{
		SignedTreeHead: nextSTH,
		Cosignatures:   cosignatures,
	}
	return nil
}

func (sm *StateManagerSingle) signTreeHead(nextTH *types.TreeHead) (types.SignedTreeHead, error) {
	nextSTH, err := nextTH.Sign(sm.signer)
	if err != nil {
		return types.SignedTreeHead{}, fmt.Errorf("sign tree head: %v", err)
	}

	if err := sm.storeSth(&nextSTH); err != nil {
		return types.SignedTreeHead{}, err
	}

	sm.Lock()
	defer sm.Unlock()
	log.Debug("rotating signed tree head: previous size %d, new size %d", sm.signedTreeHead.Size, nextSTH.Size)
	if nextSTH.Size < sm.signedTreeHead.Size {
		return types.SignedTreeHead{}, fmt.Errorf("internal error, attempting to truncate signed tree head")
	}
	sm.signedTreeHead = nextSTH
	return nextSTH, nil
}
