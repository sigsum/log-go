package state

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/log-go/internal/witness"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
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
	secondary client.Secondary, secondaryPub *crypto.PublicKey, sthFileName string) (*StateManagerSingle, error) {
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
		signedTreeHead: sth,
		// No cosignatures available at startup.
		cosignedTreeHead: types.CosignedTreeHead{SignedTreeHead: sth},
	}, nil
}

func (sm *StateManagerSingle) SignedTreeHead() types.SignedTreeHead {
	sm.RLock()
	defer sm.RUnlock()
	return sm.signedTreeHead
}

func (sm *StateManagerSingle) Run(ctx context.Context, witnesses []witness.WitnessConfig, interval time.Duration) {
	collector := witness.NewCosignatureCollector(&sm.keyHash, witnesses,
		sm.replicationState.primary.GetConsistencyProof)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// TODO: There should be a better way to
			// arrange this; if the rotate call blocks
			// until timeout, we might get soemwhat outof
			// sync. It would be better if at each tick,
			// we cancel any outstanding witness accesses,
			// complete the previous rotation with
			// whatever cosignatures we got, and then
			// start over with the next rotation.
			rotateCtx, cancel := context.WithTimeout(ctx, interval)
			defer cancel()
			if err := sm.rotate(rotateCtx, collector); err != nil {
				log.Warning("failed rotating tree heads: %v", err)
			}
			cancel()

		case <-ctx.Done():
			return
		}
	}
}

func (sm *StateManagerSingle) rotate(ctx context.Context, collector *witness.CosignatureCollector) error {
	nextTH, err := sm.replicationState.ReplicatedTreeHead(
		ctx, sm.signedTreeHead.Size)
	if err != nil {
		log.Error("no new replicated tree head: %v", err)
		nextTH = sm.signedTreeHead.TreeHead
	}
	nextSTH, err := nextTH.Sign(sm.signer)
	if err != nil {
		return fmt.Errorf("sign tree head: %v", err)
	}

	if err := sm.storeSth(&nextSTH); err != nil {
		return err
	}

	sm.setSignedTreeHead(&nextSTH)

	// Blocks, potentially until context times out.
	cosignatures := collector.GetCosignatures(ctx, &nextSTH)

	sm.Lock()
	defer sm.Unlock()

	log.Debug("about to rotate tree heads, next at %d: %s", nextSTH.Size, sm.treeStatusString())
	sm.signedTreeHead = nextSTH
	log.Debug("tree heads rotated: %s", sm.treeStatusString())
	return nil
}

func (sm *StateManagerSingle) treeStatusString() string {
	return fmt.Sprintf("signed at %d", sm.signedTreeHead.Size)
}
