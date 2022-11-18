package state

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// StateManagerSingle implements a single-instance StateManagerPrimary for primary nodes
type StateManagerSingle struct {
	client   db.Client
	signer   crypto.Signer
	keyHash  crypto.Hash
	interval time.Duration
	// Timeout for interaction with the secondary.
	timeout     time.Duration
	secondaries []client.Client
	sthFile     *os.File

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
// signedTreeHead.  Optional secondary nodes can be used to ensure that
// a newer primary tree is not signed unless it has been replicated.
func NewStateManagerSingle(dbcli db.Client, signer crypto.Signer, interval, timeout time.Duration,
	secondaries []client.Client, sthFile *os.File, witnesses map[crypto.Hash]crypto.PublicKey) (*StateManagerSingle, error) {
	pub := signer.Public()
	sm := &StateManagerSingle{
		client:      dbcli,
		signer:      signer,
		keyHash:     crypto.HashBytes(pub[:]),
		interval:    interval,
		timeout:     timeout,
		secondaries: secondaries,
		sthFile:     sthFile,
		witnesses:   witnesses,
	}
	var err error
	if sm.signedTreeHead, err = sm.restoreSTH(); err != nil {
		return nil, err
	}
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

func (sm *StateManagerSingle) ToCosignTreeHead() *types.SignedTreeHead {
	sm.RLock()
	defer sm.RUnlock()
	return sm.signedTreeHead
}

func (sm *StateManagerSingle) CosignedTreeHead() (*types.CosignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	if sm.cosignedTreeHead == nil {
		return nil, fmt.Errorf("no cosignatures available")
	}
	return sm.cosignedTreeHead, nil
}

func (sm *StateManagerSingle) AddCosignature(keyHash *crypto.Hash, sig *crypto.Signature) error {
	// This mapping is immutable, no lock needed.
	pub, ok := sm.witnesses[*keyHash]
	if !ok {
		return fmt.Errorf("unknown witness: %x", keyHash)
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
	log.Debug("wanted to advance to size %d, chose size %d", th.TreeSize, nextSTH.TreeSize)

	if err := sm.storeSTH(nextSTH); err != nil {
		return err
	}

	sm.rotate(nextSTH)
	return nil
}

// chooseTree picks a tree to publish, taking the state of any secondary nodes into account.
func (sm *StateManagerSingle) chooseTree(ctx context.Context, proposedTreeHead *types.TreeHead) *types.TreeHead {
	// Tree head replicated by all consulted secondaries, updated
	// throughout the loop. Unless we return early, due to some
	// problem with a secondary, by end of the loop,
	// replicatedTreeHead.TreeSize will be the minimum of the tree
	// sizes of the heads of all secondaries.
	replicatedTreeHead := proposedTreeHead
	for secIndex, secondary := range sm.secondaries {
		secSTH, err := secondary.GetToCosignTreeHead(ctx)
		if err != nil {
			log.Warning("failed fetching tree head from %dth secondary: %v", secIndex, err)
			return &sm.signedTreeHead.TreeHead
		}
		if secSTH.TreeSize > proposedTreeHead.TreeSize {
			log.Error("secondary %d is ahead of us: %d > %d", secIndex, secSTH.TreeSize, proposedTreeHead.TreeSize)
			return &sm.signedTreeHead.TreeHead
		}
		if secSTH.TreeHead.TreeSize <= sm.signedTreeHead.TreeSize {
			log.Debug("secondary %d is behind us: %d <= %d", secSTH.TreeHead.TreeSize, sm.signedTreeHead.TreeSize)
			return &sm.signedTreeHead.TreeHead
		}
		if secSTH.TreeSize == replicatedTreeHead.TreeSize {
			if secSTH.RootHash != proposedTreeHead.RootHash {
				log.Error("secondary root hash doesn't match our root hash at tree size %d", secSTH.TreeSize)
				return &sm.signedTreeHead.TreeHead
			}
		} else {
			// We now know that
			// * the secondary is ahead of our published tree
			// * the proposed tree is ahead of the secondary
			// * the secondary may be ahead or behind the secondaries already processed.
			if secSTH.TreeSize < replicatedTreeHead.TreeSize {
				// Behind previous secondaries.
				if err := sm.verifyConsistency(ctx, &secSTH.TreeHead, replicatedTreeHead); err != nil {
					log.Error("secondary %d tree not consistent with ours: %v", secIndex, err)
					return &sm.signedTreeHead.TreeHead
				}
				replicatedTreeHead = &secSTH.TreeHead
			} else {
				// Ahead of previous secondaries.
				if err := sm.verifyConsistency(ctx, replicatedTreeHead, &secSTH.TreeHead); err != nil {
					log.Error("secondary %d tree not consistent with ours: %v", secIndex, err)
					return &sm.signedTreeHead.TreeHead
				}
			}
		}
	}
	log.Debug("using latest replicated tree head from secondaries: size %d", replicatedTreeHead.TreeSize)
	return replicatedTreeHead
}

func (sm *StateManagerSingle) verifyConsistency(ctx context.Context, from, to *types.TreeHead) error {
	req := &requests.ConsistencyProof{
		OldSize: from.TreeSize,
		NewSize: to.TreeSize,
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

	log.Debug("about to rotate tree heads, next at %d: %s", nextSTH.TreeSize, sm.treeStatusString())
	sm.setCosignedTreeHead()
	sm.setToCosignTreeHead(nextSTH)
	log.Debug("tree heads rotated: %s", sm.treeStatusString())
}

func (sm *StateManagerSingle) setCosignedTreeHead() {
	n := len(sm.cosignatures)
	if n == 0 {
		sm.cosignedTreeHead = nil
		return
	}

	var cth types.CosignedTreeHead
	cth.SignedTreeHead = *sm.signedTreeHead
	cth.Cosignatures = make([]types.Cosignature, 0, n)
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
		cosigned = sm.cosignedTreeHead.TreeSize
	}
	return fmt.Sprintf("signed at %d, cosigned at %d", sm.signedTreeHead.TreeSize, cosigned)
}

func (sm *StateManagerSingle) restoreSTH() (*types.SignedTreeHead, error) {
	var th types.TreeHead
	b := make([]byte, 1024)
	n, err := sm.sthFile.Read(b)
	if err != nil {
		th = *zeroTreeHead()
	} else if err := th.FromASCII(bytes.NewBuffer(b[:n])); err != nil {
		th = *zeroTreeHead()
	}
	return sm.signTreeHead(&th)
}

func (sm *StateManagerSingle) storeSTH(sth *types.SignedTreeHead) error {
	buf := bytes.NewBuffer(nil)
	if err := sth.ToASCII(buf); err != nil {
		return err
	}
	if err := sm.sthFile.Truncate(int64(buf.Len())); err != nil {
		return err
	}
	if _, err := sm.sthFile.WriteAt(buf.Bytes(), 0); err != nil {
		return err
	}
	if err := sm.sthFile.Sync(); err != nil {
		return err
	}
	return nil
}

func zeroTreeHead() *types.TreeHead {
	return &types.TreeHead{RootHash: crypto.HashBytes([]byte(""))}
}

// Signs tree head, with current time as timestamp.
func (sm *StateManagerSingle) signTreeHead(th *types.TreeHead) (*types.SignedTreeHead, error) {
	return th.Sign(sm.signer, &sm.keyHash, uint64(time.Now().Unix()))
}
