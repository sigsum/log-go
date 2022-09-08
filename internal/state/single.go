package state

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"os"
	"sync"
	"time"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// StateManagerSingle implements a single-instance StateManagerPrimary for primary nodes
type StateManagerSingle struct {
	client    db.Client
	signer    crypto.Signer
	namespace merkle.Hash
	interval  time.Duration
	deadline  time.Duration
	secondary client.Client
	sthFile   *os.File

	// Lock-protected access to pointers.  A write lock is only obtained once
	// per interval when doing pointer rotation.  All endpoints are readers.
	sync.RWMutex
	signedTreeHead   *types.SignedTreeHead
	cosignedTreeHead *types.CosignedTreeHead

	// Syncronized and deduplicated witness cosignatures for signedTreeHead
	events       chan *event
	cosignatures map[merkle.Hash]*types.Signature
}

// NewStateManagerSingle() sets up a new state manager, in particular its
// signedTreeHead.  An optional secondary node can be used to ensure that
// a newer primary tree is not signed unless it has been replicated.
func NewStateManagerSingle(dbcli db.Client, signer crypto.Signer, interval, deadline time.Duration, secondary client.Client, sthFile *os.File) (*StateManagerSingle, error) {
	sm := &StateManagerSingle{
		client:    dbcli,
		signer:    signer,
		namespace: *merkle.HashFn(signer.Public().(ed25519.PublicKey)),
		interval:  interval,
		deadline:  deadline,
		secondary: secondary,
		sthFile:   sthFile,
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

func (sm *StateManagerSingle) CosignedTreeHead(_ context.Context) (*types.CosignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	if sm.cosignedTreeHead == nil {
		return nil, fmt.Errorf("no cosignatures available")
	}
	return sm.cosignedTreeHead, nil
}

func (sm *StateManagerSingle) AddCosignature(ctx context.Context, pub *types.PublicKey, sig *types.Signature) error {
	sm.RLock()
	defer sm.RUnlock()

	msg := sm.signedTreeHead.TreeHead.ToBinary(&sm.namespace)
	if !ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig[:]) {
		return fmt.Errorf("invalid cosignature")
	}
	select {
	case sm.events <- &event{merkle.HashFn(pub[:]), sig}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("request timeout")
	}
}

func (sm *StateManagerSingle) Run(ctx context.Context) {
	sm.events = make(chan *event, 4096)
	defer close(sm.events)
	ticker := time.NewTicker(sm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ictx, cancel := context.WithTimeout(ctx, sm.deadline)
			defer cancel()
			if err := sm.tryRotate(ictx); err != nil {
				log.Warning("failed rotating tree heads: %v", err)
			}
		case ev := <-sm.events:
			sm.handleEvent(ev)
		case <-ctx.Done():
			return
		}
	}
}

func (sm *StateManagerSingle) tryRotate(ctx context.Context) error {
	th, err := sm.client.GetTreeHead(ctx)
	if err != nil {
		return fmt.Errorf("get tree head: %v", err)
	}
	nextSTH, err := sm.chooseTree(ctx, th).Sign(sm.signer, &sm.namespace)
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

// chooseTree picks a tree to publish, taking the state of a possible secondary node into account.
func (sm *StateManagerSingle) chooseTree(ctx context.Context, proposedTreeHead *types.TreeHead) *types.TreeHead {
	if !sm.secondary.Initiated() {
		return proposedTreeHead
	}

	secSTH, err := sm.secondary.GetToCosignTreeHead(ctx)
	if err != nil {
		log.Warning("failed fetching tree head from secondary: %v", err)
		return refreshTreeHead(sm.signedTreeHead.TreeHead)
	}
	if secSTH.TreeSize > proposedTreeHead.TreeSize {
		log.Error("secondary is ahead of us: %d > %d", secSTH.TreeSize, proposedTreeHead.TreeSize)
		return refreshTreeHead(sm.signedTreeHead.TreeHead)
	}
	if secSTH.TreeSize == proposedTreeHead.TreeSize {
		if secSTH.RootHash != proposedTreeHead.RootHash {
			log.Error("secondary root hash doesn't match our root hash at tree size %d", secSTH.TreeSize)
			return refreshTreeHead(sm.signedTreeHead.TreeHead)
		}
		log.Debug("secondary is up-to-date with matching tree head, using proposed tree, size %d", proposedTreeHead.TreeSize)
		return proposedTreeHead
	}
	// We now know that
	// * the proposed tree is ahead of the secondary (including them not being equal)
	// * the minimal tree size is 0, so the proposed tree is at tree size 1 or greater

	// Consistency proofs can not be produced from a tree of size 0, so don't try when the secondary is at 0.
	if secSTH.TreeSize == 0 {
		log.Debug("secondary tree size is zero, using latest published tree head: size %d", sm.signedTreeHead.TreeSize)
		return refreshTreeHead(sm.signedTreeHead.TreeHead)
	}
	if err := sm.verifyConsistency(ctx, &secSTH.TreeHead, proposedTreeHead); err != nil {
		log.Error("secondary tree not consistent with ours: %v", err)
		return refreshTreeHead(sm.signedTreeHead.TreeHead)
	}
	// We now know that
	// * we have two candidates: latest published and secondary's tree
	// * secondary's tree is verified to be consistent with our proposed tree

	// Protect against going backwards by chosing the larger of secondary tree and latest published.
	if sm.signedTreeHead.TreeSize > secSTH.TreeHead.TreeSize {
		log.Debug("using latest published tree head: size %d", sm.signedTreeHead.TreeSize)
		return refreshTreeHead(sm.signedTreeHead.TreeHead)
	}

	log.Debug("using latest tree head from secondary: size %d", secSTH.TreeSize)
	return refreshTreeHead(secSTH.TreeHead)
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
	sm.handleEvents()
	sm.setCosignedTreeHead()
	sm.setToCosignTreeHead(nextSTH)
	log.Debug("tree heads rotated: %s", sm.treeStatusString())
}

func (sm *StateManagerSingle) handleEvents() {
	log.Debug("handling any outstanding events")
	for i, n := 0, len(sm.events); i < n; i++ {
		sm.handleEvent(<-sm.events)
	}
}

func (sm *StateManagerSingle) handleEvent(ev *event) {
	log.Debug("handling event from witness %x", ev.keyHash[:])
	sm.cosignatures[*ev.keyHash] = ev.cosignature
}

func (sm *StateManagerSingle) setCosignedTreeHead() {
	n := len(sm.cosignatures)
	if n == 0 {
		sm.cosignedTreeHead = nil
		return
	}

	var cth types.CosignedTreeHead
	cth.SignedTreeHead = *sm.signedTreeHead
	cth.Cosignature = make([]types.Signature, 0, n)
	cth.KeyHash = make([]merkle.Hash, 0, n)
	for keyHash, cosignature := range sm.cosignatures {
		cth.KeyHash = append(cth.KeyHash, keyHash)
		cth.Cosignature = append(cth.Cosignature, *cosignature)
	}
	sm.cosignedTreeHead = &cth
}

func (sm *StateManagerSingle) setToCosignTreeHead(nextSTH *types.SignedTreeHead) {
	sm.cosignatures = make(map[merkle.Hash]*types.Signature)
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
	th = *refreshTreeHead(th)
	return th.Sign(sm.signer, &sm.namespace)
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
	return refreshTreeHead(types.TreeHead{RootHash: *merkle.HashFn([]byte(""))})
}

func refreshTreeHead(th types.TreeHead) *types.TreeHead {
	th.Timestamp = uint64(time.Now().Unix())
	return &th
}
