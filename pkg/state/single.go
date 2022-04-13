package state

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"git.sigsum.org/sigsum-go/pkg/types"
	"git.sigsum.org/sigsum-log-go/pkg/db"
	"github.com/golang/glog"
)

// StateManagerSingle implements a single-instance StateManager
type StateManagerSingle struct {
	client    db.Client
	signer    crypto.Signer
	namespace types.Hash
	interval  time.Duration
	deadline  time.Duration

	// Lock-protected access to pointers.  A write lock is only obtained once
	// per interval when doing pointer rotation.  All endpoints are readers.
	sync.RWMutex
	signedTreeHead   *types.SignedTreeHead
	cosignedTreeHead *types.CosignedTreeHead

	// Syncronized and deduplicated witness cosignatures for signedTreeHead
	events       chan *event
	cosignatures map[types.Hash]*types.Signature
}

func NewStateManagerSingle(client db.Client, signer crypto.Signer, interval, deadline time.Duration) (*StateManagerSingle, error) {
	sm := &StateManagerSingle{
		client:    client,
		signer:    signer,
		namespace: *types.HashFn(signer.Public().(ed25519.PublicKey)),
		interval:  interval,
		deadline:  deadline,
	}
	sth, err := sm.latestSTH(context.Background())
	sm.setCosignedTreeHead()
	sm.setToCosignTreeHead(sth)
	return sm, err
}

func (sm *StateManagerSingle) Run(ctx context.Context) {
	rotation := func() {
		nextSTH, err := sm.latestSTH(ctx)
		if err != nil {
			glog.Warningf("cannot rotate without tree head: %v", err)
			return
		}
		sm.rotate(nextSTH)
	}
	sm.events = make(chan *event, 4096)
	defer close(sm.events)
	ticker := time.NewTicker(sm.interval)
	defer ticker.Stop()

	rotation()
	for {
		select {
		case <-ticker.C:
			rotation()
		case ev := <-sm.events:
			sm.handleEvent(ev)
		case <-ctx.Done():
			return
		}
	}
}

func (sm *StateManagerSingle) ToCosignTreeHead(_ context.Context) (*types.SignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	return sm.signedTreeHead, nil
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
	case sm.events <- &event{types.HashFn(pub[:]), sig}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("request timeout")
	}
}

func (sm *StateManagerSingle) rotate(nextSTH *types.SignedTreeHead) {
	sm.Lock()
	defer sm.Unlock()

	glog.V(3).Infof("rotating tree heads")
	sm.handleEvents()
	sm.setCosignedTreeHead()
	sm.setToCosignTreeHead(nextSTH)
}

func (sm *StateManagerSingle) handleEvents() {
	glog.V(3).Infof("handling any outstanding events")
	for i, n := 0, len(sm.events); i < n; i++ {
		sm.handleEvent(<-sm.events)
	}
}

func (sm *StateManagerSingle) handleEvent(ev *event) {
	glog.V(3).Infof("handling event from witness %x", ev.keyHash[:])
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
	cth.KeyHash = make([]types.Hash, 0, n)
	for keyHash, cosignature := range sm.cosignatures {
		cth.KeyHash = append(cth.KeyHash, keyHash)
		cth.Cosignature = append(cth.Cosignature, *cosignature)
	}
	sm.cosignedTreeHead = &cth
}

func (sm *StateManagerSingle) setToCosignTreeHead(nextSTH *types.SignedTreeHead) {
	sm.cosignatures = make(map[types.Hash]*types.Signature)
	sm.signedTreeHead = nextSTH
}

func (sm *StateManagerSingle) latestSTH(ctx context.Context) (*types.SignedTreeHead, error) {
	ictx, cancel := context.WithTimeout(ctx, sm.deadline)
	defer cancel()

	th, err := sm.client.GetTreeHead(ictx)
	if err != nil {
		return nil, fmt.Errorf("failed fetching tree head: %v", err)
	}
	sth, err := th.Sign(sm.signer, &sm.namespace)
	if err != nil {
		return nil, fmt.Errorf("failed signing tree head: %v", err)
	}
	return sth, nil
}
