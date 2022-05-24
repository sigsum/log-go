package state

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"git.sigsum.org/log-go/pkg/client"
	"git.sigsum.org/log-go/pkg/db"
	"git.sigsum.org/sigsum-go/pkg/log"
	//"git.sigsum.org/sigsum-go/pkg/requests"
	"git.sigsum.org/sigsum-go/pkg/types"
)

// StateManagerSingleSecondary implements a single-instance StateManager for secondary nodes
type StateManagerSingleSecondary struct {
	client    db.Client
	signer    crypto.Signer
	namespace types.Hash
	interval  time.Duration
	deadline  time.Duration
	primary   *client.Client

	// Lock-protected access to pointers.  A write lock is only obtained once
	// per interval when doing pointer rotation.  All endpoints are readers.
	sync.RWMutex
	signedTreeHead *types.SignedTreeHead
}

func NewStateManagerSingleSecondary(dbcli db.Client, signer crypto.Signer, interval, deadline time.Duration, primurl string, primpk types.PublicKey) (*StateManagerSingleSecondary, error) {
	sm := &StateManagerSingleSecondary{
		client:    dbcli,
		signer:    signer,
		namespace: *types.HashFn(signer.Public().(ed25519.PublicKey)),
		interval:  interval,
		deadline:  deadline,
		primary:   client.NewClient(primurl, primpk),
	}
	sth, err := sm.latestSTH(context.Background())
	sm.setSignedTreeHead(sth)
	return sm, err
}

func (sm *StateManagerSingleSecondary) Run(ctx context.Context) {
	rotation := func() {
		nextSTH, err := sm.latestSTH(ctx)
		if err != nil {
			log.Warning("cannot rotate without tree head: %v", err)
			return
		}
		sm.rotate(nextSTH)
	}

	ticker := time.NewTicker(sm.interval)
	defer ticker.Stop()

	// TODO: fetch leaves from primary

	rotation()
	for {
		select {
		case <-ticker.C:
			rotation()
		case <-ctx.Done():
			return
		}
	}
}

func (sm *StateManagerSingleSecondary) AddCosignature(ctx context.Context, pub *types.PublicKey, sig *types.Signature) error {
	return fmt.Errorf("internal error: AddCosignature() called in secondary node")
}
func (sm *StateManagerSingleSecondary) CosignedTreeHead(_ context.Context) (*types.CosignedTreeHead, error) {
	return nil, fmt.Errorf("internal error: AddCosignature() called in secondary node")
}
func (sm *StateManagerSingleSecondary) ToCosignTreeHead(_ context.Context) (*types.SignedTreeHead, error) {
	return nil, fmt.Errorf("internal error: AddCosignature() called in secondary node")
}

func (sm *StateManagerSingleSecondary) setSignedTreeHead(nextSTH *types.SignedTreeHead) {
	sm.signedTreeHead = nextSTH
}

func (sm *StateManagerSingleSecondary) latestSTH(ctx context.Context) (*types.SignedTreeHead, error) {
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

func (sm *StateManagerSingleSecondary) rotate(nextSTH *types.SignedTreeHead) {
	sm.Lock()
	defer sm.Unlock()

	log.Debug("rotating tree heads")
	sm.setSignedTreeHead(nextSTH)
}
