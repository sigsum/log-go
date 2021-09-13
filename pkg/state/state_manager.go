package state

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/schedule"
	"golang.sigsum.org/sigsum-log-go/pkg/trillian"
	"golang.sigsum.org/sigsum-log-go/pkg/types"
)

// StateManager coordinates access to the log's tree heads and (co)signatures
type StateManager interface {
	Latest(context.Context) (*types.SignedTreeHead, error)
	ToSign(context.Context) (*types.SignedTreeHead, error)
	Cosigned(context.Context) (*types.CosignedTreeHead, error)
	AddCosignature(context.Context, *[types.VerificationKeySize]byte, *[types.SignatureSize]byte) error
	Run(context.Context)
}

// StateManagerSingle implements the StateManager interface.  It is assumed that
// the log server is running on a single-instance machine.  So, no coordination.
type StateManagerSingle struct {
	client   trillian.Client
	signer   crypto.Signer
	interval time.Duration
	deadline time.Duration
	sync.RWMutex

	// cosigned is the current cosigned tree head that is being served
	cosigned types.CosignedTreeHead

	// tosign is the current tree head that is being cosigned by witnesses
	tosign types.SignedTreeHead

	// cosignature keeps track of all cosignatures for the tosign tree head
	cosignature map[[types.HashSize]byte]*types.SigIdent
}

func NewStateManagerSingle(client trillian.Client, signer crypto.Signer, interval, deadline time.Duration) (*StateManagerSingle, error) {
	sm := &StateManagerSingle{
		client:   client,
		signer:   signer,
		interval: interval,
		deadline: deadline,
	}

	ctx, _ := context.WithTimeout(context.Background(), sm.deadline)
	sth, err := sm.Latest(ctx)
	if err != nil {
		return nil, fmt.Errorf("Latest: %v", err)
	}

	sm.cosigned = types.CosignedTreeHead{
		SignedTreeHead: *sth,
		SigIdent:       []*types.SigIdent{},
	}
	sm.tosign = *sth
	sm.cosignature = map[[types.HashSize]byte]*types.SigIdent{}
	return sm, nil
}

func (sm *StateManagerSingle) Run(ctx context.Context) {
	schedule.Every(ctx, sm.interval, func(ctx context.Context) {
		ictx, _ := context.WithTimeout(ctx, sm.deadline)
		nextSTH, err := sm.Latest(ictx)
		if err != nil {
			glog.Warningf("rotate failed: Latest: %v", err)
			return
		}

		sm.Lock()
		defer sm.Unlock()
		sm.rotate(nextSTH)
	})
}

func (sm *StateManagerSingle) Latest(ctx context.Context) (*types.SignedTreeHead, error) {
	th, err := sm.client.GetTreeHead(ctx)
	if err != nil {
		return nil, fmt.Errorf("LatestTreeHead: %v", err)
	}
	th.KeyHash = types.Hash(sm.signer.Public().(ed25519.PublicKey)[:])
	sth, err := th.Sign(sm.signer)
	if err != nil {
		return nil, fmt.Errorf("sign: %v", err)
	}
	return sth, nil
}

func (sm *StateManagerSingle) ToSign(_ context.Context) (*types.SignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	return &sm.tosign, nil
}

func (sm *StateManagerSingle) Cosigned(_ context.Context) (*types.CosignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	if len(sm.cosigned.SigIdent) == 0 {
		return nil, fmt.Errorf("no witness cosignatures available")
	}
	return &sm.cosigned, nil
}

func (sm *StateManagerSingle) AddCosignature(_ context.Context, vk *[types.VerificationKeySize]byte, sig *[types.SignatureSize]byte) error {
	sm.Lock()
	defer sm.Unlock()

	if err := sm.tosign.TreeHead.Verify(vk, sig); err != nil {
		return fmt.Errorf("Verify: %v", err)
	}
	witness := types.Hash(vk[:])
	if _, ok := sm.cosignature[*witness]; ok {
		return fmt.Errorf("signature-signer pair is a duplicate")
	}
	sm.cosignature[*witness] = &types.SigIdent{
		Signature: sig,
		KeyHash:   witness,
	}

	glog.V(3).Infof("accepted new cosignature from witness: %x", *witness)
	return nil
}

// rotate rotates the log's cosigned and stable STH.  The caller must aquire the
// source's read-write lock if there are concurrent reads and/or writes.
func (sm *StateManagerSingle) rotate(next *types.SignedTreeHead) {
	if reflect.DeepEqual(sm.cosigned.SignedTreeHead, sm.tosign) {
		// cosigned and tosign are the same.  So, we need to merge all
		// cosignatures that we already had with the new collected ones.
		for _, sigident := range sm.cosigned.SigIdent {
			if _, ok := sm.cosignature[*sigident.KeyHash]; !ok {
				sm.cosignature[*sigident.KeyHash] = sigident
			}
		}
		glog.V(3).Infof("cosigned tree head repeated, merged signatures")
	}
	var cosignatures []*types.SigIdent
	for _, sigident := range sm.cosignature {
		cosignatures = append(cosignatures, sigident)
	}

	// Update cosigned tree head
	sm.cosigned.SignedTreeHead = sm.tosign
	sm.cosigned.SigIdent = cosignatures

	// Update to-sign tree head
	sm.tosign = *next
	sm.cosignature = map[[types.HashSize]byte]*types.SigIdent{} // TODO: on repeat we might want to not zero this
	glog.V(3).Infof("rotated tree heads")
}
