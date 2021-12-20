package state

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"reflect"
	"sync"
	"time"

	"git.sigsum.org/sigsum-lib-go/pkg/types"
	"git.sigsum.org/sigsum-log-go/pkg/db"
	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/schedule"
)

// StateManagerSingle implements a single-instance StateManager.  In other
// words, there's no other state that needs to be synced on any remote machine.
type StateManagerSingle struct {
	client   db.Client
	signer   crypto.Signer
	interval time.Duration
	deadline time.Duration
	sync.RWMutex

	// cosigned is the current cosigned tree head that is being served
	cosigned types.CosignedTreeHead

	// toSign is the current tree head that is being cosigned by witnesses
	toSign types.SignedTreeHead

	// cosignatures keep track of all cosignatures for the toSign tree head
	cosignatures map[types.Hash]*types.Signature
}

func NewStateManagerSingle(client db.Client, signer crypto.Signer, interval, deadline time.Duration) (*StateManagerSingle, error) {
	sm := &StateManagerSingle{
		client:   client,
		signer:   signer,
		interval: interval,
		deadline: deadline,
	}
	ctx, cancel := context.WithTimeout(context.Background(), sm.deadline)
	defer cancel()

	sth, err := sm.Latest(ctx)
	if err != nil {
		return nil, fmt.Errorf("Latest: %v", err)
	}
	sm.toSign = *sth
	sm.cosignatures = make(map[types.Hash]*types.Signature)
	sm.cosigned = types.CosignedTreeHead{
		SignedTreeHead: *sth,
		Cosignature:    make([]types.Signature, 0),
		KeyHash:        make([]types.Hash, 0),
	}
	return sm, nil
}

func (sm *StateManagerSingle) Run(ctx context.Context) {
	schedule.Every(ctx, sm.interval, func(ctx context.Context) {
		ictx, cancel := context.WithTimeout(ctx, sm.deadline)
		defer cancel()

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

	namespace := types.HashFn(sm.signer.Public().(ed25519.PublicKey))
	return th.Sign(sm.signer, namespace)
}

func (sm *StateManagerSingle) ToSign(_ context.Context) (*types.SignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	return &sm.toSign, nil
}

func (sm *StateManagerSingle) Cosigned(_ context.Context) (*types.CosignedTreeHead, error) {
	sm.RLock()
	defer sm.RUnlock()
	if len(sm.cosigned.Cosignature) == 0 {
		return nil, fmt.Errorf("no witness cosignatures available")
	}
	return &sm.cosigned, nil
}

func (sm *StateManagerSingle) AddCosignature(_ context.Context, vk *types.PublicKey, sig *types.Signature) error {
	sm.Lock()
	defer sm.Unlock()

	namespace := types.HashFn(sm.signer.Public().(ed25519.PublicKey))
	msg := sm.toSign.TreeHead.ToBinary(namespace)
	if !ed25519.Verify(ed25519.PublicKey(vk[:]), msg, sig[:]) {
		return fmt.Errorf("invalid tree head signature")
	}

	witness := types.HashFn(vk[:])
	if _, ok := sm.cosignatures[*witness]; ok {
		return fmt.Errorf("signature-signer pair is a duplicate") // TODO: maybe not an error
	}
	sm.cosignatures[*witness] = sig

	glog.V(3).Infof("accepted new cosignature from witness: %x", *witness)
	return nil
}

// rotate rotates the log's cosigned and stable STH.  The caller must aquire the
// source's read-write lock if there are concurrent reads and/or writes.
func (sm *StateManagerSingle) rotate(next *types.SignedTreeHead) {
	if reflect.DeepEqual(sm.cosigned.SignedTreeHead, sm.toSign) {
		// cosigned and toSign are the same.  So, we need to merge all
		// cosignatures that we already had with the new collected ones.
		for i := 0; i < len(sm.cosigned.Cosignature); i++ {
			kh := sm.cosigned.KeyHash[i]
			sig := sm.cosigned.Cosignature[i]

			if _, ok := sm.cosignatures[kh]; !ok {
				sm.cosignatures[kh] = &sig
			}
		}
		glog.V(3).Infof("cosigned tree head repeated, merged signatures")
	}
	var cosignatures []types.Signature
	var keyHashes []types.Hash

	for keyHash, cosignature := range sm.cosignatures {
		cosignatures = append(cosignatures, *cosignature)
		keyHashes = append(keyHashes, keyHash)
	}

	// Update cosigned tree head
	sm.cosigned.SignedTreeHead = sm.toSign
	sm.cosigned.Cosignature = cosignatures
	sm.cosigned.KeyHash = keyHashes

	// Update to-sign tree head
	sm.toSign = *next
	sm.cosignatures = make(map[types.Hash]*types.Signature, 0) // TODO: on repeat we might want to not zero this
	glog.V(3).Infof("rotated tree heads")
}
