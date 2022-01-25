package state

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
	"time"

	"git.sigsum.org/sigsum-lib-go/pkg/types"
	db "git.sigsum.org/sigsum-log-go/pkg/db/mocks"
	"git.sigsum.org/sigsum-log-go/pkg/state/mocks"
	"github.com/golang/mock/gomock"
)

func TestNewStateManagerSingle(t *testing.T) {
	signerOk := &mocks.TestSigner{types.PublicKey{}, types.Signature{}, nil}
	signerErr := &mocks.TestSigner{types.PublicKey{}, types.Signature{}, fmt.Errorf("err")}
	for _, table := range []struct {
		description string
		signer      crypto.Signer
		rsp         types.TreeHead
		err         error
		wantErr     bool
		wantSth     types.SignedTreeHead
	}{
		{
			description: "invalid: backend failure",
			signer:      signerOk,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: signer failure",
			signer:      signerErr,
			rsp:         types.TreeHead{},
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      signerOk,
			rsp:         types.TreeHead{},
			wantSth:     types.SignedTreeHead{},
		},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := db.NewMockClient(ctrl)
			client.EXPECT().GetTreeHead(gomock.Any()).Return(&table.rsp, table.err)

			sm, err := NewStateManagerSingle(client, table.signer, time.Duration(0), time.Duration(0))
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := sm.signedTreeHead, &table.wantSth; !reflect.DeepEqual(got, want) {
				t.Errorf("got to-cosign tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
			if got := sm.cosignedTreeHead; got != nil {
				t.Errorf("got cosigned tree head but should have none in test %q", table.description)
			}
		}()
	}
}

func TestToCosignTreeHead(t *testing.T) {
	want := &types.SignedTreeHead{}
	sm := StateManagerSingle{
		signedTreeHead: want,
	}
	sth, err := sm.ToCosignTreeHead(context.Background())
	if err != nil {
		t.Errorf("should not fail with error: %v", err)
		return
	}
	if got := sth; !reflect.DeepEqual(got, want) {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}
}

func TestCosignedTreeHead(t *testing.T) {
	want := &types.CosignedTreeHead{
		Cosignature: make([]types.Signature, 1),
		KeyHash:     make([]types.Hash, 1),
	}
	sm := StateManagerSingle{
		cosignedTreeHead: want,
	}
	cth, err := sm.CosignedTreeHead(context.Background())
	if err != nil {
		t.Errorf("should not fail with error: %v", err)
		return
	}
	if got := cth; !reflect.DeepEqual(got, want) {
		t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}

	sm.cosignedTreeHead = nil
	cth, err = sm.CosignedTreeHead(context.Background())
	if err == nil {
		t.Errorf("should fail without a cosigned tree head")
		return
	}
}

func TestAddCosignature(t *testing.T) {
	secret, public := mustKeyPair(t)
	for _, table := range []struct {
		desc    string
		signer  crypto.Signer
		vk      types.PublicKey
		wantErr bool
	}{
		{
			desc:    "invalid: wrong public key",
			signer:  secret,
			vk:      types.PublicKey{},
			wantErr: true,
		},
		{
			desc:   "valid",
			signer: secret,
			vk:     public,
		},
	} {
		sm := &StateManagerSingle{
			namespace:      *types.HashFn(nil),
			signedTreeHead: &types.SignedTreeHead{},
			events:         make(chan *event, 1),
		}
		defer close(sm.events)

		sth := mustSign(t, table.signer, &sm.signedTreeHead.TreeHead, &sm.namespace)
		ctx := context.Background()
		err := sm.AddCosignature(ctx, &table.vk, &sth.Signature)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if err := sm.AddCosignature(ctx, &table.vk, &sth.Signature); err == nil {
			t.Errorf("expected full channel in test %q", table.desc)
		}
		if got, want := len(sm.events), 1; got != want {
			t.Errorf("wanted %d cosignatures but got %d in test %q", want, got, table.desc)
		}
	}
}

func TestRotate(t *testing.T) {
	sth := &types.SignedTreeHead{}
	nextSTH := &types.SignedTreeHead{TreeHead: types.TreeHead{Timestamp: 1}}
	ev := &event{
		keyHash:     &types.Hash{},
		cosignature: &types.Signature{},
	}
	wantCTH := &types.CosignedTreeHead{
		SignedTreeHead: *sth,
		KeyHash:        []types.Hash{*ev.keyHash},
		Cosignature:    []types.Signature{*ev.cosignature},
	}
	sm := &StateManagerSingle{
		signedTreeHead: sth,
		cosignatures:   make(map[types.Hash]*types.Signature),
		events:         make(chan *event, 1),
	}
	defer close(sm.events)

	sm.events <- ev
	sm.rotate(nextSTH)
	if got, want := sm.signedTreeHead, nextSTH; !reflect.DeepEqual(got, want) {
		t.Errorf("got to-cosign tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}
	if got, want := sm.cosignedTreeHead, wantCTH; !reflect.DeepEqual(got, want) {
		t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}

	sth = nextSTH
	nextSTH = &types.SignedTreeHead{TreeHead: types.TreeHead{Timestamp: 2}}
	sm.rotate(nextSTH)
	if got, want := sm.signedTreeHead, nextSTH; !reflect.DeepEqual(got, want) {
		t.Errorf("got to-cosign tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}
	if got := sm.cosignedTreeHead; got != nil {
		t.Errorf("expected no cosignatures to be available")
	}
}

func mustKeyPair(t *testing.T) (crypto.Signer, types.PublicKey) {
	t.Helper()
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pub types.PublicKey
	copy(pub[:], vk[:])
	return sk, pub
}

func mustSign(t *testing.T, s crypto.Signer, th *types.TreeHead, kh *types.Hash) *types.SignedTreeHead {
	t.Helper()
	sth, err := th.Sign(s, kh)
	if err != nil {
		t.Fatal(err)
	}
	return sth
}
