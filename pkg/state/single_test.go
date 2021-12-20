package state

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
	"time"

	"git.sigsum.org/sigsum-lib-go/pkg/types"
	mocksTrillian "git.sigsum.org/sigsum-log-go/pkg/db/mocks"
	mocksSigner "git.sigsum.org/sigsum-log-go/pkg/state/mocks"
	"github.com/golang/mock/gomock"
)

var (
	testTH = types.TreeHead{
		Timestamp: 0,
		TreeSize:  0,
		RootHash:  types.Hash{},
	}
	testSTH = types.SignedTreeHead{
		TreeHead:  testTH,
		Signature: types.Signature{},
	}
	testCTH = types.CosignedTreeHead{
		SignedTreeHead: testSTH,
		Cosignature: []types.Signature{
			types.Signature{},
		},
		KeyHash: []types.Hash{
			types.Hash{},
		},
	}

	testSignerOK  = &mocksSigner.TestSigner{types.PublicKey{}, types.Signature{}, nil}
	testSignerErr = &mocksSigner.TestSigner{types.PublicKey{}, types.Signature{}, fmt.Errorf("something went wrong")}
)

func TestNewStateManagerSingle(t *testing.T) {
	for _, table := range []struct {
		description string
		signer      crypto.Signer
		rsp         *types.TreeHead
		err         error
		wantErr     bool
		wantSth     *types.SignedTreeHead
	}{
		{
			description: "invalid: backend failure",
			signer:      testSignerOK,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      testSignerOK,
			rsp:         &testTH,
			wantSth:     &testSTH,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksTrillian.NewMockClient(ctrl)
			client.EXPECT().GetTreeHead(gomock.Any()).Return(table.rsp, table.err)

			sm, err := NewStateManagerSingle(client, table.signer, time.Duration(0), time.Duration(0))
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := &sm.cosigned.SignedTreeHead, table.wantSth; !reflect.DeepEqual(got, want) {
				t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
			if got, want := &sm.toSign, table.wantSth; !reflect.DeepEqual(got, want) {
				t.Errorf("got toSign tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
			// we only have log signature on startup
			if got, want := len(sm.cosignatures), 0; got != want {
				t.Errorf("got %d cosignatures but wanted %d in test %q", got, want, table.description)
			}
		}()
	}
}

func TestLatest(t *testing.T) {
	for _, table := range []struct {
		description string
		signer      crypto.Signer
		rsp         *types.TreeHead
		err         error
		wantErr     bool
		wantSth     *types.SignedTreeHead
	}{
		{
			description: "invalid: backend failure",
			signer:      testSignerOK,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: signature failure",
			rsp:         &testTH,
			signer:      testSignerErr,
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      testSignerOK,
			rsp:         &testTH,
			wantSth:     &testSTH,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocksTrillian.NewMockClient(ctrl)
			client.EXPECT().GetTreeHead(gomock.Any()).Return(table.rsp, table.err)
			sm := StateManagerSingle{
				client: client,
				signer: table.signer,
			}

			sth, err := sm.Latest(context.Background())
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := sth, table.wantSth; !reflect.DeepEqual(got, want) {
				t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
		}()
	}
}

func TestToSign(t *testing.T) {
	description := "valid"
	sm := StateManagerSingle{
		toSign: testSTH,
	}
	sth, err := sm.ToSign(context.Background())
	if err != nil {
		t.Errorf("ToSign should not fail with error: %v", err)
		return
	}
	if got, want := sth, &testSTH; !reflect.DeepEqual(got, want) {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, description)
	}
}

func TestCosigned(t *testing.T) {
	description := "valid"
	sm := StateManagerSingle{
		cosigned: testCTH,
	}
	cth, err := sm.Cosigned(context.Background())
	if err != nil {
		t.Errorf("Cosigned should not fail with error: %v", err)
		return
	}
	if got, want := cth, &testCTH; !reflect.DeepEqual(got, want) {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, description)
	}

	sm.cosigned.Cosignature = make([]types.Signature, 0)
	sm.cosigned.KeyHash = make([]types.Hash, 0)
	cth, err = sm.Cosigned(context.Background())
	if err == nil {
		t.Errorf("Cosigned should fail without witness cosignatures")
		return
	}
}

func TestAddCosignature(t *testing.T) {
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if bytes.Equal(vk[:], new(types.PublicKey)[:]) {
		t.Fatalf("Sampled same key as testPub, aborting...")
	}
	var vkArray types.PublicKey
	copy(vkArray[:], vk[:])

	for _, table := range []struct {
		description string
		signer      crypto.Signer
		vk          types.PublicKey
		th          types.TreeHead
		wantErr     bool
	}{
		{
			description: "invalid: signature error",
			signer:      sk,
			vk:          types.PublicKey{}, // wrong key for message
			th:          testTH,
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      sk,
			vk:          vkArray,
			th:          testTH,
		},
	} {
		kh := types.HashFn(testSignerOK.Public().(ed25519.PublicKey))
		sth := mustSign(t, testSignerOK, &table.th, kh)
		cth := &types.CosignedTreeHead{
			SignedTreeHead: *sth,
			Cosignature:    make([]types.Signature, 0),
			KeyHash:        make([]types.Hash, 0),
		}
		sm := &StateManagerSingle{
			signer:       testSignerOK,
			cosigned:     *cth,
			toSign:       *sth,
			cosignatures: make(map[types.Hash]*types.Signature, 0),
		}

		// Prepare witness signature
		var vk types.PublicKey
		copy(vk[:], table.vk[:]) //table.signer.Public().(ed25519.PublicKey))
		sth = mustSign(t, table.signer, &table.th, kh)
		kh = types.HashFn(vk[:])

		// Add witness signature
		err = sm.AddCosignature(context.Background(), &vk, &sth.Signature)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		// We should have one witness signature
		if got, want := len(sm.cosignatures), 1; got != want {
			t.Errorf("got %d cosignatures but wanted %v in test %q", got, want, table.description)
			continue
		}
		// check that witness signature is there
		sig, ok := sm.cosignatures[*kh]
		if !ok {
			t.Errorf("witness signature is missing")
			continue
		}
		if got, want := sig[:], sth.Signature[:]; !bytes.Equal(got, want) {
			t.Errorf("got witness sigident\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			continue
		}

		// Adding a duplicate signature should give an error
		if err := sm.AddCosignature(context.Background(), &vk, &sth.Signature); err == nil {
			t.Errorf("duplicate witness signature accepted as valid")
		}
	}
}

func TestRotate(t *testing.T) {
	logSig := types.Signature{}
	wit1Sig := types.Signature{}
	wit2Sig := types.Signature{}

	//logKH := &types.Hash{}
	wit1KH := types.HashFn([]byte("wit1 key"))
	wit2KH := types.HashFn([]byte("wit2 key"))

	th0 := &testTH
	th1 := &types.TreeHead{
		Timestamp: 1,
		TreeSize:  1,
		RootHash:  *types.HashFn([]byte("1")),
	}
	th2 := &types.TreeHead{
		Timestamp: 2,
		TreeSize:  2,
		RootHash:  *types.HashFn([]byte("2")),
	}

	for _, table := range []struct {
		description   string
		before, after *StateManagerSingle
		next          *types.SignedTreeHead
	}{
		{
			description: "toSign tree head repated, but got one new witnes signature",
			before: &StateManagerSingle{
				cosigned: types.CosignedTreeHead{
					SignedTreeHead: types.SignedTreeHead{
						TreeHead:  *th0,
						Signature: logSig,
					},
					Cosignature: []types.Signature{wit1Sig},
					KeyHash:     []types.Hash{*wit1KH},
				},
				toSign: types.SignedTreeHead{
					TreeHead:  *th0,
					Signature: logSig,
				},
				cosignatures: map[types.Hash]*types.Signature{
					*wit2KH: &wit2Sig, // the new witness signature
				},
			},
			next: &types.SignedTreeHead{
				TreeHead:  *th1,
				Signature: logSig,
			},
			after: &StateManagerSingle{
				cosigned: types.CosignedTreeHead{
					SignedTreeHead: types.SignedTreeHead{
						TreeHead:  *th0,
						Signature: logSig,
					},
					Cosignature: []types.Signature{wit1Sig, wit2Sig},
					KeyHash:     []types.Hash{*wit1KH, *wit2KH},
				},
				toSign: types.SignedTreeHead{
					TreeHead:  *th1,
					Signature: logSig,
				},
				cosignatures: map[types.Hash]*types.Signature{},
			},
		},
		{
			description: "toSign tree head did not repeat, it got one witness signature",
			before: &StateManagerSingle{
				cosigned: types.CosignedTreeHead{
					SignedTreeHead: types.SignedTreeHead{
						TreeHead:  *th0,
						Signature: logSig,
					},
					Cosignature: []types.Signature{wit1Sig},
					KeyHash:     []types.Hash{*wit1KH},
				},
				toSign: types.SignedTreeHead{
					TreeHead:  *th1,
					Signature: logSig,
				},
				cosignatures: map[types.Hash]*types.Signature{
					*wit2KH: &wit2Sig,
				},
			},
			next: &types.SignedTreeHead{
				TreeHead:  *th2,
				Signature: logSig,
			},
			after: &StateManagerSingle{
				cosigned: types.CosignedTreeHead{
					SignedTreeHead: types.SignedTreeHead{
						TreeHead:  *th1,
						Signature: logSig,
					},
					Cosignature: []types.Signature{wit2Sig},
					KeyHash:     []types.Hash{*wit2KH},
				},
				toSign: types.SignedTreeHead{
					TreeHead:  *th2,
					Signature: logSig,
				},
				cosignatures: map[types.Hash]*types.Signature{},
			},
		},
	} {
		table.before.rotate(table.next)
		if got, want := table.before.cosigned.SignedTreeHead, table.after.cosigned.SignedTreeHead; !reflect.DeepEqual(got, want) {
			t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
		checkWitnessList(t, table.description, table.before.cosigned, table.after.cosigned)
		if got, want := table.before.toSign, table.after.toSign; !reflect.DeepEqual(got, want) {
			t.Errorf("got toSign tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
		if got, want := table.before.cosignatures, table.after.cosignatures; !reflect.DeepEqual(got, want) {
			t.Errorf("got cosignatures map\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func checkWitnessList(t *testing.T, description string, got, want types.CosignedTreeHead) {
	t.Helper()
	if got, want := len(got.Cosignature), len(want.Cosignature); got != want {
		t.Errorf("got %d cosignatures but wanted %d in test %q", got, want, description)
		return
	}
	if got, want := len(got.KeyHash), len(want.KeyHash); got != want {
		t.Errorf("got %d key hashes but wanted %d in test %q", got, want, description)
		return
	}
	for i := 0; i < len(got.Cosignature); i++ {
		found := false
		for j := 0; j < len(want.Cosignature); j++ {
			if bytes.Equal(got.Cosignature[i][:], want.Cosignature[j][:]) && bytes.Equal(got.KeyHash[i][:], want.KeyHash[j][:]) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("got unexpected signature-signer pair with key hash in test %q: %x", description, got.KeyHash[i][:])
		}
	}
}

func mustSign(t *testing.T, s crypto.Signer, th *types.TreeHead, kh *types.Hash) *types.SignedTreeHead {
	sth, err := th.Sign(s, kh)
	if err != nil {
		t.Fatal(err)
	}
	return sth
}
