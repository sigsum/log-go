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

	"github.com/golang/mock/gomock"
	"golang.sigsum.org/sigsum-log-go/pkg/mocks"
	"golang.sigsum.org/sigsum-log-go/pkg/types"
)

var (
	testSig = &[types.SignatureSize]byte{}
	testPub = &[types.VerificationKeySize]byte{}
	testTH  = &types.TreeHead{
		Timestamp: 0,
		TreeSize:  0,
		RootHash:  types.Hash(nil),
	}
	testSigIdent = &types.SigIdent{
		Signature: testSig,
		KeyHash:   types.Hash(testPub[:]),
	}
	testSTH = &types.SignedTreeHead{
		TreeHead: *testTH,
		SigIdent: []*types.SigIdent{testSigIdent},
	}
	testSignerOK  = &mocks.TestSigner{testPub, testSig, nil}
	testSignerErr = &mocks.TestSigner{testPub, testSig, fmt.Errorf("something went wrong")}
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
			rsp:         testTH,
			wantSth:     testSTH,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocks.NewMockClient(ctrl)
			client.EXPECT().GetTreeHead(gomock.Any()).Return(table.rsp, table.err)

			sm, err := NewStateManagerSingle(client, table.signer, time.Duration(0), time.Duration(0))
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := &sm.cosigned, table.wantSth; !reflect.DeepEqual(got, want) {
				t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
			if got, want := &sm.tosign, table.wantSth; !reflect.DeepEqual(got, want) {
				t.Errorf("got tosign tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
			// we only have log signature on startup
			if got, want := len(sm.cosignature), 1; got != want {
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
			rsp:         testTH,
			signer:      testSignerErr,
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      testSignerOK,
			rsp:         testTH,
			wantSth:     testSTH,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			client := mocks.NewMockClient(ctrl)
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
		tosign: *testSTH,
	}
	sth, err := sm.ToSign(context.Background())
	if err != nil {
		t.Errorf("ToSign should not fail with error: %v", err)
		return
	}
	if got, want := sth, testSTH; !reflect.DeepEqual(got, want) {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, description)
	}
}

func TestCosigned(t *testing.T) {
	description := "valid"
	sm := StateManagerSingle{
		cosigned: *testSTH,
	}
	sth, err := sm.Cosigned(context.Background())
	if err != nil {
		t.Errorf("Cosigned should not fail with error: %v", err)
		return
	}
	if got, want := sth, testSTH; !reflect.DeepEqual(got, want) {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, description)
	}
}

func TestAddCosignature(t *testing.T) {
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if bytes.Equal(vk[:], testPub[:]) {
		t.Fatalf("Sampled same key as testPub, aborting...")
	}
	var vkArray [types.VerificationKeySize]byte
	copy(vkArray[:], vk[:])

	for _, table := range []struct {
		description string
		signer      crypto.Signer
		vk          *[types.VerificationKeySize]byte
		th          *types.TreeHead
		wantErr     bool
	}{
		{
			description: "invalid: signature error",
			signer:      sk,
			vk:          testPub, // wrong key for message
			th:          testTH,
			wantErr:     true,
		},
		{
			description: "valid",
			signer:      sk,
			vk:          &vkArray,
			th:          testTH,
		},
	} {
		sth, _ := table.th.Sign(testSignerOK)
		logKeyHash := sth.SigIdent[0].KeyHash
		logSigIdent := sth.SigIdent[0]
		sm := &StateManagerSingle{
			signer:   testSignerOK,
			cosigned: *sth,
			tosign:   *sth,
			cosignature: map[[types.HashSize]byte]*types.SigIdent{
				*logKeyHash: logSigIdent,
			},
		}

		// Prepare witness signature
		sth, err := table.th.Sign(table.signer)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		witnessKeyHash := sth.SigIdent[0].KeyHash
		witnessSigIdent := sth.SigIdent[0]

		// Add witness signature
		err = sm.AddCosignature(context.Background(), table.vk, witnessSigIdent.Signature)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}

		// We should have two signatures (log + witness)
		if got, want := len(sm.cosignature), 2; got != want {
			t.Errorf("got %d cosignatures but wanted %v in test %q", got, want, table.description)
			continue
		}
		// check that log signature is there
		sigident, ok := sm.cosignature[*logKeyHash]
		if !ok {
			t.Errorf("log signature is missing")
			continue
		}
		if got, want := sigident, logSigIdent; !reflect.DeepEqual(got, want) {
			t.Errorf("got log sigident\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
		// check that witness signature is there
		sigident, ok = sm.cosignature[*witnessKeyHash]
		if !ok {
			t.Errorf("witness signature is missing")
			continue
		}
		if got, want := sigident, witnessSigIdent; !reflect.DeepEqual(got, want) {
			t.Errorf("got witness sigident\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			continue
		}

		// Adding a duplicate signature should give an error
		if err := sm.AddCosignature(context.Background(), table.vk, witnessSigIdent.Signature); err == nil {
			t.Errorf("duplicate witness signature accepted as valid")
		}
	}
}

func TestRotate(t *testing.T) {
	log := testSigIdent
	wit1 := &types.SigIdent{
		Signature: testSig,
		KeyHash:   types.Hash([]byte("wit1 key")),
	}
	wit2 := &types.SigIdent{
		Signature: testSig,
		KeyHash:   types.Hash([]byte("wit2 key")),
	}
	th0 := testTH
	th1 := &types.TreeHead{
		Timestamp: 1,
		TreeSize:  1,
		RootHash:  types.Hash([]byte("1")),
	}
	th2 := &types.TreeHead{
		Timestamp: 2,
		TreeSize:  2,
		RootHash:  types.Hash([]byte("2")),
	}

	for _, table := range []struct {
		description   string
		before, after *StateManagerSingle
		next          *types.SignedTreeHead
	}{
		{
			description: "tosign tree head repated, but got one new witnes signature",
			before: &StateManagerSingle{
				cosigned: types.SignedTreeHead{
					TreeHead: *th0,
					SigIdent: []*types.SigIdent{log, wit1},
				},
				tosign: types.SignedTreeHead{
					TreeHead: *th0,
					SigIdent: []*types.SigIdent{log},
				},
				cosignature: map[[types.HashSize]byte]*types.SigIdent{
					*log.KeyHash:  log,
					*wit2.KeyHash: wit2, // the new witness signature
				},
			},
			next: &types.SignedTreeHead{
				TreeHead: *th1,
				SigIdent: []*types.SigIdent{log},
			},
			after: &StateManagerSingle{
				cosigned: types.SignedTreeHead{
					TreeHead: *th0,
					SigIdent: []*types.SigIdent{log, wit1, wit2},
				},
				tosign: types.SignedTreeHead{
					TreeHead: *th1,
					SigIdent: []*types.SigIdent{log},
				},
				cosignature: map[[types.HashSize]byte]*types.SigIdent{
					*log.KeyHash: log, // after rotate we always have log sig
				},
			},
		},
		{
			description: "tosign tree head did not repeat, it got one witness signature",
			before: &StateManagerSingle{
				cosigned: types.SignedTreeHead{
					TreeHead: *th0,
					SigIdent: []*types.SigIdent{log, wit1},
				},
				tosign: types.SignedTreeHead{
					TreeHead: *th1,
					SigIdent: []*types.SigIdent{log},
				},
				cosignature: map[[types.HashSize]byte]*types.SigIdent{
					*log.KeyHash:  log,
					*wit2.KeyHash: wit2, // the only witness that signed tosign
				},
			},
			next: &types.SignedTreeHead{
				TreeHead: *th2,
				SigIdent: []*types.SigIdent{log},
			},
			after: &StateManagerSingle{
				cosigned: types.SignedTreeHead{
					TreeHead: *th1,
					SigIdent: []*types.SigIdent{log, wit2},
				},
				tosign: types.SignedTreeHead{
					TreeHead: *th2,
					SigIdent: []*types.SigIdent{log},
				},
				cosignature: map[[types.HashSize]byte]*types.SigIdent{
					*log.KeyHash: log, // after rotate we always have log sig
				},
			},
		},
	} {
		table.before.rotate(table.next)
		if got, want := table.before.cosigned.TreeHead, table.after.cosigned.TreeHead; !reflect.DeepEqual(got, want) {
			t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
		checkWitnessList(t, table.description, table.before.cosigned.SigIdent, table.after.cosigned.SigIdent)
		if got, want := table.before.tosign.TreeHead, table.after.tosign.TreeHead; !reflect.DeepEqual(got, want) {
			t.Errorf("got tosign tree head\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
		checkWitnessList(t, table.description, table.before.tosign.SigIdent, table.after.tosign.SigIdent)
		if got, want := table.before.cosignature, table.after.cosignature; !reflect.DeepEqual(got, want) {
			t.Errorf("got cosignature map\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func checkWitnessList(t *testing.T, description string, got, want []*types.SigIdent) {
	t.Helper()
	for _, si := range got {
		found := false
		for _, sj := range want {
			if reflect.DeepEqual(si, sj) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("got unexpected signature-signer pair with key hash in test %q: %x", description, si.KeyHash[:])
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d signature-signer pairs but wanted %d in test %q", len(got), len(want), description)
	}
}
