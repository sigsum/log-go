package state

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

// TestSigner implements the signer interface.  It can be used to mock
// an Ed25519 signer that always return the same public key,
// signature, and error.
// NOTE: Code duplication with internal/node/secondary/endpoint_internal_test.go
type TestSigner struct {
	PublicKey crypto.PublicKey
	Signature crypto.Signature
	Error     error
}

func (ts *TestSigner) Public() crypto.PublicKey {
	return ts.PublicKey
}

func (ts *TestSigner) Sign(_ []byte) (crypto.Signature, error) {
	return ts.Signature, ts.Error
}

const testWitnessTimestamp = 1234

func TestNewStateManagerSingle(t *testing.T) {
	_, signer, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []struct {
		description string
		thErr       error
	}{
		{"valid", nil},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			trillianClient := db.NewMockClient(ctrl)
			th := types.TreeHead{}
			trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(th, table.thErr)

			tmpFile, err := os.CreateTemp("", "sigsum-log-test-sth")
			if err != nil {
				t.Fatal(err)
			}
			defer tmpFile.Close()
			defer os.Remove(tmpFile.Name())
			emptyTh := types.TreeHead{RootHash: crypto.HashBytes([]byte(""))}
			emptySth, err := emptyTh.Sign(signer)
			if err != nil {
				t.Fatal(err)
			}
			if err := emptySth.ToASCII(tmpFile); err != nil {
				t.Fatal(err)
			}
			if err := tmpFile.Close(); err != nil {
				t.Fatal(err)
			}
			// This test uses no secondary and no witnesses.
			sm, err := NewStateManagerSingle(trillianClient, signer, time.Duration(0), nil, tmpFile.Name(), nil)
			if got, want := err != nil, table.description != "valid"; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}

			if got, want := sm.signedTreeHead.Size, th.Size; got != want {
				t.Errorf("%q: got tree size %d but wanted %d", table.description, got, want)
			}
			if got, want := sm.signedTreeHead.RootHash[:], th.RootHash[:]; !bytes.Equal(got, want) {
				t.Errorf("%q: got tree hash %x but wanted %x", table.description, got, want)
			}
			if got := len(sm.cosignedTreeHead.Cosignatures); got != 0 {
				t.Errorf("%q: got %d cosignatures but should have none", table.description, got)
			}
		}()
	}
}

func TestNextTreeHead(t *testing.T) {
	want := types.SignedTreeHead{}
	sm := StateManagerSingle{
		signedTreeHead: want,
	}
	sth := sm.NextTreeHead()
	if got := sth; got != want {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}
}

func TestCosignedTreeHead(t *testing.T) {
	want := types.CosignedTreeHead{
		Cosignatures: make([]types.Cosignature, 1),
	}
	sm := StateManagerSingle{
		cosignedTreeHead: want,
	}
	cth := sm.CosignedTreeHead()
	if got := cth; !reflect.DeepEqual(got, want) {
		t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}
}

func TestAddCosignature(t *testing.T) {
	public, secret := mustKeyPair(t)

	for _, table := range []struct {
		desc    string
		signer  crypto.Signer
		vk      crypto.PublicKey
		wantErr error
	}{
		{
			desc:    "invalid: wrong public key",
			signer:  secret,
			vk:      crypto.PublicKey{},
			wantErr: ErrUnknownWitness,
		},
		{
			desc:   "valid",
			signer: secret,
			vk:     public,
		},
	} {
		sm := StateManagerSingle{
			keyHash:        crypto.HashBytes(nil),
			signedTreeHead: types.SignedTreeHead{},
			witnesses:      map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(public[:]): public},
			cosignatures:   make(map[crypto.Hash]types.Cosignature),
		}

		sig := mustCosign(t, table.signer, &sm.signedTreeHead.TreeHead, &sm.keyHash)
		sig.KeyHash = crypto.HashBytes(table.vk[:])
		err := sm.AddCosignature(&sig)
		if got, want := err, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
	}
}

func TestAddRotate(t *testing.T) {
	// Log and witness keys.
	lPub, lSigner := mustKeyPair(t)
	wPub, wSigner := mustKeyPair(t)

	signerErr := TestSigner{lPub, crypto.Signature{}, fmt.Errorf("err")}

	kh := crypto.HashBytes(lPub[:])

	for _, table := range []struct {
		desc            string
		signErr         bool
		signedSize      uint64
		nextSize        uint64
		withCosignature bool
	}{
		{
			desc:     "empty",
			nextSize: 1,
		},
		{
			desc:       "1->2",
			signedSize: 1,
			nextSize:   2,
		},
		{
			desc:            "cosignatures",
			signedSize:      2,
			nextSize:        4,
			withCosignature: true,
		},
		{
			desc:       "sign failure",
			signErr:    true,
			signedSize: 1,
			nextSize:   2,
		},
	} {
		var signer crypto.Signer
		if table.signErr {
			signer = &signerErr
		} else {
			signer = lSigner
		}
		sth := mustSignTreehead(t, lSigner, table.signedSize)
		cth := types.CosignedTreeHead{SignedTreeHead: sth}
		nth := types.TreeHead{Size: table.nextSize}
		cosignatures := make(map[crypto.Hash]types.Cosignature)
		if table.withCosignature {
			cosignatures[crypto.Hash{}] = mustCosign(
				t, wSigner, &sth.TreeHead, &kh)
		}
		var storedSth types.SignedTreeHead
		sm := StateManagerSingle{
			signer:           signer,
			signedTreeHead:   sth,
			cosignedTreeHead: cth,
			cosignatures:     cosignatures,
			storeSth: func(sth *types.SignedTreeHead) error {
				storedSth = *sth
				return nil
			},
		}
		err := sm.rotate(&nth)
		// Expect error only for signature failures
		if table.signErr {
			if err == nil {
				t.Errorf("%s: rotate succeeded, despite failing signer", table.desc)
			}
		} else if err != nil {
			t.Errorf("%s: rotate failed: %v", table.desc, err)
		} else {
			if s := len(sm.cosignatures); s > 0 {
				t.Errorf("%s: state cosignature list not empty after rotation, got size %d", table.desc, s)
			}
			newSth := sm.NextTreeHead()
			if !newSth.Verify(&lPub) {
				t.Errorf("%s: sth signature not valid", table.desc)
			}
			if newSth.TreeHead != nth {
				t.Errorf("%s: unexpected signed tree head after rotation, got size %d, expected %d", table.desc, newSth.Size, table.nextSize)
			}
			if storedSth != newSth {
				t.Errorf("%s: unexpected stored tree head after rotation, got size %d, expected %d", table.desc, storedSth.Size, table.nextSize)
			}
			newCth := sm.CosignedTreeHead()
			if !newCth.Verify(&lPub) {
				t.Errorf("%s: cth log signature not valid", table.desc)
			}
			if newCth.SignedTreeHead != sth {
				t.Errorf("%s: unexpected cosigned tree head after rotation, got size %d, expected %d", table.desc, newCth.Size, table.signedSize)
			}
			if table.withCosignature {
				if len(newCth.Cosignatures) != 1 {
					t.Fatalf("%s: unexpected cth cosignature count, got %d, expected 1", table.desc, len(newCth.Cosignatures))
				}
				if !newCth.Cosignatures[0].Verify(&wPub, &kh, &newCth.TreeHead) {
					t.Errorf("%s: cth cosignature not valid", table.desc)
				}
				if newCth.Cosignatures[0].Timestamp != testWitnessTimestamp {
					t.Errorf("%s: cth cosignature timestamp not as expected, got %d", table.desc, newCth.Cosignatures[0].Timestamp)
				}
			} else {
				if len(newCth.Cosignatures) > 0 {
					t.Fatalf("%s: non-empty cth cosignature list, got size %d", table.desc, len(newCth.Cosignatures))
				}
			}
		}
	}
}

func mustKeyPair(t *testing.T) (crypto.PublicKey, crypto.Signer) {
	t.Helper()
	pub, signer, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pub, signer
}

func mustCosign(t *testing.T, s crypto.Signer, th *types.TreeHead, kh *crypto.Hash) types.Cosignature {
	t.Helper()
	signature, err := th.Cosign(s, kh, testWitnessTimestamp)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func mustSignTreehead(t *testing.T,
	signer crypto.Signer, size uint64) types.SignedTreeHead {
	t.Helper()
	th := types.TreeHead{Size: size}
	sth, err := th.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	return sth
}

func newHashBufferInc(t *testing.T) *crypto.Hash {
	t.Helper()

	var buf crypto.Hash
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}
func validConsistencyProof_5_10(t *testing.T) *types.ConsistencyProof {
	t.Helper()
	// # old tree head
	//     size=5
	//     root_hash=c8e73a8c09e44c344d515eb717e248c5dbf12420908a6d29568197fae7751803
	// # new tree head
	//     size=10
	//     root_hash=2a40f11563b45522ca9eccf993c934238a8fbadcf7d7d65be3583ab2584838aa
	r := bytes.NewReader([]byte("consistency_path=fadca95ab8ca34f17c5f3fa719183fe0e5c194a44c25324745388964a743ecce\nconsistency_path=6366fc0c20f9b8a8c089ed210191e401da6c995592eba78125f0ba0ba142ebaf\nconsistency_path=72b8d4f990b555a72d76fb8da075a65234519070cfa42e082026a8c686160349\nconsistency_path=d92714be792598ff55560298cd3ff099dfe5724646282578531c0d0063437c00\nconsistency_path=4b20d58bbae723755304fb179aef6d5f04d755a601884828c62c07929f6bd84a\n"))
	var proof types.ConsistencyProof
	if err := proof.FromASCII(r, 5, 10); err != nil {
		t.Fatal(err)
	}
	return &proof
}

func hashFromString(t *testing.T, s string) (h crypto.Hash) {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	copy(h[:], b)
	return h
}

func now(t *testing.T) uint64 {
	t.Helper()
	return uint64(time.Now().Unix())
}
