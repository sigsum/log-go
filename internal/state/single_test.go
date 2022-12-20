package state

import (
	"bytes"
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
			// This test uses no secondary.
			sm, err := NewStateManagerSingle(trillianClient, signer, time.Duration(0), nil, &crypto.PublicKey{}, tmpFile.Name())
			if got, want := err != nil, table.description != "valid"; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}

			if got, want := sm.signedTreeHead.Size, emptyTh.Size; got != want {
				t.Errorf("%q: got tree size %d but wanted %d", table.description, got, want)
			}
			if got, want := sm.signedTreeHead.RootHash[:], emptyTh.RootHash[:]; !bytes.Equal(got, want) {
				t.Errorf("%q: got tree hash %x but wanted %x", table.description, got, want)
			}
		}()
	}
}

func TestSignedTreeHead(t *testing.T) {
	want := types.SignedTreeHead{}
	sm := StateManagerSingle{
		signedTreeHead: want,
	}
	sth := sm.SignedTreeHead()
	if got := sth; !reflect.DeepEqual(got, want) {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}
}

func TestAddRotate(t *testing.T) {
	// Log and witness keys.
	lPub, lSigner := mustKeyPair(t)

	signerErr := TestSigner{lPub, crypto.Signature{}, fmt.Errorf("err")}

	for _, table := range []struct {
		desc            string
		signErr         bool
		signedSize      uint64
		nextSize        uint64
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
		nth := types.TreeHead{Size: table.nextSize}
		var storedSth types.SignedTreeHead
		sm := StateManagerSingle{
			signer:           signer,
			signedTreeHead:   sth,
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
			newSth := sm.SignedTreeHead()
			if !newSth.Verify(&lPub) {
				t.Errorf("%s: sth signature not valid", table.desc)
			}
			if newSth.TreeHead != nth {
				t.Errorf("%s: unexpected signed tree head after rotation, got size %d, expected %d", table.desc, newSth.Size, table.nextSize)
			}
			if storedSth != newSth {
				t.Errorf("%s: unexpected stored tree head after rotation, got size %d, expected %d", table.desc, storedSth.Size, table.nextSize)
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
