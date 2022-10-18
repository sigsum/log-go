package state

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	mocksClient "sigsum.org/log-go/internal/mocks/client"
	mocksDB "sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
	"github.com/golang/mock/gomock"
)

// TestSigner implements the signer interface.  It can be used to mock
// an Ed25519 signer that always return the same public key,
// signature, and error.
// NOTE: Code duplication with internal/node/secondary/endpoint_internal_test.go
type TestSigner struct {
	PublicKey [ed25519.PublicKeySize]byte
	Signature [ed25519.SignatureSize]byte
	Error     error
}

func (ts *TestSigner) Public() crypto.PublicKey {
	return ed25519.PublicKey(ts.PublicKey[:])
}

func (ts *TestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ts.Signature[:], ts.Error
}

func TestNewStateManagerSingle(t *testing.T) {
	signerOk := &TestSigner{types.PublicKey{}, types.Signature{}, nil}
	signerErr := &TestSigner{types.PublicKey{}, types.Signature{}, fmt.Errorf("err")}
	for _, table := range []struct {
		description string
		signer      crypto.Signer
		thExp       bool
		thErr       error
		th          types.TreeHead
		secExp      bool
		wantErr     bool
	}{
		{"invalid: signer failure", signerErr, false, nil, types.TreeHead{}, false, true},
		{"valid", signerOk, true, nil, types.TreeHead{Timestamp: now(t)}, true, false},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			trillianClient := mocksDB.NewMockClient(ctrl)
			if table.thExp {
				trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(&table.th, table.thErr)
			}
			secondary := mocksClient.NewMockClient(ctrl)
			if table.secExp {
				secondary.EXPECT().Initiated().Return(false)
			}

			tmpFile, err := os.CreateTemp("", "sigsum-log-test-sth")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpFile.Name())
			sm, err := NewStateManagerSingle(trillianClient, table.signer, time.Duration(0), time.Duration(0), secondary, tmpFile, nil)
			if got, want := err != nil, table.description != "valid"; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}

			if got, want := sm.signedTreeHead.TreeSize, table.th.TreeSize; got != want {
				t.Errorf("%q: got tree size %d but wanted %d", table.description, got, want)
			}
			if got, want := sm.signedTreeHead.RootHash[:], table.th.RootHash[:]; !bytes.Equal(got, want) {
				t.Errorf("%q: got tree size %v but wanted %v", table.description, got, want)
			}
			if got, want := sm.signedTreeHead.Timestamp, table.th.Timestamp; got < want {
				t.Errorf("%q: got timestamp %d but wanted at least %d", table.description, got, want)
			}
			if got := sm.cosignedTreeHead; got != nil {
				t.Errorf("%q: got cosigned tree head but should have none", table.description)
			}
		}()
	}
}

func TestToCosignTreeHead(t *testing.T) {
	want := &types.SignedTreeHead{}
	sm := StateManagerSingle{
		signedTreeHead: want,
	}
	sth := sm.ToCosignTreeHead()
	if got := sth; !reflect.DeepEqual(got, want) {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}
}

func TestCosignedTreeHead(t *testing.T) {
	want := &types.CosignedTreeHead{
		Cosignature: make([]types.Signature, 1),
		KeyHash:     make([]merkle.Hash, 1),
	}
	sm := StateManagerSingle{
		cosignedTreeHead: want,
	}
	cth, err := sm.CosignedTreeHead()
	if err != nil {
		t.Errorf("should not fail with error: %v", err)
		return
	}
	if got := cth; !reflect.DeepEqual(got, want) {
		t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v", got, want)
	}

	sm.cosignedTreeHead = nil
	cth, err = sm.CosignedTreeHead()
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
			namespace:      *merkle.HashFn(nil),
			signedTreeHead: &types.SignedTreeHead{},
			witnesses:      map[merkle.Hash]types.PublicKey{*merkle.HashFn(public[:]): public},
			cosignatures:   make(map[merkle.Hash]*types.Signature),
		}

		sth := mustSign(t, table.signer, &sm.signedTreeHead.TreeHead, &sm.namespace)
		err := sm.AddCosignature(merkle.HashFn(table.vk[:]), &sth.Signature)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
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

func mustSign(t *testing.T, s crypto.Signer, th *types.TreeHead, kh *merkle.Hash) *types.SignedTreeHead {
	t.Helper()
	sth, err := th.Sign(s, kh)
	if err != nil {
		t.Fatal(err)
	}
	return sth
}

func newHashBufferInc(t *testing.T) *merkle.Hash {
	t.Helper()

	var buf merkle.Hash
	for i := 0; i < len(buf); i++ {
		buf[i] = byte(i)
	}
	return &buf
}
func validConsistencyProof_5_10(t *testing.T) *types.ConsistencyProof {
	t.Helper()
	// # old tree head
	//     tree_size=5
	//     root_hash=c8e73a8c09e44c344d515eb717e248c5dbf12420908a6d29568197fae7751803
	// # new tree head
	//     tree_size=10
	//     root_hash=2a40f11563b45522ca9eccf993c934238a8fbadcf7d7d65be3583ab2584838aa
	r := bytes.NewReader([]byte("consistency_path=fadca95ab8ca34f17c5f3fa719183fe0e5c194a44c25324745388964a743ecce\nconsistency_path=6366fc0c20f9b8a8c089ed210191e401da6c995592eba78125f0ba0ba142ebaf\nconsistency_path=72b8d4f990b555a72d76fb8da075a65234519070cfa42e082026a8c686160349\nconsistency_path=d92714be792598ff55560298cd3ff099dfe5724646282578531c0d0063437c00\nconsistency_path=4b20d58bbae723755304fb179aef6d5f04d755a601884828c62c07929f6bd84a\n"))
	var proof types.ConsistencyProof
	if err := proof.FromASCII(r, 5, 10); err != nil {
		t.Fatal(err)
	}
	return &proof
}

func hashFromString(t *testing.T, s string) (h merkle.Hash) {
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
