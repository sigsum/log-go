package witness

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"sigsum.org/log-go/internal/mocks/db"

	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/mocks/mockapi"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func testWitness(t *testing.T, ctrl *gomock.Controller) (crypto.Signer, *mockapi.MockWitness, *witness) {
	pub, signer := mustKeyPair(t)
	client := mockapi.NewMockWitness(ctrl)
	return signer, client, &witness{
		client:  client,
		entity:  policy.Entity{PublicKey: pub, URL: "test://test"},
		keyHash: crypto.HashBytes(pub[:]),
	}
}

type ptrMatcher struct {
	m gomock.Matcher
}

func (p ptrMatcher) Matches(x any) bool {
	return x != nil && p.m.Matches(reflect.ValueOf(x).Elem().Interface())
}
func (p ptrMatcher) String() string {
	return fmt.Sprintf("non-nil pointer to %s", p.m)
}
func Ptr(m gomock.Matcher) gomock.Matcher {
	return ptrMatcher{m: m}
}
func TestWitnessEmpty(t *testing.T) {
	testTimestamp := uint64(101010)
	_, logSigner := mustKeyPair(t)

	ctrl := gomock.NewController(t)
	witnessSigner, cli, w := testWitness(t, ctrl)

	log := db.NewMockClient(ctrl)

	cp := mustSignTreehead(t, logSigner, 5)

	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 0, NewSize: 5}))).Return(types.ConsistencyProof{}, nil)
	cli.EXPECT().AddCheckpoint(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error) {
			if req.OldSize != 0 || req.Checkpoint != cp {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return mustCosign(t, witnessSigner, &req.Checkpoint, testTimestamp), nil
		})

	i, err := w.getCosignature(context.Background(), &cp, log.GetConsistencyProof)
	if err != nil {
		t.Fatalf("getCosignature failed: %v", err)
	}
	if i.cs.Timestamp != testTimestamp {
		t.Errorf("unexpected timestamp, got %d, want: %d", i.cs.Timestamp, testTimestamp)
	}
}

func TestWitnessBadSize(t *testing.T) {
	testTimestamp := uint64(101010)
	_, logSigner := mustKeyPair(t)

	ctrl := gomock.NewController(t)
	witnessSigner, cli, w := testWitness(t, ctrl)

	log := db.NewMockClient(ctrl)

	cp := mustSignTreehead(t, logSigner, 5)

	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 0, NewSize: 5}))).Return(types.ConsistencyProof{}, nil)
	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 2, NewSize: 5}))).Return(
		// Dummy path, but length 1 to distinguish the two calls.
		types.ConsistencyProof{Path: []crypto.Hash{crypto.Hash{}}}, nil)
	cli.EXPECT().AddCheckpoint(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error) {
			if req.OldSize != 0 || req.Checkpoint != cp || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return nil, api.ErrConflict.WithOldSize(2)
		})
	cli.EXPECT().AddCheckpoint(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error) {
			if req.OldSize != 2 || req.Checkpoint != cp || len(req.Proof.Path) != 1 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return mustCosign(t, witnessSigner, &req.Checkpoint, testTimestamp), nil
		})

	i, err := w.getCosignature(context.Background(), &cp, log.GetConsistencyProof)
	if err != nil {
		t.Fatalf("getCosignature failed: %v", err)
	}
	if i.cs.Timestamp != testTimestamp {
		t.Errorf("unexpected timestamp, got %d, want: %d", i.cs.Timestamp, testTimestamp)
	}
}

func TestGetCosignatures(t *testing.T) {
	testTimestamp := uint64(101010)
	_, logSigner := mustKeyPair(t)

	ctrl := gomock.NewController(t)
	signer1, cli1, w1 := testWitness(t, ctrl)
	_, cli2, w2 := testWitness(t, ctrl)
	signer3, cli3, w3 := testWitness(t, ctrl)

	log := db.NewMockClient(ctrl)

	cp := mustSignTreehead(t, logSigner, 5)
	collector := CosignatureCollector{
		origin:              cp.Origin,
		keyId:               cp.KeyId,
		getConsistencyProof: log.GetConsistencyProof,
		witnesses:           []*witness{w1, w2, w3},
	}

	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 0, NewSize: 5}))).Return(types.ConsistencyProof{}, nil).AnyTimes()
	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 2, NewSize: 5}))).Return(
		// Dummy path, but length 1 to distinguish the two calls.
		types.ConsistencyProof{Path: []crypto.Hash{crypto.Hash{}}}, nil)

	// First witness needs size query.
	cli1.EXPECT().AddCheckpoint(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error) {
			if req.OldSize != 0 || req.Checkpoint != cp || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return nil, api.ErrConflict.WithOldSize(2)
		})
	cli1.EXPECT().AddCheckpoint(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error) {
			if req.OldSize != 2 || req.Checkpoint != cp || len(req.Proof.Path) != 1 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return mustCosign(t, signer1, &req.Checkpoint, testTimestamp), nil
		})
	// Second witness fails.
	cli2.EXPECT().AddCheckpoint(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error) {
			if req.OldSize != 0 || req.Checkpoint != cp || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return nil, fmt.Errorf("mock failure")
		})

	// Third witness succeeds with slight delay.
	cli3.EXPECT().AddCheckpoint(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error) {
			if req.OldSize != 0 || req.Checkpoint != cp || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			time.Sleep(50 * time.Millisecond)
			return mustCosign(t, signer3, &req.Checkpoint, testTimestamp), nil
		})

	cosignatures := collector.GetCosignatures(context.Background(), &cp.SignedTreeHead)
	if got, want := len(cosignatures), 2; got != want {
		t.Errorf("unexpected number of cosignatures, got: %d, want: %d", got, want)
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

func mustCosign(t *testing.T, s crypto.Signer, cp *checkpoint.Checkpoint, timestamp uint64) []checkpoint.CosignatureLine {
	t.Helper()
	cs, err := cp.Cosign(s, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := s.Public()
	keyName := "example.org/witness"

	return []checkpoint.CosignatureLine{
		checkpoint.CosignatureLine{
			KeyName: keyName,
			KeyId:   checkpoint.NewWitnessKeyId(keyName, &publicKey),
			Cosignature: types.Cosignature{
				Timestamp: cs.Timestamp,
				Signature: cs.Signature,
			},
		},
	}
}

func mustSignTreehead(t *testing.T,
	signer crypto.Signer, size uint64) checkpoint.Checkpoint {
	t.Helper()
	th := types.TreeHead{Size: size}
	sth, err := th.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.Public()
	origin := types.SigsumCheckpointOrigin(&pub)

	return checkpoint.Checkpoint{
		SignedTreeHead: sth,
		Origin:         origin,
		KeyId:          checkpoint.NewLogKeyId(origin, &pub),
	}
}
