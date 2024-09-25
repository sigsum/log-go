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
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/mocks"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func testWitness(t *testing.T, ctrl *gomock.Controller,
	logKeyHash *crypto.Hash,
	f GetConsistencyProofFunc) (crypto.Signer, *mocks.MockWitness, *witness) {
	pub, signer := mustKeyPair(t)
	client := mocks.NewMockWitness(ctrl)
	return signer, client, &witness{
		client:              client,
		pubKey:              pub,
		keyHash:             crypto.HashBytes(pub[:]),
		logKeyHash:          *logKeyHash,
		getConsistencyProof: f,
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
	logPub, logSigner := mustKeyPair(t)
	logKeyHash := crypto.HashBytes(logPub[:])

	ctrl := gomock.NewController(t)
	log := db.NewMockClient(ctrl)
	witnessSigner, cli, w := testWitness(t, ctrl, &logKeyHash, log.GetConsistencyProof)

	sth := mustSignTreehead(t, logSigner, 5)

	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 0, NewSize: 5}))).Return(types.ConsistencyProof{}, nil)
	cli.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (crypto.Hash, types.Cosignature, error) {
			if req.OldSize != 0 || req.TreeHead != sth {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return w.keyHash, mustCosign(t, witnessSigner, &req.TreeHead.TreeHead, &logKeyHash, testTimestamp), nil
		})

	i, err := w.getCosignature(context.Background(), &sth)
	if err != nil {
		t.Fatalf("getCosignature failed: %v", err)
	}
	if i.cs.Timestamp != testTimestamp {
		t.Errorf("unexpected timestamp, got %d, want: %d", i.cs.Timestamp, testTimestamp)
	}
}

func TestWitnessBadSize(t *testing.T) {
	testTimestamp := uint64(101010)
	logPub, logSigner := mustKeyPair(t)
	logKeyHash := crypto.HashBytes(logPub[:])

	ctrl := gomock.NewController(t)
	log := db.NewMockClient(ctrl)
	witnessSigner, cli, w := testWitness(t, ctrl, &logKeyHash, log.GetConsistencyProof)

	sth := mustSignTreehead(t, logSigner, 5)

	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 0, NewSize: 5}))).Return(types.ConsistencyProof{}, nil)
	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 2, NewSize: 5}))).Return(
		// Dummy path, but length 1 to distinguish the two calls.
		types.ConsistencyProof{Path: []crypto.Hash{crypto.Hash{}}}, nil)
	cli.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (crypto.Hash, types.Cosignature, error) {
			if req.OldSize != 0 || req.TreeHead != sth || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return crypto.Hash{}, types.Cosignature{}, api.ErrConflict
		})
	cli.EXPECT().GetTreeSize(gomock.Any(), gomock.Any()).Return(uint64(2), nil)
	cli.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (crypto.Hash, types.Cosignature, error) {
			if req.OldSize != 2 || req.TreeHead != sth || len(req.Proof.Path) != 1 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return w.keyHash, mustCosign(t, witnessSigner, &req.TreeHead.TreeHead, &logKeyHash, testTimestamp), nil
		})

	i, err := w.getCosignature(context.Background(), &sth)
	if err != nil {
		t.Fatalf("getCosignature failed: %v", err)
	}
	if i.cs.Timestamp != testTimestamp {
		t.Errorf("unexpected timestamp, got %d, want: %d", i.cs.Timestamp, testTimestamp)
	}
}

func TestGetCosignatures(t *testing.T) {
	testTimestamp := uint64(101010)
	logPub, logSigner := mustKeyPair(t)
	logKeyHash := crypto.HashBytes(logPub[:])

	ctrl := gomock.NewController(t)
	log := db.NewMockClient(ctrl)

	signer1, cli1, w1 := testWitness(t, ctrl, &logKeyHash, log.GetConsistencyProof)
	_, cli2, w2 := testWitness(t, ctrl, &logKeyHash, log.GetConsistencyProof)
	signer3, cli3, w3 := testWitness(t, ctrl, &logKeyHash, log.GetConsistencyProof)

	sth := mustSignTreehead(t, logSigner, 5)

	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 0, NewSize: 5}))).Return(types.ConsistencyProof{}, nil).AnyTimes()
	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 2, NewSize: 5}))).Return(
		// Dummy path, but length 1 to distinguish the two calls.
		types.ConsistencyProof{Path: []crypto.Hash{crypto.Hash{}}}, nil)

	// First witness needs size query.
	cli1.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (crypto.Hash, types.Cosignature, error) {
			if req.OldSize != 0 || req.TreeHead != sth || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return crypto.Hash{}, types.Cosignature{}, api.ErrConflict
		})
	cli1.EXPECT().GetTreeSize(gomock.Any(), gomock.Any()).Return(uint64(2), nil)
	cli1.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (crypto.Hash, types.Cosignature, error) {
			if req.OldSize != 2 || req.TreeHead != sth || len(req.Proof.Path) != 1 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return w1.keyHash, mustCosign(t, signer1, &req.TreeHead.TreeHead, &logKeyHash, testTimestamp), nil
		})
	// Second witness fails.
	cli2.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (crypto.Hash, types.Cosignature, error) {
			if req.OldSize != 0 || req.TreeHead != sth || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return crypto.Hash{}, types.Cosignature{}, fmt.Errorf("mock failure")
		})

	// Third witness succeeds with slight delay.
	cli3.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (crypto.Hash, types.Cosignature, error) {
			if req.OldSize != 0 || req.TreeHead != sth || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			time.Sleep(50 * time.Millisecond)
			return w3.keyHash, mustCosign(t, signer3, &req.TreeHead.TreeHead, &logKeyHash, testTimestamp), nil
		})
	collector := CosignatureCollector{witnesses: []*witness{w1, w2, w3}}

	cosignatures := collector.GetCosignatures(context.Background(), &sth)
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

func mustCosign(t *testing.T, s crypto.Signer, th *types.TreeHead, kh *crypto.Hash, timestamp uint64) types.Cosignature {
	t.Helper()
	signature, err := th.Cosign(s, kh, timestamp)
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
