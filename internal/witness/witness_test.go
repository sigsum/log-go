package witness

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"

	"sigsum.org/log-go/internal/mocks/db"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/mocks"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func testWitness(ctrl *gomock.Controller, f GetConsistencyProofFunc) (*mocks.MockWitnessClient, *witness) {
	client := mocks.NewMockWitnessClient(ctrl)
	return client, &witness{
		client:              client,
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
	ctrl := gomock.NewController(t)
	log := db.NewMockClient(ctrl)
	cli, w := testWitness(ctrl, log.GetConsistencyProof)

	sth := types.SignedTreeHead{TreeHead: types.TreeHead{Size: 5}}

	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 0, NewSize: 5}))).Return(types.ConsistencyProof{}, nil)
	cli.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (types.Cosignature, error) {
			if req.OldSize != 0 || req.TreeHead != sth {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return types.Cosignature{Timestamp: testTimestamp}, nil
		})

	cs, err := w.getCosignature(context.Background(), &sth)
	if err != nil {
		t.Fatalf("getCosignature failed: %v", err)
	}
	if cs.Timestamp != testTimestamp {
		t.Errorf("unexpected timestamp, got %d, want: %d", cs.Timestamp, testTimestamp)
	}
}

func TestWitnessBadSize(t *testing.T) {
	testTimestamp := uint64(101010)
	ctrl := gomock.NewController(t)
	log := db.NewMockClient(ctrl)
	cli, w := testWitness(ctrl, log.GetConsistencyProof)

	sth := types.SignedTreeHead{TreeHead: types.TreeHead{Size: 5}}

	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 0, NewSize: 5}))).Return(types.ConsistencyProof{}, nil)
	log.EXPECT().GetConsistencyProof(gomock.Any(), Ptr(gomock.Eq(requests.ConsistencyProof{OldSize: 2, NewSize: 5}))).Return(
		// Dummy path, but length 1 to distinguish the two calls.
		types.ConsistencyProof{Path: []crypto.Hash{crypto.Hash{}}}, nil)
	cli.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (types.Cosignature, error) {
			if req.OldSize != 0 || req.TreeHead != sth || len(req.Proof.Path) != 0 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return types.Cosignature{}, client.HttpUnprocessableEntity
		})
	cli.EXPECT().GetTreeSize(gomock.Any(), gomock.Any()).Return(uint64(2), nil)
	cli.EXPECT().AddTreeHead(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, req requests.AddTreeHead) (types.Cosignature, error) {
			if req.OldSize != 2 || req.TreeHead != sth || len(req.Proof.Path) != 1 {
				t.Fatalf("unexpected add tree head req, got: %v", req)
			}
			return types.Cosignature{Timestamp: testTimestamp}, nil
		})

	cs, err := w.getCosignature(context.Background(), &sth)
	if err != nil {
		t.Fatalf("getCosignature failed: %v", err)
	}
	if cs.Timestamp != testTimestamp {
		t.Errorf("unexpected timestamp, got %d, want: %d", cs.Timestamp, testTimestamp)
	}
}
