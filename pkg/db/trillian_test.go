package db

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"git.sigsum.org/log-go/pkg/db/mocks"
	"git.sigsum.org/sigsum-go/pkg/requests"
	"git.sigsum.org/sigsum-go/pkg/types"
	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAddLeaf(t *testing.T) {
	req := &requests.Leaf{
		ShardHint:       0,
		Message:         types.Hash{},
		Signature:       types.Signature{},
		VerificationKey: types.PublicKey{},
		DomainHint:      "example.com",
	}
	for _, table := range []struct {
		description string
		req         *requests.Leaf
		rsp         *trillian.QueueLeafResponse
		err         error
		wantErr     bool
	}{
		{
			description: "invalid: backend failure",
			req:         req,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: no response",
			req:         req,
			wantErr:     true,
		},
		{
			description: "invalid: no queued leaf",
			req:         req,
			rsp:         &trillian.QueueLeafResponse{},
			wantErr:     true,
		},
		{
			description: "invalid: leaf is already queued or included",
			req:         req,
			rsp: &trillian.QueueLeafResponse{
				QueuedLeaf: &trillian.QueuedLogLeaf{
					Leaf: &trillian.LogLeaf{
						LeafValue: []byte{0}, // does not matter for test
					},
					Status: status.New(codes.AlreadyExists, "duplicate").Proto(),
				},
			},
			wantErr: true,
		},
		{
			description: "valid",
			req:         req,
			rsp: &trillian.QueueLeafResponse{
				QueuedLeaf: &trillian.QueuedLogLeaf{
					Leaf: &trillian.LogLeaf{
						LeafValue: []byte{0}, // does not matter for test
					},
					Status: status.New(codes.OK, "ok").Proto(),
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocks.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{GRPC: grpc}

			err := client.AddLeaf(context.Background(), table.req)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
		}()
	}
}

func TestGetTreeHead(t *testing.T) {
	// valid root
	root := &ttypes.LogRootV1{
		TreeSize:       0,
		RootHash:       make([]byte, types.HashSize),
		TimestampNanos: 1622585623133599429,
	}
	buf, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("must marshal log root: %v", err)
	}
	// invalid root
	root.RootHash = make([]byte, types.HashSize+1)
	bufBadHash, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("must marshal log root: %v", err)
	}

	for _, table := range []struct {
		description string
		rsp         *trillian.GetLatestSignedLogRootResponse
		err         error
		wantErr     bool
		wantTh      *types.TreeHead
	}{
		{
			description: "invalid: backend failure",
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: no response",
			wantErr:     true,
		},
		{
			description: "invalid: no signed log root",
			rsp:         &trillian.GetLatestSignedLogRootResponse{},
			wantErr:     true,
		},
		{
			description: "invalid: no log root",
			rsp: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{},
			},
			wantErr: true,
		},
		{
			description: "invalid: no log root: unmarshal failed",
			rsp: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: buf[1:],
				},
			},
			wantErr: true,
		},
		{
			description: "invalid: unexpected hash length",
			rsp: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: bufBadHash,
				},
			},
			wantErr: true,
		},
		{
			description: "valid",
			rsp: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: buf,
				},
			},
			wantTh: &types.TreeHead{
				Timestamp: 1622585623,
				TreeSize:  0,
				RootHash:  types.Hash{},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocks.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{GRPC: grpc}

			th, err := client.GetTreeHead(context.Background())
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}

			// we would need a clock that can be mocked to make a nicer test
			now := uint64(time.Now().Unix())
			if got, wantLow, wantHigh := th.Timestamp, now-5, now+5; got < wantLow || got > wantHigh {
				t.Errorf("got tree head with timestamp %d but wanted between [%d, %d] in test %q",
					got, wantLow, wantHigh, table.description)
			}
			if got, want := th.TreeSize, table.wantTh.TreeSize; got != want {
				t.Errorf("got tree head with tree size %d but wanted %d in test %q", got, want, table.description)
			}
			if got, want := th.RootHash[:], table.wantTh.RootHash[:]; !bytes.Equal(got, want) {
				t.Errorf("got root hash %x but wanted %x in test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetConsistencyProof(t *testing.T) {
	req := &requests.ConsistencyProof{
		OldSize: 1,
		NewSize: 3,
	}
	for _, table := range []struct {
		description string
		req         *requests.ConsistencyProof
		rsp         *trillian.GetConsistencyProofResponse
		err         error
		wantErr     bool
		wantProof   *types.ConsistencyProof
	}{
		{
			description: "invalid: backend failure",
			req:         req,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: no response",
			req:         req,
			wantErr:     true,
		},
		{
			description: "invalid: no consistency proof",
			req:         req,
			rsp:         &trillian.GetConsistencyProofResponse{},
			wantErr:     true,
		},
		{
			description: "invalid: not a consistency proof (1/2)",
			req:         req,
			rsp: &trillian.GetConsistencyProofResponse{
				Proof: &trillian.Proof{
					Hashes: [][]byte{},
				},
			},
			wantErr: true,
		},
		{
			description: "invalid: not a consistency proof (2/2)",
			req:         req,
			rsp: &trillian.GetConsistencyProofResponse{
				Proof: &trillian.Proof{
					Hashes: [][]byte{
						make([]byte, types.HashSize),
						make([]byte, types.HashSize+1),
					},
				},
			},
			wantErr: true,
		},
		{
			description: "valid",
			req:         req,
			rsp: &trillian.GetConsistencyProofResponse{
				Proof: &trillian.Proof{
					Hashes: [][]byte{
						make([]byte, types.HashSize),
						make([]byte, types.HashSize),
					},
				},
			},
			wantProof: &types.ConsistencyProof{
				OldSize: 1,
				NewSize: 3,
				Path: []types.Hash{
					types.Hash{},
					types.Hash{},
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocks.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{GRPC: grpc}

			proof, err := client.GetConsistencyProof(context.Background(), table.req)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := proof, table.wantProof; !reflect.DeepEqual(got, want) {
				t.Errorf("got proof\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetInclusionProof(t *testing.T) {
	req := &requests.InclusionProof{
		TreeSize: 4,
		LeafHash: types.Hash{},
	}
	for _, table := range []struct {
		description string
		req         *requests.InclusionProof
		rsp         *trillian.GetInclusionProofByHashResponse
		err         error
		wantErr     bool
		wantProof   *types.InclusionProof
	}{
		{
			description: "invalid: backend failure",
			req:         req,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: no response",
			req:         req,
			wantErr:     true,
		},
		{
			description: "invalid: bad proof count",
			req:         req,
			rsp: &trillian.GetInclusionProofByHashResponse{
				Proof: []*trillian.Proof{
					&trillian.Proof{},
					&trillian.Proof{},
				},
			},
			wantErr: true,
		},
		{
			description: "invalid: not an inclusion proof (1/2)",
			req:         req,
			rsp: &trillian.GetInclusionProofByHashResponse{
				Proof: []*trillian.Proof{
					&trillian.Proof{
						LeafIndex: 1,
						Hashes:    [][]byte{},
					},
				},
			},
			wantErr: true,
		},
		{
			description: "invalid: not an inclusion proof (2/2)",
			req:         req,
			rsp: &trillian.GetInclusionProofByHashResponse{
				Proof: []*trillian.Proof{
					&trillian.Proof{
						LeafIndex: 1,
						Hashes: [][]byte{
							make([]byte, types.HashSize),
							make([]byte, types.HashSize+1),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			description: "valid",
			req:         req,
			rsp: &trillian.GetInclusionProofByHashResponse{
				Proof: []*trillian.Proof{
					&trillian.Proof{
						LeafIndex: 1,
						Hashes: [][]byte{
							make([]byte, types.HashSize),
							make([]byte, types.HashSize),
						},
					},
				},
			},
			wantProof: &types.InclusionProof{
				TreeSize:  4,
				LeafIndex: 1,
				Path: []types.Hash{
					types.Hash{},
					types.Hash{},
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocks.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{GRPC: grpc}

			proof, err := client.GetInclusionProof(context.Background(), table.req)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := proof, table.wantProof; !reflect.DeepEqual(got, want) {
				t.Errorf("got proof\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
		}()
	}
}

func TestGetLeaves(t *testing.T) {
	req := &requests.Leaves{
		StartSize: 1,
		EndSize:   2,
	}
	firstLeaf := &types.Leaf{
		Statement: types.Statement{
			ShardHint: 0,
			Checksum:  types.Hash{},
		},
		Signature: types.Signature{},
		KeyHash:   types.Hash{},
	}
	secondLeaf := &types.Leaf{
		Statement: types.Statement{
			ShardHint: 0,
			Checksum:  types.Hash{},
		},
		Signature: types.Signature{},
		KeyHash:   types.Hash{},
	}

	for _, table := range []struct {
		description string
		req         *requests.Leaves
		rsp         *trillian.GetLeavesByRangeResponse
		err         error
		wantErr     bool
		wantLeaves  *types.Leaves
	}{
		{
			description: "invalid: backend failure",
			req:         req,
			err:         fmt.Errorf("something went wrong"),
			wantErr:     true,
		},
		{
			description: "invalid: no response",
			req:         req,
			wantErr:     true,
		},
		{
			description: "invalid: unexpected number of leaves",
			req:         req,
			rsp: &trillian.GetLeavesByRangeResponse{
				Leaves: []*trillian.LogLeaf{
					&trillian.LogLeaf{
						LeafValue: firstLeaf.ToBinary(),
						LeafIndex: 1,
					},
				},
			},
			wantErr: true,
		},
		{
			description: "invalid: unexpected leaf (1/2)",
			req:         req,
			rsp: &trillian.GetLeavesByRangeResponse{
				Leaves: []*trillian.LogLeaf{
					&trillian.LogLeaf{
						LeafValue: firstLeaf.ToBinary(),
						LeafIndex: 1,
					},
					&trillian.LogLeaf{
						LeafValue: secondLeaf.ToBinary(),
						LeafIndex: 3,
					},
				},
			},
			wantErr: true,
		},
		{
			description: "invalid: unexpected leaf (2/2)",
			req:         req,
			rsp: &trillian.GetLeavesByRangeResponse{
				Leaves: []*trillian.LogLeaf{
					&trillian.LogLeaf{
						LeafValue: firstLeaf.ToBinary(),
						LeafIndex: 1,
					},
					&trillian.LogLeaf{
						LeafValue: secondLeaf.ToBinary()[1:],
						LeafIndex: 2,
					},
				},
			},
			wantErr: true,
		},
		{
			description: "valid",
			req:         req,
			rsp: &trillian.GetLeavesByRangeResponse{
				Leaves: []*trillian.LogLeaf{
					&trillian.LogLeaf{
						LeafValue: firstLeaf.ToBinary(),
						LeafIndex: 1,
					},
					&trillian.LogLeaf{
						LeafValue: secondLeaf.ToBinary(),
						LeafIndex: 2,
					},
				},
			},
			wantLeaves: &types.Leaves{
				*firstLeaf,
				*secondLeaf,
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocks.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{GRPC: grpc}

			leaves, err := client.GetLeaves(context.Background(), table.req)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if got, want := leaves, table.wantLeaves; !reflect.DeepEqual(got, want) {
				t.Errorf("got leaves\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
			}
		}()
	}
}
