package db

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	ttypes "github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	mocksTrillian "sigsum.org/log-go/internal/mocks/trillian"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// TODO: Add TestAddSequencedLeaves

func TestAddLeaf(t *testing.T) {
	leaf := &types.Leaf{
		Checksum:  crypto.Hash{},
		Signature: crypto.Signature{},
		KeyHash:   crypto.Hash{},
	}
	for _, table := range []struct {
		description       string
		leaf              *types.Leaf
		rsp               *trillian.QueueLeafResponse
		queueLeafErr      error
		inclusionProofErr error
		wantErr           bool
		wantSequenced     bool
	}{
		{
			description:  "invalid: backend failure",
			leaf:         leaf,
			queueLeafErr: fmt.Errorf("something went wrong"),
			wantErr:      true,
		},
		{
			description:       "unsequenced",
			leaf:              leaf,
			queueLeafErr:      nil,
			inclusionProofErr: status.Error(codes.NotFound, "not found"),
			wantErr:           false,
			wantSequenced:     false,
		},
		{
			description:       "sequenced",
			leaf:              leaf,
			queueLeafErr:      nil,
			inclusionProofErr: nil,
			wantErr:           false,
			wantSequenced:     true,
		},
	} {
		// Run deferred functions at the end of each iteration
		t.Run(table.description, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocksTrillian.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().QueueLeaf(gomock.Any(), gomock.Any()).Return(table.rsp, table.queueLeafErr)
			if table.queueLeafErr == nil {
				grpc.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(
					// returns a fake inclusion proof just to pass validation in GetInclusionProof
					&trillian.GetInclusionProofByHashResponse{
						Proof: []*trillian.Proof{{LeafIndex: 1, Hashes: [][]byte{make([]byte, crypto.HashSize)}}},
					},
					table.inclusionProofErr,
				)
			}
			client := TrillianClient{logClient: grpc}

			status, err := client.AddLeaf(context.Background(), table.leaf, 1)
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}
			if status.IsSequenced != table.wantSequenced {
				t.Errorf("got sequenced == %v, expected %v", status.IsSequenced, table.wantSequenced)
			}
		})
	}
}

func TestGetTreeHead(t *testing.T) {
	// valid root
	root := &ttypes.LogRootV1{
		TreeSize:       0,
		RootHash:       make([]byte, crypto.HashSize),
		TimestampNanos: 1622585623133599429,
	}
	buf, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("must marshal log root: %v", err)
	}
	// invalid root
	root.RootHash = make([]byte, crypto.HashSize+1)
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
				Size:     0,
				RootHash: crypto.Hash{},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocksTrillian.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{logClient: grpc}

			th, err := client.GetTreeHead(context.Background())
			if got, want := err != nil, table.wantErr; got != want {
				t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
			}
			if err != nil {
				return
			}

			if got, want := th.Size, table.wantTh.Size; got != want {
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
		wantProof   types.ConsistencyProof
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
			description: "invalid: not a consistency proof (2/2)",
			req:         req,
			rsp: &trillian.GetConsistencyProofResponse{
				Proof: &trillian.Proof{
					Hashes: [][]byte{
						make([]byte, crypto.HashSize),
						make([]byte, crypto.HashSize+1),
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
						make([]byte, crypto.HashSize),
						make([]byte, crypto.HashSize),
					},
				},
			},
			wantProof: types.ConsistencyProof{
				Path: []crypto.Hash{
					crypto.Hash{},
					crypto.Hash{},
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocksTrillian.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetConsistencyProof(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{logClient: grpc}

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
		Size:     4,
		LeafHash: crypto.Hash{},
	}
	for _, table := range []struct {
		description string
		req         *requests.InclusionProof
		rsp         *trillian.GetInclusionProofByHashResponse
		err         error
		wantErr     bool
		wantProof   types.InclusionProof
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
							make([]byte, crypto.HashSize),
							make([]byte, crypto.HashSize+1),
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
							make([]byte, crypto.HashSize),
							make([]byte, crypto.HashSize),
						},
					},
				},
			},
			wantProof: types.InclusionProof{
				LeafIndex: 1,
				Path: []crypto.Hash{
					crypto.Hash{},
					crypto.Hash{},
				},
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocksTrillian.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetInclusionProofByHash(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{logClient: grpc}

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
		StartIndex: 1,
		EndIndex:   3,
	}
	firstLeaf := &types.Leaf{
		Checksum:  crypto.Hash{},
		Signature: crypto.Signature{},
		KeyHash:   crypto.Hash{},
	}
	secondLeaf := &types.Leaf{
		Checksum:  crypto.Hash{},
		Signature: crypto.Signature{},
		KeyHash:   crypto.Hash{},
	}

	for _, table := range []struct {
		description string
		req         *requests.Leaves
		rsp         *trillian.GetLeavesByRangeResponse
		err         error
		wantErr     bool
		wantLeaves  []types.Leaf
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
			wantLeaves: []types.Leaf{
				*firstLeaf,
				*secondLeaf,
			},
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			grpc := mocksTrillian.NewMockTrillianLogClient(ctrl)
			grpc.EXPECT().GetLeavesByRange(gomock.Any(), gomock.Any()).Return(table.rsp, table.err)
			client := TrillianClient{logClient: grpc}

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
