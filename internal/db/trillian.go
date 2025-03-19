package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/trillian"
	trillianTypes "github.com/google/trillian/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// TrillianClient implements the Client interface for Trillian's gRPC backend
type TrillianClient struct {
	// treeID is a Merkle tree identifier that Trillian uses
	treeID int64

	// logClient is a Trillian gRPC client
	logClient trillian.TrillianLogClient
}

type TreeType int

const (
	PrimaryTree TreeType = iota
	SecondaryTree
)

// This is an error if it happens for a get-inclusion-proof request
// from a log client, but we must accept it when we internally ask for
// an inclusion proof for the very first leaf.
var errEmptyInclusionProof = errors.New("not an inclusion proof: empty")

func (treeType TreeType) checkTrillianTreeType(trillianType trillian.TreeType) error {
	switch treeType {
	case PrimaryTree:
		if trillianType != trillian.TreeType_LOG {
			return fmt.Errorf("trillian tree of type %s, but must be of type LOG for a Sigsum primary",
				trillianType.String())
		}
	case SecondaryTree:
		if trillianType != trillian.TreeType_PREORDERED_LOG {
			return fmt.Errorf("trillian tree of type %s, but must be of type PREORDERED_LOG for a Sigsum secondary",
				trillianType.String())
		}
	default:
		panic(fmt.Sprintf("internal error, invalid tree type %d", treeType))
	}
	return nil
}

func DialTrillian(target string, timeout time.Duration, treeType TreeType, treeIdFile string) (*TrillianClient, error) {
	treeId, err := readTreeId(treeIdFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read tree id: %v", err)
	}

	conn, err := grpc.Dial(target,
		grpc.WithInsecure(), grpc.WithBlock(),
		grpc.WithTimeout(timeout))
	if err != nil {
		return nil, fmt.Errorf("connection to trillian failed: %v", err)
	}
	tree, err := trillian.NewTrillianAdminClient(conn).GetTree(
		context.Background(), &trillian.GetTreeRequest{TreeId: int64(treeId)})
	if err != nil {
		return nil, err
	}
	if err := treeType.checkTrillianTreeType(tree.TreeType); err != nil {
		return nil, err
	}

	return &TrillianClient{
		treeID:    int64(treeId),
		logClient: trillian.NewTrillianLogClient(conn),
	}, nil
}

// AddLeaf adds a leaf to the tree and returns true if the leaf has
// been sequenced into the tree of size treeSize.
func (c *TrillianClient) AddLeaf(ctx context.Context, leaf *types.Leaf, treeSize uint64) (AddLeafStatus, error) {
	serialized := leaf.ToBinary()

	log.Debug("queueing leaf request: %x", merkle.HashLeafNode(serialized))
	queueLeafResponse, err := c.logClient.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: c.treeID,
		Leaf: &trillian.LogLeaf{
			LeafValue: serialized,
		},
	})
	alreadyExists := false
	switch status.Code(err) {
	case codes.OK:
		if queueLeafResponse != nil {
			queueLeafStatus := queueLeafResponse.QueuedLeaf.Status
			if queueLeafStatus != nil {
				if codes.Code(queueLeafStatus.Code) == codes.AlreadyExists {
					alreadyExists = true
				}
			}
		}
	case codes.AlreadyExists:
		alreadyExists = true
	default:
		return AddLeafStatus{}, fmt.Errorf("back-end rpc failure: %v", err)
	}
	if treeSize == 0 {
		// Certainly not sequenced, and passing treeSize = 0 to Trillian results in an InvalidArgument response.
		return AddLeafStatus{AlreadyExists: alreadyExists, IsSequenced: false}, nil
	}
	_, err = c.GetInclusionProof(ctx, &requests.InclusionProof{treeSize, merkle.HashLeafNode(serialized)})
	switch err {
	case nil:
		return AddLeafStatus{AlreadyExists: alreadyExists, IsSequenced: true}, nil
	case ErrNotIncluded:
		return AddLeafStatus{AlreadyExists: alreadyExists, IsSequenced: false}, nil
	case errEmptyInclusionProof:
		if treeSize == 1 {
			// An empty proof is expected, and means that the leaf is present.
			return AddLeafStatus{AlreadyExists: alreadyExists, IsSequenced: true}, nil
		}
		fallthrough
	default:
		return AddLeafStatus{}, fmt.Errorf("back-end rpc failure: %v", err)
	}
}

// AddSequencedLeaves adds a set of already sequenced leaves to the tree.
func (c *TrillianClient) AddSequencedLeaves(ctx context.Context, leaves []types.Leaf, index int64) error {
	trilLeaves := make([]*trillian.LogLeaf, len(leaves))
	for i, leaf := range leaves {
		trilLeaves[i] = &trillian.LogLeaf{
			LeafValue: leaf.ToBinary(),
			LeafIndex: index + int64(i),
		}
	}

	req := trillian.AddSequencedLeavesRequest{
		LogId:  c.treeID,
		Leaves: trilLeaves,
	}
	log.Debug("adding sequenced leaves: count %d", len(trilLeaves))
	var err error
	for wait := 1; wait < 30; wait *= 2 {
		var rsp *trillian.AddSequencedLeavesResponse
		rsp, err = c.logClient.AddSequencedLeaves(ctx, &req)
		switch status.Code(err) {
		case codes.ResourceExhausted:
			log.Info("waiting %d seconds before retrying to add %d leaves, reason: %v", wait, len(trilLeaves), err)
			time.Sleep(time.Second * time.Duration(wait))
			continue
		case codes.OK:
			if rsp == nil {
				return fmt.Errorf("logClient.AddSequencedLeaves no response")
			}
			// FIXME: check rsp.Results.QueuedLogLeaf
			return nil
		default:
			return fmt.Errorf("logClient.AddSequencedLeaves error: %v", err)
		}
	}

	return fmt.Errorf("giving up on adding %d leaves", len(trilLeaves))
}

func (c *TrillianClient) GetTreeHead(ctx context.Context) (types.TreeHead, error) {
	rsp, err := c.logClient.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: c.treeID,
	})
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return types.TreeHead{}, fmt.Errorf("no response")
	}
	if rsp.SignedLogRoot == nil {
		return types.TreeHead{}, fmt.Errorf("no signed log root")
	}
	if rsp.SignedLogRoot.LogRoot == nil {
		return types.TreeHead{}, fmt.Errorf("no log root")
	}
	var r trillianTypes.LogRootV1
	if err := r.UnmarshalBinary(rsp.SignedLogRoot.LogRoot); err != nil {
		return types.TreeHead{}, fmt.Errorf("no log root: unmarshal failed: %v", err)
	}
	if len(r.RootHash) != crypto.HashSize {
		return types.TreeHead{}, fmt.Errorf("unexpected hash length: %d", len(r.RootHash))
	}
	return treeHeadFromLogRoot(&r), nil
}

func (c *TrillianClient) GetConsistencyProof(ctx context.Context, req *requests.ConsistencyProof) (types.ConsistencyProof, error) {
	// Trivial cases with empty proof.
	if req.OldSize == 0 || req.OldSize == req.NewSize {
		return types.ConsistencyProof{}, nil
	}
	rsp, err := c.logClient.GetConsistencyProof(ctx, &trillian.GetConsistencyProofRequest{
		LogId:          c.treeID,
		FirstTreeSize:  int64(req.OldSize),
		SecondTreeSize: int64(req.NewSize),
	})
	if err != nil {
		return types.ConsistencyProof{}, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return types.ConsistencyProof{}, fmt.Errorf("no response")
	}
	if rsp.Proof == nil {
		return types.ConsistencyProof{}, fmt.Errorf("no consistency proof")
	}
	path, err := nodePathFromHashes(rsp.Proof.Hashes)
	if err != nil {
		return types.ConsistencyProof{}, fmt.Errorf("not a consistency proof: %v", err)
	}
	return types.ConsistencyProof{Path: path}, nil
}

func (c *TrillianClient) GetInclusionProof(ctx context.Context, req *requests.InclusionProof) (types.InclusionProof, error) {
	rsp, err := c.logClient.GetInclusionProofByHash(ctx, &trillian.GetInclusionProofByHashRequest{
		LogId:           c.treeID,
		LeafHash:        req.LeafHash[:],
		TreeSize:        int64(req.Size),
		OrderBySequence: true,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return types.InclusionProof{}, ErrNotIncluded
		}
		return types.InclusionProof{}, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return types.InclusionProof{}, ErrNotIncluded
	}
	if len(rsp.Proof) != 1 {
		return types.InclusionProof{}, fmt.Errorf("bad proof count: %d", len(rsp.Proof))
	}
	proof := rsp.Proof[0]
	if len(proof.Hashes) == 0 {
		return types.InclusionProof{}, errEmptyInclusionProof
	}
	path, err := nodePathFromHashes(proof.Hashes)
	if err != nil {
		return types.InclusionProof{}, fmt.Errorf("not an inclusion proof: %v", err)
	}
	return types.InclusionProof{
		LeafIndex: uint64(proof.LeafIndex),
		Path:      path,
	}, nil
}

func (c *TrillianClient) GetLeaves(ctx context.Context, req *requests.Leaves) ([]types.Leaf, error) {
	rsp, err := c.logClient.GetLeavesByRange(ctx, &trillian.GetLeavesByRangeRequest{
		LogId:      c.treeID,
		StartIndex: int64(req.StartIndex),
		Count:      int64(req.EndIndex - req.StartIndex),
	})
	if err != nil {
		return nil, fmt.Errorf("backend failure: %v", err)
	}
	if rsp == nil {
		return nil, fmt.Errorf("no response")
	}
	if got, want := len(rsp.Leaves), int(req.EndIndex-req.StartIndex); got != want {
		return nil, fmt.Errorf("unexpected number of leaves: %d", got)
	}
	list := make([]types.Leaf, 0, len(rsp.Leaves))
	for i, leaf := range rsp.Leaves {
		leafIndex := int64(req.StartIndex + uint64(i))
		if leafIndex != leaf.LeafIndex {
			return nil, fmt.Errorf("unexpected leaf(%d): got index %d", leafIndex, leaf.LeafIndex)
		}

		var l types.Leaf
		if err := l.FromBinary(leaf.LeafValue); err != nil {
			return nil, fmt.Errorf("unexpected leaf(%d): %v", leafIndex, err)
		}
		list = append(list[:], l)
	}
	return list, nil
}

func treeHeadFromLogRoot(lr *trillianTypes.LogRootV1) types.TreeHead {
	th := types.TreeHead{
		Size: uint64(lr.TreeSize),
	}
	copy(th.RootHash[:], lr.RootHash)
	return th
}

func nodePathFromHashes(hashes [][]byte) ([]crypto.Hash, error) {
	path := make([]crypto.Hash, len(hashes))
	for i := 0; i < len(hashes); i++ {
		if len(hashes[i]) != crypto.HashSize {
			return nil, fmt.Errorf("unexpected hash length: %v", len(hashes[i]))
		}

		copy(path[i][:], hashes[i])
	}
	return path, nil
}

func readTreeId(file string) (uint64, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	p := ascii.NewParser(f)
	return p.GetInt("tree-id")
}
