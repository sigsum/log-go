package requests

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"sigsum.org/sigsum-go/pkg/dns"
	"sigsum.org/sigsum-go/pkg/merkle"
	sigsumreq "sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func LeafRequestFromHTTP(r *http.Request, shardStart uint64, ctx context.Context, vf dns.Verifier) (*sigsumreq.Leaf, error) {
	var req sigsumreq.Leaf
	if err := req.FromASCII(r.Body); err != nil {
		return nil, fmt.Errorf("parse ascii: %w", err)
	}
	stmt := types.Statement{
		ShardHint: req.ShardHint,
		Checksum:  *merkle.HashFn(req.Message[:]),
	}
	if !stmt.Verify(&req.PublicKey, &req.Signature) {
		return nil, fmt.Errorf("invalid signature")
	}
	shardEnd := uint64(time.Now().Unix())
	if req.ShardHint < shardStart {
		return nil, fmt.Errorf("invalid shard hint: %d not in [%d, %d]", req.ShardHint, shardStart, shardEnd)
	}
	if req.ShardHint > shardEnd {
		return nil, fmt.Errorf("invalid shard hint: %d not in [%d, %d]", req.ShardHint, shardStart, shardEnd)
	}
	if err := vf.Verify(ctx, req.DomainHint, &req.PublicKey); err != nil {
		return nil, fmt.Errorf("invalid domain hint: %v", err)
	}
	return &req, nil
}

func CosignatureRequestFromHTTP(r *http.Request) (*sigsumreq.Cosignature, error) {
	var req sigsumreq.Cosignature
	if err := req.FromASCII(r.Body); err != nil {
		return nil, fmt.Errorf("parse ascii: %w", err)
	}
	return &req, nil
}

func ConsistencyProofRequestFromHTTP(r *http.Request) (*sigsumreq.ConsistencyProof, error) {
	var req sigsumreq.ConsistencyProof
	if err := req.FromURL(r.URL.Path); err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if req.OldSize < 1 {
		return nil, fmt.Errorf("old_size(%d) must be larger than zero", req.OldSize)
	}
	if req.NewSize <= req.OldSize {
		return nil, fmt.Errorf("new_size(%d) must be larger than old_size(%d)", req.NewSize, req.OldSize)
	}
	return &req, nil
}

func InclusionProofRequestFromHTTP(r *http.Request) (*sigsumreq.InclusionProof, error) {
	var req sigsumreq.InclusionProof
	if err := req.FromURL(r.URL.Path); err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if req.TreeSize < 2 {
		// TreeSize:0 => not possible to prove inclusion of anything
		// TreeSize:1 => you don't need an inclusion proof (it is always empty)
		return nil, fmt.Errorf("tree_size(%d) must be larger than one", req.TreeSize)
	}
	return &req, nil
}

func LeavesRequestFromHTTP(r *http.Request, maxIndex, maxRange uint64) (*sigsumreq.Leaves, error) {
	var req sigsumreq.Leaves
	if err := req.FromURL(r.URL.Path); err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	if req.StartSize > req.EndSize {
		return nil, fmt.Errorf("start_size(%d) must be less than or equal to end_size(%d)", req.StartSize, req.EndSize)
	}
	if req.EndSize > maxIndex {
		return nil, fmt.Errorf("end_size(%d) outside of current tree", req.EndSize)
	}
	if req.EndSize-req.StartSize+1 > maxRange {
		req.EndSize = req.StartSize + maxRange - 1
	}
	return &req, nil
}
