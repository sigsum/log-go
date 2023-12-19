package primary

// This file implements external HTTP handler callbacks for primary nodes.

import (
	"context"
	"fmt"
	"net/http"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/sigsum-go/pkg/api"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit-token"
	"sigsum.org/sigsum-go/pkg/types"
)

func (p Primary) AddLeaf(ctx context.Context, req requests.Leaf, t *token.SubmitHeader) (bool, error) {
	log.Debug("handling add-leaf request")
	var domain *string
	if t != nil && p.TokenVerifier != nil {
		// TODO: Return more appropriate errors from TokenVerifier?
		if err := p.TokenVerifier.Verify(ctx, t); err != nil {
			return false, api.NewError(http.StatusBadRequest, err)
		}
		domain = &t.Domain
	}
	keyHash := crypto.HashBytes(req.PublicKey[:])
	relax := p.RateLimiter.AccessAllowed(domain, &keyHash)
	if relax == nil {
		if domain == nil {
			return false, api.NewError(http.StatusTooManyRequests, fmt.Errorf("rate-limit for unknown domain exceeded"))
		}
		return false, api.NewError(http.StatusTooManyRequests, fmt.Errorf("rate-limit for domain %q exceeded", *domain))
	}
	leaf, err := req.Verify()
	if err != nil {
		return false, api.NewError(http.StatusForbidden, err)
	}

	sth := p.Stateman.SignedTreeHead()
	status, err := p.DbClient.AddLeaf(ctx,
		&leaf, sth.Size)
	log.Debug("status: %#v, err: %v", status, err)
	if err != nil {
		return false, err
	}
	if status.AlreadyExists {
		relax()
	}
	return status.IsSequenced, nil
}

func (p Primary) GetTreeHead(_ context.Context) (types.CosignedTreeHead, error) {
	log.Debug("handling get-tree-head request")
	return p.Stateman.CosignedTreeHead(), nil
}

func (p Primary) GetConsistencyProof(ctx context.Context, req requests.ConsistencyProof) (types.ConsistencyProof, error) {
	log.Debug("handling get-consistency-proof request")
	curTree := p.Stateman.CosignedTreeHead()
	if req.NewSize > curTree.TreeHead.Size {
		// TODO: Would be better with something like api.ErrBadRequest.WithMessage(...)
		return types.ConsistencyProof{}, api.NewError(http.StatusBadRequest, fmt.Errorf("new_size %d outside of current tree, size %d",
			req.NewSize, curTree.TreeHead.Size))
	}

	return p.DbClient.GetConsistencyProof(ctx, &req)
}

func (p Primary) GetInclusionProof(ctx context.Context, req requests.InclusionProof) (types.InclusionProof, error) {
	log.Debug("handling get-inclusion-proof request")
	curTree := p.Stateman.CosignedTreeHead()
	if req.Size > curTree.TreeHead.Size {
		return types.InclusionProof{}, api.NewError(http.StatusBadRequest, fmt.Errorf("tree_size outside of current tree"))
	}

	proof, err := p.DbClient.GetInclusionProof(ctx, &req)
	// TODO: Appropriate error from DbClient?
	if err == db.ErrNotIncluded {
		err = api.ErrNotFound
	}
	return proof, err
}

func (p Primary) getLeavesGeneral(ctx context.Context, req requests.Leaves,
	maxIndex uint64, strictEnd bool) ([]types.Leaf, error) {
	log.Debug("handling get-leaves request")

	// When invoked via sigsum-go/pkg/server, this error is
	// already checked for earlier and will not happen here.
	if req.StartIndex >= req.EndIndex {
		return nil, api.NewError(http.StatusBadRequest,
			fmt.Errorf("start_index(%d) must be less than end_index(%d)",
				req.StartIndex, req.EndIndex))
	}

	if req.StartIndex > maxIndex || (strictEnd && req.StartIndex >= maxIndex) {
		return nil, api.NewError(http.StatusBadRequest,
			fmt.Errorf("start_index(%d) outside of current tree", req.StartIndex))
	}
	if req.EndIndex > maxIndex {
		if strictEnd {
			return nil, api.NewError(http.StatusBadRequest,
				fmt.Errorf("end_index(%d) outside of current tree", req.EndIndex))
		}
		req.EndIndex = maxIndex
	}
	if req.EndIndex-req.StartIndex > uint64(p.MaxRange) {
		req.EndIndex = req.StartIndex + uint64(p.MaxRange)
	}

	// May happen only when strictEnd is false.
	if req.StartIndex == req.EndIndex {
		if strictEnd {
			return nil, fmt.Errorf("internal error, empty range")
		}
		// TODO: Would be better with api.ErrNotFound.WithMessage(...)
		return nil, api.NewError(http.StatusNotFound, fmt.Errorf("at end of tree"))
	}
	leaves, err := p.DbClient.GetLeaves(ctx, &req)
	if err == nil && len(leaves) == 0 {
		err = fmt.Errorf("backend get leaves returned an empty list")
	}
	return leaves, err
}

func (p Primary) GetLeaves(ctx context.Context, req requests.Leaves) ([]types.Leaf, error) {
	return p.getLeavesGeneral(ctx, req, p.Stateman.CosignedTreeHead().Size, true)
}
