package primary

// This file implements external HTTP handler callbacks for primary nodes.

import (
	"context"
	"fmt"
	"math"
	"net/http"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/requests"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

func (p Primary) addLeaf(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
	log.Debug("handling add-leaf request")
	req, domain, err := requests.LeafRequestFromHTTP(ctx, r, p.TokenVerifier)
	if err != nil {
		return http.StatusBadRequest, err
	}
	keyHash := crypto.HashBytes(req.PublicKey[:])
	relax := p.RateLimiter.AccessAllowed(domain, &keyHash)
	if relax == nil {
		if domain == nil {
			return http.StatusTooManyRequests, fmt.Errorf("rate-limit for unknown domain exceeded")
		}
		return http.StatusTooManyRequests, fmt.Errorf("rate-limit for domain %q exceeded", *domain)
	}
	leaf, err := req.Verify()
	if err != nil {
		return http.StatusForbidden, err
	}

	sth := p.Stateman.NextTreeHead()
	status, err := p.DbClient.AddLeaf(ctx,
		&leaf, sth.Size)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if status.AlreadyExists {
		relax()
	}
	if status.IsSequenced {
		return http.StatusOK, nil
	} else {
		return http.StatusAccepted, nil
	}
}

func (p Primary) addCosignature(_ context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
	log.Debug("handling add-cosignature request")
	var cs types.Cosignature
	if err := cs.FromASCII(r.Body); err != nil {
		return http.StatusBadRequest, err
	}
	switch err := p.Stateman.AddCosignature(&cs); err {
	case nil:
		return http.StatusOK, nil
	case state.ErrUnknownWitness:
		return http.StatusForbidden, err
	default:
		return http.StatusBadRequest, err
	}
}

func (p Primary) getNextTreeHead(ctx context.Context, w http.ResponseWriter, _ *http.Request) (int, error) {
	log.Debug("handling get-tree-head-to-cosign request")
	sth := p.Stateman.NextTreeHead()
	if err := sth.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func (p Primary) getTreeHead(_ context.Context, w http.ResponseWriter, _ *http.Request) (int, error) {
	log.Debug("handling get-tree-head-cosigned request")
	cth := p.Stateman.CosignedTreeHead()
	if err := cth.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func (p Primary) getConsistencyProof(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
	log.Debug("handling get-consistency-proof request")
	req, err := requests.ConsistencyProofRequestFromHTTP(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	curTree := p.Stateman.NextTreeHead()
	if req.NewSize > curTree.TreeHead.Size {
		return http.StatusBadRequest, fmt.Errorf("new_size %d outside of current tree, size %d",
			req.NewSize, curTree.TreeHead.Size)
	}

	proof, err := p.DbClient.GetConsistencyProof(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := proof.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func (p Primary) getInclusionProof(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
	log.Debug("handling get-inclusion-proof request")
	req, err := requests.InclusionProofRequestFromHTTP(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	curTree := p.Stateman.NextTreeHead()
	if req.Size > curTree.TreeHead.Size {
		return http.StatusBadRequest, fmt.Errorf("tree_size outside of current tree")
	}

	switch proof, err := p.DbClient.GetInclusionProof(ctx, req); err {
	case db.ErrNotIncluded:
		return http.StatusNotFound, err
	case nil:
		if err := proof.ToASCII(w); err != nil {
			return http.StatusInternalServerError, err
		}
		return http.StatusOK, nil
	default:
		return http.StatusInternalServerError, err
	}
}

func getLeavesGeneral(ctx context.Context, p Primary, w http.ResponseWriter, r *http.Request, doLimitToCurrentTree bool) (int, error) {
	log.Debug("handling get-leaves request")

	maxIndex := uint64(math.MaxUint64)
	if doLimitToCurrentTree {
		curTree := p.Stateman.NextTreeHead()
		treeSize := curTree.TreeHead.Size
		if treeSize == 0 {
			return http.StatusBadRequest, fmt.Errorf("tree is empty")
		}
		maxIndex = treeSize
	}
	req, err := requests.LeavesRequestFromHTTP(r, maxIndex, p.MaxRange)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if req.StartIndex == req.EndIndex {
		return http.StatusNoContent, nil
	}
	leaves, err := p.DbClient.GetLeaves(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if len(leaves) == 0 {
		return http.StatusInternalServerError, fmt.Errorf("internal get leaves returned an empty list")
	}
	if err = types.LeavesToASCII(w, leaves); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func (p Primary) getLeavesExternal(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
	return getLeavesGeneral(ctx, p, w, r, true)
}
