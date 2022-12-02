package primary

// This file implements external HTTP handler callbacks for primary nodes.

import (
	"context"
	"fmt"
	"net/http"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/requests"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

func addLeaf(p Primary) func(context.Context, http.ResponseWriter, *http.Request) (int, error) {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
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
			return http.StatusBadRequest, err
		}

		sth := p.Stateman.ToCosignTreeHead()
		status, err := p.DbClient.AddLeaf(ctx,
			&leaf, sth.TreeSize)
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
}

func addCosignature(p Primary) func(context.Context, http.ResponseWriter, *http.Request) (int, error) {
	return func(_ context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
		log.Debug("handling add-cosignature request")
		req, err := requests.CosignatureRequestFromHTTP(r)
		if err != nil {
			return http.StatusBadRequest, err
		}
		if err := p.Stateman.AddCosignature(&req.KeyHash, &req.Signature); err != nil {
			return http.StatusBadRequest, err
		}
		return http.StatusOK, nil
	}
}

func getTreeHeadToCosign(p Primary) func(context.Context, http.ResponseWriter, *http.Request) (int, error) {
	return func(ctx context.Context, w http.ResponseWriter, _ *http.Request) (int, error) {
		log.Debug("handling get-tree-head-to-cosign request")
		sth := p.Stateman.ToCosignTreeHead()
		if err := sth.ToASCII(w); err != nil {
			return http.StatusInternalServerError, err
		}
		return http.StatusOK, nil
	}
}

func getTreeHeadCosigned(p Primary) func(context.Context, http.ResponseWriter, *http.Request) (int, error) {
	return func(_ context.Context, w http.ResponseWriter, _ *http.Request) (int, error) {
		log.Debug("handling get-tree-head-cosigned request")
		cth := p.Stateman.CosignedTreeHead()
		if err := cth.ToASCII(w); err != nil {
			return http.StatusInternalServerError, err
		}
		return http.StatusOK, nil
	}
}

func getConsistencyProof(p Primary) func(context.Context, http.ResponseWriter, *http.Request) (int, error) {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
		log.Debug("handling get-consistency-proof request")
		req, err := requests.ConsistencyProofRequestFromHTTP(r)
		if err != nil {
			return http.StatusBadRequest, err
		}

		curTree := p.Stateman.ToCosignTreeHead()
		if req.NewSize > curTree.TreeHead.TreeSize {
			return http.StatusBadRequest, fmt.Errorf("new_size %d outside of current tree, size %d",
				req.NewSize, curTree.TreeHead.TreeSize)
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
}

func getInclusionProof(p Primary) func(context.Context, http.ResponseWriter, *http.Request) (int, error) {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
		log.Debug("handling get-inclusion-proof request")
		req, err := requests.InclusionProofRequestFromHTTP(r)
		if err != nil {
			return http.StatusBadRequest, err
		}

		curTree := p.Stateman.ToCosignTreeHead()
		if req.TreeSize > curTree.TreeHead.TreeSize {
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
}

func getLeavesGeneral(ctx context.Context, p Primary, w http.ResponseWriter, r *http.Request, doLimitToCurrentTree bool) (int, error) {
	log.Debug("handling get-leaves request")
	// TODO: Use math.MaxUint64, available from golang 1.17.
	maxIndex := ^uint64(0)
	if doLimitToCurrentTree {
		curTree := p.Stateman.ToCosignTreeHead()
		treeSize := curTree.TreeHead.TreeSize
		if treeSize == 0 {
			return http.StatusBadRequest, fmt.Errorf("tree is empty")
		}
		maxIndex = treeSize
	}
	req, err := requests.LeavesRequestFromHTTP(r, maxIndex, uint64(p.MaxRange))
	if err != nil {
		return http.StatusBadRequest, err
	}

	leaves, err := p.DbClient.GetLeaves(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err = types.LeavesToASCII(w, leaves); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getLeavesExternal(p Primary) func(context.Context, http.ResponseWriter, *http.Request) (int, error) {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) (int, error) {
		return getLeavesGeneral(ctx, p, w, r, true)
	}
}
