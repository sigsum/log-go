package primary

// This file implements external HTTP handler callbacks for primary nodes.

import (
	"context"
	"fmt"
	"net/http"

	"sigsum.org/log-go/internal/node/handler"
	"sigsum.org/log-go/internal/requests"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

func addLeaf(ctx context.Context, c handler.Config, w http.ResponseWriter, r *http.Request) (int, error) {
	p := c.(Primary)
	log.Debug("handling add-leaf request")
	req, domain, err := requests.LeafRequestFromHTTP(ctx, r, p.TokenVerifier)
	if err != nil {
		return http.StatusBadRequest, err
	}
	relax := p.RateLimiter.AccessAllowed(domain, &req.PublicKey)
	if relax == nil {
		if domain == nil {
			return http.StatusTooManyRequests, fmt.Errorf("rate-limit for unknown domain exceeded")
		} else {
			return http.StatusTooManyRequests, fmt.Errorf("rate-limit for domain %q exceeded", *domain)
		}
	}
	if !types.VerifyLeafMessage(&req.PublicKey, req.Message[:], &req.Signature) {
		return http.StatusBadRequest, fmt.Errorf("invalid signature")
	}

	leaf := types.Leaf{
		Checksum:  crypto.HashBytes(req.Message[:]),
		Signature: req.Signature,
		KeyHash:   crypto.HashBytes(req.PublicKey[:]),
	}

	sth := p.Stateman.ToCosignTreeHead()
	status, err := p.TrillianClient.AddLeaf(ctx,
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

func addCosignature(_ context.Context, c handler.Config, w http.ResponseWriter, r *http.Request) (int, error) {
	p := c.(Primary)
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

func getTreeHeadToCosign(ctx context.Context, c handler.Config, w http.ResponseWriter, _ *http.Request) (int, error) {
	p := c.(Primary)
	log.Debug("handling get-tree-head-to-cosign request")
	sth := p.Stateman.ToCosignTreeHead()
	if err := sth.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getTreeHeadCosigned(_ context.Context, c handler.Config, w http.ResponseWriter, _ *http.Request) (int, error) {
	p := c.(Primary)
	log.Debug("handling get-tree-head-cosigned request")
	cth, err := p.Stateman.CosignedTreeHead()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := cth.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getConsistencyProof(ctx context.Context, c handler.Config, w http.ResponseWriter, r *http.Request) (int, error) {
	p := c.(Primary)
	log.Debug("handling get-consistency-proof request")
	req, err := requests.ConsistencyProofRequestFromHTTP(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	curTree := p.Stateman.ToCosignTreeHead()
	if req.NewSize > curTree.TreeHead.TreeSize {
		return http.StatusBadRequest, fmt.Errorf("new_size outside of current tree")
	}

	proof, err := p.TrillianClient.GetConsistencyProof(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := proof.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getInclusionProof(ctx context.Context, c handler.Config, w http.ResponseWriter, r *http.Request) (int, error) {
	p := c.(Primary)
	log.Debug("handling get-inclusion-proof request")
	req, err := requests.InclusionProofRequestFromHTTP(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	curTree := p.Stateman.ToCosignTreeHead()
	if req.TreeSize > curTree.TreeHead.TreeSize {
		return http.StatusBadRequest, fmt.Errorf("tree_size outside of current tree")
	}

	proof, err := p.TrillianClient.GetInclusionProof(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := proof.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getLeavesGeneral(ctx context.Context, c handler.Config, w http.ResponseWriter, r *http.Request, doLimitToCurrentTree bool) (int, error) {
	p := c.(Primary)
	log.Debug("handling get-leaves request")
	// TODO: Use math.MaxUint64, available from golang 1.17.
	maxIndex := ^uint64(0)
	if doLimitToCurrentTree {
		curTree := p.Stateman.ToCosignTreeHead()
		treeSize := curTree.TreeHead.TreeSize
		if treeSize == 0 {
			return http.StatusBadRequest, fmt.Errorf("tree is empty")
		}
		maxIndex = treeSize - 1
	}
	req, err := requests.LeavesRequestFromHTTP(r, maxIndex, uint64(p.MaxRange))
	if err != nil {
		return http.StatusBadRequest, err
	}

	leaves, err := p.TrillianClient.GetLeaves(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err = types.LeavesToASCII(w, *leaves); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getLeavesExternal(ctx context.Context, c handler.Config, w http.ResponseWriter, r *http.Request) (int, error) {
	return getLeavesGeneral(ctx, c, w, r, true)
}
