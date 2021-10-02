package instance

import (
	"context"
	"net/http"

	"github.com/golang/glog"
)

func addLeaf(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling add-entry request")
	req, err := i.leafRequestFromHTTP(ctx, r)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if err := i.Client.AddLeaf(ctx, req); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func addCosignature(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling add-cosignature request")
	req, err := i.cosignatureRequestFromHTTP(r)
	if err != nil {
		return http.StatusBadRequest, err
	}
	vk := i.Witnesses[*req.KeyHash]
	if err := i.Stateman.AddCosignature(ctx, &vk, req.Signature); err != nil {
		return http.StatusBadRequest, err
	}
	return http.StatusOK, nil
}

func getTreeHeadLatest(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-tree-head-latest request")
	sth, err := i.Stateman.Latest(ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := sth.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getTreeHeadToSign(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-tree-head-to-sign request")
	sth, err := i.Stateman.ToSign(ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := sth.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getTreeHeadCosigned(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-tree-head-cosigned request")
	cth, err := i.Stateman.Cosigned(ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := cth.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getConsistencyProof(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-consistency-proof request")
	req, err := i.consistencyProofRequestFromHTTP(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	proof, err := i.Client.GetConsistencyProof(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := proof.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getInclusionProof(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-proof-by-hash request")
	req, err := i.inclusionProofRequestFromHTTP(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	proof, err := i.Client.GetInclusionProof(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := proof.MarshalASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getLeaves(ctx context.Context, i *Instance, w http.ResponseWriter, r *http.Request) (int, error) {
	glog.V(3).Info("handling get-leaves request")
	req, err := i.leavesRequestFromHTTP(r)
	if err != nil {
		return http.StatusBadRequest, err
	}

	leaves, err := i.Client.GetLeaves(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	for _, leaf := range *leaves {
		if err := leaf.MarshalASCII(w); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	return http.StatusOK, nil
}
