package instance

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"git.sigsum.org/sigsum-lib-go/pkg/types"
	"github.com/golang/glog"
)

// Handler implements the http.Handler interface, and contains a reference
// to a sigsum server instance as well as a function that uses it.
type Handler struct {
	Instance *Instance
	Endpoint types.Endpoint
	Method   string
	Handler  func(context.Context, *Instance, http.ResponseWriter, *http.Request) (int, error)
}

// Path returns a path that should be configured for this handler
func (h Handler) Path() string {
	if len(h.Instance.Prefix) == 0 {
		return h.Endpoint.Path("", "sigsum", "v0")
	}
	return h.Endpoint.Path("", h.Instance.Prefix, "sigsum", "v0")
}

// ServeHTTP is part of the http.Handler interface
func (a Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// export prometheus metrics
	var now time.Time = time.Now()
	var statusCode int
	defer func() {
		rspcnt.Inc(a.Instance.LogID, string(a.Endpoint), fmt.Sprintf("%d", statusCode))
		latency.Observe(time.Now().Sub(now).Seconds(), a.Instance.LogID, string(a.Endpoint), fmt.Sprintf("%d", statusCode))
	}()
	reqcnt.Inc(a.Instance.LogID, string(a.Endpoint))

	ctx, cancel := context.WithDeadline(r.Context(), now.Add(a.Instance.Deadline))
	defer cancel()

	if r.Method != a.Method {
		glog.Warningf("%s/%s: got HTTP %s, wanted HTTP %s", a.Instance.Prefix, string(a.Endpoint), r.Method, a.Method)
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}

	statusCode, err := a.Handler(ctx, a.Instance, w, r)
	if err != nil {
		glog.Warningf("handler error %s/%s: %v", a.Instance.Prefix, a.Endpoint, err)
		http.Error(w, fmt.Sprintf("Error=%s\n", err.Error()), statusCode)
	}
}

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
	vk := i.Witnesses[req.KeyHash]
	if err := i.Stateman.AddCosignature(ctx, &vk, &req.Cosignature); err != nil {
		return http.StatusBadRequest, err
	}
	return http.StatusOK, nil
}

func getTreeHeadToCosign(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-tree-head-to-sign request")
	sth, err := i.Stateman.ToCosignTreeHead(ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := sth.ToASCII(w); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

func getTreeHeadCosigned(ctx context.Context, i *Instance, w http.ResponseWriter, _ *http.Request) (int, error) {
	glog.V(3).Info("handling get-tree-head-cosigned request")
	cth, err := i.Stateman.CosignedTreeHead(ctx)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := cth.ToASCII(w); err != nil {
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
	// XXX: check tree size of latest thing we signed?

	proof, err := i.Client.GetConsistencyProof(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := proof.ToASCII(w); err != nil {
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
	// XXX: check tree size of latest thing we signed?

	proof, err := i.Client.GetInclusionProof(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := proof.ToASCII(w); err != nil {
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
	// XXX: check tree size of latest thing we signed?

	leaves, err := i.Client.GetLeaves(ctx, req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	for _, leaf := range *leaves {
		if err := leaf.ToASCII(w); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	return http.StatusOK, nil
}
