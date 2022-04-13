package instance

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"git.sigsum.org/sigsum-go/pkg/types"
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
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	code := 0
	defer func() {
		end := time.Now().Sub(start).Seconds()
		sc := fmt.Sprintf("%d", code)

		rspcnt.Inc(h.Instance.LogID, string(h.Endpoint), sc)
		latency.Observe(end, h.Instance.LogID, string(h.Endpoint), sc)
	}()
	reqcnt.Inc(h.Instance.LogID, string(h.Endpoint))

	code = h.verifyMethod(w, r)
	if code != 0 {
		return
	}
	code = h.handle(w, r)
}

// verifyMethod checks that an appropriate HTTP method is used.  Error handling
// is based on RFC 7231, see Sections 6.5.5 (Status 405) and 6.5.1 (Status 400).
func (h *Handler) verifyMethod(w http.ResponseWriter, r *http.Request) int {
	if h.Method == r.Method {
		return 0
	}

	code := http.StatusBadRequest
	if ok := h.Instance.checkHTTPMethod(r.Method); ok {
		w.Header().Set("Allow", h.Method)
		code = http.StatusMethodNotAllowed
	}

	http.Error(w, fmt.Sprintf("error=%s", http.StatusText(code)), code)
	return code
}

// handle handles an HTTP request for which the HTTP method is already verified
func (h Handler) handle(w http.ResponseWriter, r *http.Request) int {
	deadline := time.Now().Add(h.Instance.Deadline)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()

	code, err := h.Handler(ctx, h.Instance, w, r)
	if err != nil {
		glog.V(3).Infof("%s/%s: %v", h.Instance.Prefix, h.Endpoint, err)
		http.Error(w, fmt.Sprintf("error=%s", err.Error()), code)
	}
	return code
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
