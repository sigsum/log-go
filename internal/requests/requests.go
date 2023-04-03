package requests

import (
	"context"
	"fmt"
	"net/http"

	sigsumreq "sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit-token"
)

// The string return value, if non-nil, is the verified submitter domain.
func LeafRequestFromHTTP(ctx context.Context, r *http.Request) (*sigsumreq.Leaf, error) {
	var req sigsumreq.Leaf
	if err := req.FromASCII(r.Body); err != nil {
		return nil, fmt.Errorf("parse ascii: %w", err)
	}

	if headerValue := r.Header.Get(token.HeaderName); len(headerValue) > 0 {
		if err := req.FromTokenHeader(headerValue); err != nil {
			return nil, fmt.Errorf("invalid Sigsum-Token value %q: %v\n", headerValue, err)
		}
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
	if req.Size < 2 {
		// Size:0 => not possible to prove inclusion of anything
		// Size:1 => you don't need an inclusion proof (it is always empty)
		return nil, fmt.Errorf("size(%d) must be larger than one", req.Size)
	}
	return &req, nil
}

func LeavesRequestFromHTTP(r *http.Request, maxIndex uint64, maxRange int, strictEnd bool) (sigsumreq.Leaves, error) {
	var req sigsumreq.Leaves
	if err := req.FromURL(r.URL.Path); err != nil {
		return req, fmt.Errorf("parse url: %w", err)
	}

	if req.StartIndex >= req.EndIndex {
		return req, fmt.Errorf("start_index(%d) must be less than end_index(%d)", req.StartIndex, req.EndIndex)
	}
	if req.StartIndex > maxIndex || (strictEnd && req.StartIndex >= maxIndex) {
		return req, fmt.Errorf("start_index(%d) outside of current tree", req.StartIndex)
	}
	if req.EndIndex > maxIndex {
		if strictEnd {
			return req, fmt.Errorf("end_index(%d) outside of current tree", req.EndIndex)
		}
		req.EndIndex = maxIndex
	}
	if req.EndIndex-req.StartIndex > uint64(maxRange) {
		req.EndIndex = req.StartIndex + uint64(maxRange)
	}
	return req, nil
}
