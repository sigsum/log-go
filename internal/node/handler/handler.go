package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"git.sigsum.org/sigsum-go/pkg/log"
	"git.sigsum.org/sigsum-go/pkg/types"
)

type Config interface {
	Prefix() string
	LogID() string
	Deadline() time.Duration
}

// Handler implements the http.Handler interface
type Handler struct {
	Config
	Fun      func(context.Context, Config, http.ResponseWriter, *http.Request) (int, error)
	Endpoint types.Endpoint
	Method   string
}

// Path returns a path that should be configured for this handler
func (h Handler) Path() string {
	if len(h.Prefix()) == 0 {
		return h.Endpoint.Path("", "sigsum", "v0")
	}
	return h.Endpoint.Path("", h.Prefix(), "sigsum", "v0")
}

// ServeHTTP is part of the http.Handler interface
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	code := 0
	defer func() {
		end := time.Now().Sub(start).Seconds()
		sc := fmt.Sprintf("%d", code)

		rspcnt.Inc(h.LogID(), string(h.Endpoint), sc)
		latency.Observe(end, h.LogID(), string(h.Endpoint), sc)
	}()
	reqcnt.Inc(h.LogID(), string(h.Endpoint))

	code = h.verifyMethod(w, r)
	if code != 0 {
		return
	}
	h.handle(w, r)
}

// verifyMethod checks that an appropriate HTTP method is used and
// returns 0 if so, or an HTTP status code if not.  Error handling is
// based on RFC 7231, see Sections 6.5.5 (Status 405) and 6.5.1
// (Status 400).
func (h Handler) verifyMethod(w http.ResponseWriter, r *http.Request) int {
	checkHTTPMethod := func(m string) bool {
		return m == http.MethodGet || m == http.MethodPost
	}

	if h.Method == r.Method {
		return 0
	}

	code := http.StatusBadRequest
	if ok := checkHTTPMethod(r.Method); ok {
		w.Header().Set("Allow", h.Method)
		code = http.StatusMethodNotAllowed
	}

	http.Error(w, fmt.Sprintf("error=%s", http.StatusText(code)), code)
	return code
}

// handle handles an HTTP request for which the HTTP method is already verified
func (h Handler) handle(w http.ResponseWriter, r *http.Request) {
	deadline := time.Now().Add(h.Deadline())
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()

	code, err := h.Fun(ctx, h.Config, w, r)
	if err != nil {
		log.Debug("%s/%s: %v", h.Prefix(), h.Endpoint, err)
		http.Error(w, fmt.Sprintf("error=%s", err.Error()), code)
	} else if code != 200 {
		w.WriteHeader(code)
	}
}
