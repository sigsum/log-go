package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

type Config struct {
	LogID   string
	Timeout time.Duration
}

// Handler implements the http.Handler interface
type Handler struct {
	Config
	// Must always return a valid HTTP status code, for both nil and non-nil error.
	Fun      func(context.Context, http.ResponseWriter, *http.Request) (int, error)
	Endpoint types.Endpoint
	Method   string
}

// Path returns a path that should be configured for this handler
func (h Handler) path(prefix string) string {
	return "/" + h.Endpoint.Path(prefix)
}

func (h Handler) Register(mux *http.ServeMux, prefix string) {
	mux.Handle(h.path(prefix), h)
}

// ServeHTTP is part of the http.Handler interface
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	code := 0
	defer func() {
		end := time.Now().Sub(start).Seconds()
		sc := fmt.Sprintf("%d", code)

		rspcnt.Inc(h.LogID, string(h.Endpoint), sc)
		latency.Observe(end, h.LogID, string(h.Endpoint), sc)
	}()
	reqcnt.Inc(h.LogID, string(h.Endpoint))

	// All responses (success or error) are text/plain.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if h.validMethod(w, r) {
		h.handle(w, r)
	}
}

// validMethod checks that an appropriate HTTP method is used. Error
// handling is based on RFC 7231, see Sections 6.5.5 (Status 405) and
// 6.5.1 (Status 400).
func (h Handler) validMethod(w http.ResponseWriter, r *http.Request) bool {
	if h.Method == r.Method {
		return true
	}

	errorWithCode := func(w http.ResponseWriter, code int) {
		http.Error(w, http.StatusText(code), code)
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut:
		w.Header().Set("Allow", h.Method)
		errorWithCode(w, http.StatusMethodNotAllowed)
	default:
		errorWithCode(w, http.StatusBadRequest)
	}
	return false
}

// handle handles an HTTP request for which the HTTP method is already verified
func (h Handler) handle(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.Timeout)
	defer cancel()

	code, err := h.Fun(ctx, w, r)
	// Log all internal server errors.
	if code == http.StatusInternalServerError {
		log.Error("Internal server error for %s (%q): %v", h.Endpoint, r.URL.Path, err)
	}
	if err != nil {
		if code != http.StatusInternalServerError {
			log.Debug("%s (%q): status %d, %v", h.Endpoint, r.URL.Path, code, err)
		}
		http.Error(w, err.Error(), code)
	} else if code != 200 {
		w.WriteHeader(code)
	}
}
