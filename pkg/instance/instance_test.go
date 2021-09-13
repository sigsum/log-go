package instance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.sigsum.org/sigsum-log-go/pkg/types"
)

// TestHandlers check that the expected handlers are configured
func TestHandlers(t *testing.T) {
	endpoints := map[types.Endpoint]bool{
		types.EndpointAddLeaf:             false,
		types.EndpointAddCosignature:      false,
		types.EndpointGetTreeHeadLatest:   false,
		types.EndpointGetTreeHeadToSign:   false,
		types.EndpointGetTreeHeadCosigned: false,
		types.EndpointGetConsistencyProof: false,
		types.EndpointGetInclusionProof:   false,
		types.EndpointGetLeaves:           false,
	}
	i := &Instance{
		Config: testConfig,
	}
	for _, handler := range i.Handlers() {
		if _, ok := endpoints[handler.Endpoint]; !ok {
			t.Errorf("got unexpected endpoint: %s", handler.Endpoint)
		}
		endpoints[handler.Endpoint] = true
	}
	for endpoint, ok := range endpoints {
		if !ok {
			t.Errorf("endpoint %s is not configured", endpoint)
		}
	}
}

// TestServeHTTP checks that invalid HTTP methods are rejected
func TestServeHTTP(t *testing.T) {
	i := &Instance{
		Config: testConfig,
	}
	for _, handler := range i.Handlers() {
		// Prepare invalid HTTP request
		method := http.MethodPost
		if method == handler.Method {
			method = http.MethodGet
		}
		url := handler.Endpoint.Path("http://example.com", i.Prefix)
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatalf("must create HTTP request: %v", err)
		}
		w := httptest.NewRecorder()

		// Check that it is rejected
		handler.ServeHTTP(w, req)
		if got, want := w.Code, http.StatusMethodNotAllowed; got != want {
			t.Errorf("got HTTP code %v but wanted %v for endpoint %q", got, want, handler.Endpoint)
		}
	}
}

func TestPath(t *testing.T) {
	instance := &Instance{
		Config: Config{
			Prefix: "testonly",
		},
	}
	handler := Handler{
		Instance: instance,
		Handler:  addLeaf,
		Endpoint: types.EndpointAddLeaf,
		Method:   http.MethodPost,
	}
	if got, want := handler.Path(), "testonly/sigsum/v0/add-leaf"; got != want {
		t.Errorf("got path %v but wanted %v", got, want)
	}
}
