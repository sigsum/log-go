package secondary

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	mocksDB "git.sigsum.org/log-go/internal/mocks/db"
	"git.sigsum.org/log-go/internal/node/handler"
	"git.sigsum.org/sigsum-go/pkg/merkle"
	"git.sigsum.org/sigsum-go/pkg/types"
	"github.com/golang/mock/gomock"
)

// TestSigner implements the signer interface.  It can be used to mock
// an Ed25519 signer that always return the same public key,
// signature, and error.
// NOTE: Code duplication with internal/state/single_test.go
type TestSigner struct {
	PublicKey [ed25519.PublicKeySize]byte
	Signature [ed25519.SignatureSize]byte
	Error     error
}

func (ts *TestSigner) Public() crypto.PublicKey {
	return ed25519.PublicKey(ts.PublicKey[:])
}

func (ts *TestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ts.Signature[:], ts.Error
}

var (
	testTH = types.TreeHead{
		Timestamp: 0,
		TreeSize:  0,
		RootHash:  *merkle.HashFn([]byte("root hash")),
	}
	testSignerFailing    = TestSigner{types.PublicKey{}, types.Signature{}, fmt.Errorf("mocked error")}
	testSignerSucceeding = TestSigner{types.PublicKey{}, types.Signature{}, nil}
)

func TestGetTreeHeadToCosign(t *testing.T) {
	for _, tbl := range []struct {
		desc          string
		trillianTHErr error
		trillianTHRet *types.TreeHead
		signer        crypto.Signer
		httpStatus    int
	}{
		{
			desc:          "trillian GetTreeHead error",
			trillianTHErr: fmt.Errorf("mocked error"),
			httpStatus:    http.StatusInternalServerError,
		},
		{
			desc:          "signer error",
			trillianTHRet: &testTH,
			signer:        &testSignerFailing,
			httpStatus:    http.StatusInternalServerError,
		},
		{
			desc:          "success",
			trillianTHRet: &testTH,
			signer:        &testSignerSucceeding,
			httpStatus:    http.StatusOK,
		},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			trillianClient := mocksDB.NewMockClient(ctrl)
			trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(tbl.trillianTHRet, tbl.trillianTHErr)

			node := Secondary{
				Config:         testConfig,
				TrillianClient: trillianClient,
				Signer:         tbl.signer,
			}

			// Create HTTP request
			url := types.EndpointAddLeaf.Path("http://example.com", node.Prefix())
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			mustHandleInternal(t, node, types.EndpointGetTreeHeadToCosign).ServeHTTP(w, req)
			if got, want := w.Code, tbl.httpStatus; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, tbl.desc)
			}
		}()
	}
}

func mustHandleInternal(t *testing.T, s Secondary, e types.Endpoint) handler.Handler {
	for _, h := range s.InternalHTTPHandlers() {
		if h.Endpoint == e {
			return h
		}
	}
	t.Fatalf("must handle endpoint: %v", e)
	return handler.Handler{}
}
