package secondary

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"sigsum.org/log-go/internal/mocks/db"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

// TestSigner implements the signer interface.  It can be used to mock
// an Ed25519 signer that always return the same public key,
// signature, and error.
// NOTE: Code duplication with internal/state/single_test.go
type TestSigner struct {
	PublicKey crypto.PublicKey
	Signature crypto.Signature
	Error     error
}

func (ts *TestSigner) Public() crypto.PublicKey {
	return ts.PublicKey
}

func (ts *TestSigner) Sign(_ []byte) (crypto.Signature, error) {
	return ts.Signature, ts.Error
}

var (
	testTH = types.TreeHead{
		Size:     0,
		RootHash: crypto.HashBytes([]byte("root hash")),
	}
	testSignerFailing    = TestSigner{crypto.PublicKey{}, crypto.Signature{}, fmt.Errorf("mocked error")}
	testSignerSucceeding = TestSigner{crypto.PublicKey{}, crypto.Signature{}, nil}
)

func TestGetTreeHeadToCosign(t *testing.T) {
	for _, tbl := range []struct {
		desc          string
		trillianTHErr error
		trillianTHRet types.TreeHead
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
			trillianTHRet: testTH,
			signer:        &testSignerFailing,
			httpStatus:    http.StatusInternalServerError,
		},
		{
			desc:          "success",
			trillianTHRet: testTH,
			signer:        &testSignerSucceeding,
			httpStatus:    http.StatusOK,
		},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			trillianClient := db.NewMockClient(ctrl)
			trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(tbl.trillianTHRet, tbl.trillianTHErr)

			node := Secondary{
				Config:   testConfig,
				DbClient: trillianClient,
				Signer:   tbl.signer,
			}

			// Create HTTP request
			url := types.EndpointGetNextTreeHead.Path("http://example.com")
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			node.InternalHTTPMux("").ServeHTTP(w, req)
			if got, want := w.Code, tbl.httpStatus; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, tbl.desc)
			}
		}()
	}
}
