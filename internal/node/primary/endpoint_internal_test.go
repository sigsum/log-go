package primary

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

var (
	testTH = types.TreeHead{
		Size:     0,
		RootHash: crypto.HashBytes([]byte("root hash")),
	}
)

func TestGetTreeHeadUnsigned(t *testing.T) {
	for _, table := range []struct {
		description string
		expect      bool           // set if a mock answer is expected
		rsp         types.TreeHead // tree head from Trillian client
		err         error          // error from Trillian client
		wantCode    int            // HTTP status ok
	}{
		{
			description: "invalid: backend failure",
			expect:      true,
			err:         fmt.Errorf("something went wrong"),
			wantCode:    http.StatusInternalServerError,
		},
		{
			description: "valid",
			expect:      true,
			rsp:         testTH,
			wantCode:    http.StatusOK,
		},
	} {
		// Run deferred functions at the end of each iteration
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			trillianClient := db.NewMockClient(ctrl)
			trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(table.rsp, table.err)

			node := Primary{
				Config:   testConfig,
				DbClient: trillianClient,
			}

			// Create HTTP request
			url := types.EndpointGetTreeHeadUnsigned.Path("http://example.com")
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			// Run HTTP request
			w := httptest.NewRecorder()
			node.InternalHTTPMux("").ServeHTTP(w, req)
			if got, want := w.Code, table.wantCode; got != want {
				t.Errorf("got HTTP status code %v but wanted %v in test %q", got, want, table.description)
			}
		}()
	}
}
