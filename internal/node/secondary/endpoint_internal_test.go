package secondary

import (
	"context"
	"fmt"
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
	Error error
}

func (ts *TestSigner) Public() crypto.PublicKey {
	return crypto.PublicKey{}
}

func (ts *TestSigner) Sign(_ []byte) (crypto.Signature, error) {
	return crypto.Signature{}, ts.Error
}

func TestGetSecondaryTreeHead(t *testing.T) {
	publicKey, signer, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []struct {
		desc          string
		trillianTHErr error
		signErr       error
	}{
		{
			desc:          "trillian GetTreeHead error",
			trillianTHErr: fmt.Errorf("mocked error"),
		},
		{
			desc:    "signer error",
			signErr: fmt.Errorf("mocked error"),
		},
		{
			desc: "success",
		},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			trillianClient := db.NewMockClient(ctrl)
			trillianClient.EXPECT().GetTreeHead(gomock.Any()).Return(types.TreeHead{}, tbl.trillianTHErr)

			signer := crypto.Signer(signer)
			if tbl.signErr != nil {
				signer = &TestSigner{Error: tbl.signErr}
			}
			node := Secondary{
				DbClient: trillianClient,
				Signer:   signer,
			}

			sth, err := node.GetSecondaryTreeHead(context.Background())
			if tbl.trillianTHErr != nil || tbl.signErr != nil {
				if err == nil {
					t.Errorf("%s: expected error, got none", tbl.desc)
				}
			} else {
				if err != nil {
					t.Errorf("%s: GetSecondaryTreeHead failed: %v\n", tbl.desc, err)
				} else if !sth.Verify(&publicKey) {
					t.Errorf("%s: Invalid tree head signature", tbl.desc)
				}
			}
		}()
	}
}
