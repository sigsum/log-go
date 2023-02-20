package requests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	mocksToken "sigsum.org/log-go/internal/mocks/submit-token"
	"sigsum.org/sigsum-go/pkg/crypto"
	sigsumreq "sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestLeafRequestFromHTTP(t *testing.T) {
	msg := crypto.Hash{}
	pub, priv, err := crypto.NewKeyPair()
	if err != nil {
		t.Fatalf("must generate key pair: %v", err)
	}

	sign := func(msg crypto.Hash) crypto.Signature {
		sig, err := types.SignLeafMessage(priv, msg[:])
		if err != nil {
			t.Fatalf("must sign: %v", err)
		}
		return sig
	}
	input := func(msg crypto.Hash) io.Reader {
		sig := sign(msg)
		str := fmt.Sprintf("message=%x\n", msg)
		str += fmt.Sprintf("signature=%x\n", sig)
		str += fmt.Sprintf("public_key=%x\n", pub)
		return bytes.NewBufferString(str)
	}

	type token struct {
		domain    string
		signature string
	}
	for _, table := range []struct {
		desc       string
		params     io.Reader
		token      *token
		tokenErr   error
		wantRsp    *sigsumreq.Leaf
		wantDomain bool
	}{
		{"invalid: parse ascii", bytes.NewBufferString("a=b"), nil, nil, nil, false},
		{"invalid: mocked token error", input(msg), &token{"foo.example.com", "aaaa"}, fmt.Errorf("mocked token error"), nil, false},
		{"valid", input(msg), nil, nil, &sigsumreq.Leaf{msg, sign(msg), pub}, false},
		{"valid with domain", input(msg), &token{"foo.example.com", "aaaa"}, nil, &sigsumreq.Leaf{msg, sign(msg), pub}, true},
		{"valid leaf, invalid domain", input(msg), &token{"foo.example.com", "aaaa"}, fmt.Errorf("mocked token error"), nil, false},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			vf := mocksToken.NewMockVerifier(ctrl)
			url := types.EndpointAddLeaf.Path("http://example.org/sigsum")
			req, err := http.NewRequest(http.MethodPost, url, table.params)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}
			if table.token != nil {
				vf.EXPECT().Verify(gomock.Any(), table.token.domain, table.token.signature).Return(table.tokenErr)
				req.Header.Add("sigsum-token", table.token.domain+" "+table.token.signature)
			}

			parsedReq, domain, err := LeafRequestFromHTTP(context.Background(), req, vf)
			if got, want := err != nil, table.wantRsp == nil; got != want {
				t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
			}
			if err != nil {
				return
			}
			if got, want := parsedReq, table.wantRsp; !reflect.DeepEqual(got, want) {
				t.Errorf("%s: got request %v but wanted %v", table.desc, got, want)
			}
			if got, want := domain != nil, table.wantDomain; got != want {
				t.Errorf("%s: got domain %v but wanted %v: %v", table.desc, got, want, domain)
			}
			if table.wantDomain && *domain != table.token.domain {
				t.Errorf("%s: got domain %v but wanted %v", table.desc, table.token.domain, table.wantDomain)
			}

		}()
	}
}

func TestConsistencyProofRequestFromHTTP(t *testing.T) {
	for _, table := range []struct {
		desc    string
		params  string
		wantRsp *sigsumreq.ConsistencyProof
	}{
		{"invalid: bad request (parser error)", "a/1", nil},
		{"invalid: bad request (out of range 1/2)", "0/1", nil},
		{"invalid: bad request (out of range 2/2)", "1/1", nil},
		{"valid", "1/2", &sigsumreq.ConsistencyProof{1, 2}},
	} {
		url := types.EndpointGetConsistencyProof.Path("http://example.org/sigsum/")
		req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
		if err != nil {
			t.Fatalf("must create http request: %v", err)
		}

		parsedReq, err := ConsistencyProofRequestFromHTTP(req)
		if got, want := err != nil, table.desc != "valid"; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
		if err != nil {
			continue
		}
		if got, want := parsedReq, table.wantRsp; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got request %v but wanted %v", table.desc, got, want)
		}
	}
}

func TestInclusionProofRequestFromHTTP(t *testing.T) {
	for _, table := range []struct {
		desc    string
		params  string
		wantRsp *sigsumreq.InclusionProof
	}{
		{"invalid: bad request (parser error)", "a/0000000000000000000000000000000000000000000000000000000000000000", nil},
		{"invalid: bad request (out of range)", "1/0000000000000000000000000000000000000000000000000000000000000000", nil},
		{"valid", "2/0000000000000000000000000000000000000000000000000000000000000000", &sigsumreq.InclusionProof{2, crypto.Hash{}}},
	} {
		url := types.EndpointGetInclusionProof.Path("http://example.org/sigsum/")
		req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
		if err != nil {
			t.Fatalf("must create http request: %v", err)
		}

		parsedReq, err := InclusionProofRequestFromHTTP(req)
		if got, want := err != nil, table.desc != "valid"; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
		if err != nil {
			continue
		}
		if got, want := parsedReq, table.wantRsp; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got request %v but wanted %v", table.desc, got, want)
		}
	}
}

func TestGetLeaves(t *testing.T) {
	maxRange := 10
	for _, table := range []struct {
		desc    string
		params  string
		wantRsp *sigsumreq.Leaves
	}{
		{"invalid: bad request (parser error)", "a/1", nil},
		{"invalid: bad request (StartIndex >= EndIndex)", "1/1", nil},
		{"valid", "0/10", &sigsumreq.Leaves{0, uint64(maxRange)}},
	} {
		url := types.EndpointGetLeaves.Path("http://example.org/sigsum/")
		req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
		if err != nil {
			t.Fatalf("must create http request: %v", err)
		}

		parsedReq, err := LeavesRequestFromHTTP(req, ^uint64(0), maxRange, true)
		if got, want := err != nil, table.desc != "valid"; got != want {
			t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
		}
		if err != nil {
			continue
		}
		if got, want := parsedReq, *table.wantRsp; got != want {
			t.Errorf("%s: got request %v but wanted %v", table.desc, got, want)
		}
	}
}
