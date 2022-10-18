package requests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	mocksDNS "sigsum.org/log-go/internal/mocks/dns"
	"sigsum.org/sigsum-go/pkg/merkle"
	sigsumreq "sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
	"github.com/golang/mock/gomock"
)

func TestLeafRequestFromHTTP(t *testing.T) {
	st := uint64(10)
	dh := "_sigsum_v0.example.org"
	msg := merkle.Hash{}
	var pub types.PublicKey
	b, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("must generate key pair: %v", err)
	}
	copy(pub[:], b)

	sign := func(sh uint64, msg merkle.Hash) *types.Signature {
		stm := types.Statement{sh, *merkle.HashFn(msg[:])}
		sig, err := stm.Sign(priv)
		if err != nil {
			t.Fatalf("must sign: %v", err)
		}
		return sig
	}
	input := func(sh uint64, msg merkle.Hash, badSig bool) io.Reader {
		sig := sign(sh, msg)[:]
		if badSig {
			msg[0] += 1 // use a different message
		}
		str := fmt.Sprintf("shard_hint=%d\n", sh)
		str += fmt.Sprintf("message=%x\n", msg[:])
		str += fmt.Sprintf("signature=%x\n", sig[:])
		str += fmt.Sprintf("public_key=%x\n", pub[:])
		str += fmt.Sprintf("domain_hint=%s\n", dh)
		return bytes.NewBufferString(str)
	}

	for _, table := range []struct {
		desc      string
		params    io.Reader
		dnsExpect bool
		dnsErr    error
		wantRsp   *sigsumreq.Leaf
	}{
		{"invalid: parse ascii", bytes.NewBufferString("a=b"), false, nil, nil},
		{"invalid: signature", input(st, msg, true), false, nil, nil},
		{"invalid: shard start", input(st-1, msg, false), false, nil, nil},
		{"invalid: shard end", input(uint64(time.Now().Unix())+1024, msg, false), false, nil, nil},
		{"invalid: mocked dns error", input(st, msg, false), true, fmt.Errorf("mocked dns error"), nil},
		{"valid", input(st, msg, false), true, nil, &sigsumreq.Leaf{st, msg, *sign(st, msg), pub, dh}},
	} {
		func() {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			vf := mocksDNS.NewMockVerifier(ctrl)
			if table.dnsExpect {
				vf.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).Return(table.dnsErr)
			}

			url := types.EndpointAddLeaf.Path("http://example.org/sigsum")
			req, err := http.NewRequest(http.MethodPost, url, table.params)
			if err != nil {
				t.Fatalf("must create http request: %v", err)
			}

			parsedReq, err := LeafRequestFromHTTP(req, st, context.Background(), vf)
			if got, want := err != nil, table.desc != "valid"; got != want {
				t.Errorf("%s: got error %v but wanted %v: %v", table.desc, got, want, err)
			}
			if err != nil {
				return
			}
			if got, want := parsedReq, table.wantRsp; !reflect.DeepEqual(got, want) {
				t.Errorf("%s: got request %v but wanted %v", table.desc, got, want)
			}
		}()
	}
}

func TestCosignatureRequestFromHTTP(t *testing.T) {
	input := func(h merkle.Hash) io.Reader {
		return bytes.NewBufferString(fmt.Sprintf("cosignature=%x\nkey_hash=%x\n", types.Signature{}, h))
	}
	for _, table := range []struct {
		desc    string
		params  io.Reader
		wantRsp *sigsumreq.Cosignature
	}{
		{"invalid: parser error", bytes.NewBufferString("abcd"), nil},
		{"valid", input(*merkle.HashFn([]byte("w1"))), &sigsumreq.Cosignature{types.Signature{}, *merkle.HashFn([]byte("w1"))}},
	} {
		url := types.EndpointAddCosignature.Path("http://example.org/sigsum")
		req, err := http.NewRequest(http.MethodPost, url, table.params)
		if err != nil {
			t.Fatalf("must create http request: %v", err)
		}

		parsedReq, err := CosignatureRequestFromHTTP(req)
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
		{"valid", "2/0000000000000000000000000000000000000000000000000000000000000000", &sigsumreq.InclusionProof{2, merkle.Hash{}}},
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
	maxRange := uint64(10)
	for _, table := range []struct {
		desc    string
		params  string
		wantRsp *sigsumreq.Leaves
	}{
		{"invalid: bad request (parser error)", "a/1", nil},
		{"invalid: bad request (StartSize > EndSize)", "1/0", nil},
		{"valid", "0/10", &sigsumreq.Leaves{0, maxRange - 1}},
	} {
		url := types.EndpointGetLeaves.Path("http://example.org/sigsum/")
		req, err := http.NewRequest(http.MethodGet, url+table.params, nil)
		if err != nil {
			t.Fatalf("must create http request: %v", err)
		}

		parsedReq, err := LeavesRequestFromHTTP(req, ^uint64(0), maxRange)
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
