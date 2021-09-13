package types

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
)

/*
 *
 * MessageASCII methods and helpers
 *
 */
func TestNewMessageASCII(t *testing.T) {
	for _, table := range []struct {
		description string
		input       io.Reader
		wantErr     bool
		wantMap     map[string][]string
	}{
		{
			description: "invalid: not enough lines",
			input:       bytes.NewBufferString(""),
			wantErr:     true,
		},
		{
			description: "invalid: lines must end with new line",
			input:       bytes.NewBufferString("k1=v1\nk2=v2"),
			wantErr:     true,
		},
		{
			description: "invalid: lines must not be empty",
			input:       bytes.NewBufferString("k1=v1\n\nk2=v2\n"),
			wantErr:     true,
		},
		{
			description: "invalid: wrong number of fields",
			input:       bytes.NewBufferString("k1=v1\n"),
			wantErr:     true,
		},
		{
			description: "valid",
			input:       bytes.NewBufferString("k1=v1\nk2=v2\nk2=v3=4\n"),
			wantMap: map[string][]string{
				"k1": []string{"v1"},
				"k2": []string{"v2", "v3=4"},
			},
		},
	} {
		msg, err := NewMessageASCII(table.input, len(table.wantMap))
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := msg.m, table.wantMap; !reflect.DeepEqual(got, want) {
			t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func TestNumField(t *testing.T)           {}
func TestGetStrings(t *testing.T)         {}
func TestGetString(t *testing.T)          {}
func TestGetUint64(t *testing.T)          {}
func TestGetHash(t *testing.T)            {}
func TestGetSignature(t *testing.T)       {}
func TestGetVerificationKey(t *testing.T) {}
func TestDecodeHex(t *testing.T)          {}

/*
 *
 * MarshalASCII methods and helpers
 *
 */
func TestLeafMarshalASCII(t *testing.T) {
	description := "valid: two leaves"
	leafList := []*Leaf{
		&Leaf{
			Message: Message{
				ShardHint: 123,
				Checksum:  testBuffer32,
			},
			SigIdent: SigIdent{
				Signature: testBuffer64,
				KeyHash:   testBuffer32,
			},
		},
		&Leaf{
			Message: Message{
				ShardHint: 456,
				Checksum:  testBuffer32,
			},
			SigIdent: SigIdent{
				Signature: testBuffer64,
				KeyHash:   testBuffer32,
			},
		},
	}
	wantBuf := bytes.NewBufferString(fmt.Sprintf(
		"%s%s%d%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s"+
			"%s%s%d%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s",
		// Leaf 1
		ShardHint, Delim, 123, EOL,
		Checksum, Delim, testBuffer32[:], EOL,
		Signature, Delim, testBuffer64[:], EOL,
		KeyHash, Delim, testBuffer32[:], EOL,
		// Leaf 2
		ShardHint, Delim, 456, EOL,
		Checksum, Delim, testBuffer32[:], EOL,
		Signature, Delim, testBuffer64[:], EOL,
		KeyHash, Delim, testBuffer32[:], EOL,
	))
	buf := bytes.NewBuffer(nil)
	for _, leaf := range leafList {
		if err := leaf.MarshalASCII(buf); err != nil {
			t.Errorf("expected error %v but got %v in test %q: %v", false, true, description, err)
			return
		}
	}
	if got, want := buf.Bytes(), wantBuf.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", string(got), string(want), description)
	}
}

func TestSignedTreeHeadMarshalASCII(t *testing.T) {
	description := "valid"
	sth := &SignedTreeHead{
		TreeHead: TreeHead{
			Timestamp: 123,
			TreeSize:  456,
			RootHash:  testBuffer32,
		},
		SigIdent: []*SigIdent{
			&SigIdent{
				Signature: testBuffer64,
				KeyHash:   testBuffer32,
			},
			&SigIdent{
				Signature: testBuffer64,
				KeyHash:   testBuffer32,
			},
		},
	}
	wantBuf := bytes.NewBufferString(fmt.Sprintf(
		"%s%s%d%s"+"%s%s%d%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s",
		Timestamp, Delim, 123, EOL,
		TreeSize, Delim, 456, EOL,
		RootHash, Delim, testBuffer32[:], EOL,
		Signature, Delim, testBuffer64[:], EOL,
		KeyHash, Delim, testBuffer32[:], EOL,
		Signature, Delim, testBuffer64[:], EOL,
		KeyHash, Delim, testBuffer32[:], EOL,
	))
	buf := bytes.NewBuffer(nil)
	if err := sth.MarshalASCII(buf); err != nil {
		t.Errorf("expected error %v but got %v in test %q", false, true, description)
		return
	}
	if got, want := buf.Bytes(), wantBuf.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", string(got), string(want), description)
	}
}

func TestInclusionProofMarshalASCII(t *testing.T) {
	description := "valid"
	proof := InclusionProof{
		TreeSize:  321,
		LeafIndex: 123,
		Path: []*[HashSize]byte{
			testBuffer32,
			testBuffer32,
		},
	}
	wantBuf := bytes.NewBufferString(fmt.Sprintf(
		"%s%s%d%s"+"%s%s%d%s"+"%s%s%x%s"+"%s%s%x%s",
		TreeSize, Delim, 321, EOL,
		LeafIndex, Delim, 123, EOL,
		InclusionPath, Delim, testBuffer32[:], EOL,
		InclusionPath, Delim, testBuffer32[:], EOL,
	))
	buf := bytes.NewBuffer(nil)
	if err := proof.MarshalASCII(buf); err != nil {
		t.Errorf("expected error %v but got %v in test %q", false, true, description)
		return
	}
	if got, want := buf.Bytes(), wantBuf.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", string(got), string(want), description)
	}
}

func TestConsistencyProofMarshalASCII(t *testing.T) {
	description := "valid"
	proof := ConsistencyProof{
		NewSize: 321,
		OldSize: 123,
		Path: []*[HashSize]byte{
			testBuffer32,
			testBuffer32,
		},
	}
	wantBuf := bytes.NewBufferString(fmt.Sprintf(
		"%s%s%d%s"+"%s%s%d%s"+"%s%s%x%s"+"%s%s%x%s",
		NewSize, Delim, 321, EOL,
		OldSize, Delim, 123, EOL,
		ConsistencyPath, Delim, testBuffer32[:], EOL,
		ConsistencyPath, Delim, testBuffer32[:], EOL,
	))
	buf := bytes.NewBuffer(nil)
	if err := proof.MarshalASCII(buf); err != nil {
		t.Errorf("expected error %v but got %v in test %q", false, true, description)
		return
	}
	if got, want := buf.Bytes(), wantBuf.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", string(got), string(want), description)
	}
}

func TestWriteASCII(t *testing.T) {
}

/*
 *
 * UnmarshalASCII methods and helpers
 *
 */
func TestLeafListUnmarshalASCII(t *testing.T) {}

func TestSignedTreeHeadUnmarshalASCII(t *testing.T) {
	for _, table := range []struct {
		description string
		buf         io.Reader
		wantErr     bool
		wantSth     *SignedTreeHead
	}{
		{
			description: "valid",
			buf: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%d%s"+"%s%s%d%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s",
				Timestamp, Delim, 123, EOL,
				TreeSize, Delim, 456, EOL,
				RootHash, Delim, testBuffer32[:], EOL,
				Signature, Delim, testBuffer64[:], EOL,
				KeyHash, Delim, testBuffer32[:], EOL,
				Signature, Delim, testBuffer64[:], EOL,
				KeyHash, Delim, testBuffer32[:], EOL,
			)),
			wantSth: &SignedTreeHead{
				TreeHead: TreeHead{
					Timestamp: 123,
					TreeSize:  456,
					RootHash:  testBuffer32,
				},
				SigIdent: []*SigIdent{
					&SigIdent{
						Signature: testBuffer64,
						KeyHash:   testBuffer32,
					},
					&SigIdent{
						Signature: testBuffer64,
						KeyHash:   testBuffer32,
					},
				},
			},
		},
	} {
		var sth SignedTreeHead
		err := sth.UnmarshalASCII(table.buf)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := &sth, table.wantSth; !reflect.DeepEqual(got, want) {
			t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func TestInclusionProofUnmarshalASCII(t *testing.T)   {}
func TestConsistencyProofUnmarshalASCII(t *testing.T) {}

func TestInclusionProofRequestUnmarshalASCII(t *testing.T) {
	for _, table := range []struct {
		description string
		buf         io.Reader
		wantErr     bool
		wantReq     *InclusionProofRequest
	}{
		{
			description: "valid",
			buf: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%x%s"+"%s%s%d%s",
				LeafHash, Delim, testBuffer32[:], EOL,
				TreeSize, Delim, 123, EOL,
			)),
			wantReq: &InclusionProofRequest{
				LeafHash: testBuffer32,
				TreeSize: 123,
			},
		},
	} {
		var req InclusionProofRequest
		err := req.UnmarshalASCII(table.buf)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.wantReq; !reflect.DeepEqual(got, want) {
			t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func TestConsistencyProofRequestUnmarshalASCII(t *testing.T) {
	for _, table := range []struct {
		description string
		buf         io.Reader
		wantErr     bool
		wantReq     *ConsistencyProofRequest
	}{
		{
			description: "valid",
			buf: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%d%s"+"%s%s%d%s",
				NewSize, Delim, 321, EOL,
				OldSize, Delim, 123, EOL,
			)),
			wantReq: &ConsistencyProofRequest{
				NewSize: 321,
				OldSize: 123,
			},
		},
	} {
		var req ConsistencyProofRequest
		err := req.UnmarshalASCII(table.buf)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.wantReq; !reflect.DeepEqual(got, want) {
			t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func TestLeavesRequestUnmarshalASCII(t *testing.T) {
	for _, table := range []struct {
		description string
		buf         io.Reader
		wantErr     bool
		wantReq     *LeavesRequest
	}{
		{
			description: "valid",
			buf: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%d%s"+"%s%s%d%s",
				StartSize, Delim, 123, EOL,
				EndSize, Delim, 456, EOL,
			)),
			wantReq: &LeavesRequest{
				StartSize: 123,
				EndSize:   456,
			},
		},
	} {
		var req LeavesRequest
		err := req.UnmarshalASCII(table.buf)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.wantReq; !reflect.DeepEqual(got, want) {
			t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func TestLeafRequestUnmarshalASCII(t *testing.T) {
	for _, table := range []struct {
		description string
		buf         io.Reader
		wantErr     bool
		wantReq     *LeafRequest
	}{
		{
			description: "valid",
			buf: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%d%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%x%s"+"%s%s%s%s",
				ShardHint, Delim, 123, EOL,
				Checksum, Delim, testBuffer32[:], EOL,
				Signature, Delim, testBuffer64[:], EOL,
				VerificationKey, Delim, testBuffer32[:], EOL,
				DomainHint, Delim, "example.com", EOL,
			)),
			wantReq: &LeafRequest{
				Message: Message{
					ShardHint: 123,
					Checksum:  testBuffer32,
				},
				Signature:       testBuffer64,
				VerificationKey: testBuffer32,
				DomainHint:      "example.com",
			},
		},
	} {
		var req LeafRequest
		err := req.UnmarshalASCII(table.buf)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.wantReq; !reflect.DeepEqual(got, want) {
			t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}

func TestCosignatureRequestUnmarshalASCII(t *testing.T) {
	for _, table := range []struct {
		description string
		buf         io.Reader
		wantErr     bool
		wantReq     *CosignatureRequest
	}{
		{
			description: "valid",
			buf: bytes.NewBufferString(fmt.Sprintf(
				"%s%s%x%s"+"%s%s%x%s",
				Signature, Delim, testBuffer64[:], EOL,
				KeyHash, Delim, testBuffer32[:], EOL,
			)),
			wantReq: &CosignatureRequest{
				SigIdent: SigIdent{
					Signature: testBuffer64,
					KeyHash:   testBuffer32,
				},
			},
		},
	} {
		var req CosignatureRequest
		err := req.UnmarshalASCII(table.buf)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.description, err)
		}
		if err != nil {
			continue
		}
		if got, want := &req, table.wantReq; !reflect.DeepEqual(got, want) {
			t.Errorf("got\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.description)
		}
	}
}
