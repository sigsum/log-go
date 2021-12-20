package mocks

import (
	"crypto"
	"crypto/ed25519"
	"io"
)

// TestSign implements the signer interface.  It can be used to mock an Ed25519
// signer that always return the same public key, signature, and error.
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
