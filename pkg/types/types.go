package types

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
	HashSize            = sha256.Size
	SignatureSize       = ed25519.SignatureSize
	VerificationKeySize = ed25519.PublicKeySize

	EndpointAddLeaf             = Endpoint("add-leaf")
	EndpointAddCosignature      = Endpoint("add-cosignature")
	EndpointGetTreeHeadLatest   = Endpoint("get-tree-head-latest")
	EndpointGetTreeHeadToSign   = Endpoint("get-tree-head-to-sign")
	EndpointGetTreeHeadCosigned = Endpoint("get-tree-head-cosigned")
	EndpointGetInclusionProof   = Endpoint("get-inclusion-proof")
	EndpointGetConsistencyProof = Endpoint("get-consistency-proof")
	EndpointGetLeaves           = Endpoint("get-leaves")
)

// Endpoint is a named HTTP API endpoint
type Endpoint string

// Path joins a number of components to form a full endpoint path.  For example,
// EndpointAddLeaf.Path("example.com", "st/v0") -> example.com/st/v0/add-leaf.
func (e Endpoint) Path(components ...string) string {
	return strings.Join(append(components, string(e)), "/")
}

type Leaf struct {
	Message
	SigIdent
}

type Message struct {
	ShardHint uint64
	Checksum  *[HashSize]byte
}

type SigIdent struct {
	Signature *[SignatureSize]byte
	KeyHash   *[HashSize]byte
}

type SignedTreeHead struct {
	TreeHead
	Signature *[SignatureSize]byte
}

type CosignedTreeHead struct {
	SignedTreeHead
	SigIdent []*SigIdent
}

type TreeHead struct {
	Timestamp uint64
	TreeSize  uint64
	RootHash  *[HashSize]byte
	KeyHash   *[HashSize]byte
}

type ConsistencyProof struct {
	NewSize uint64
	OldSize uint64
	Path    []*[HashSize]byte
}

type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      []*[HashSize]byte
}

type LeafList []*Leaf

type ConsistencyProofRequest struct {
	NewSize uint64
	OldSize uint64
}

type InclusionProofRequest struct {
	LeafHash *[HashSize]byte
	TreeSize uint64
}

type LeavesRequest struct {
	StartSize uint64
	EndSize   uint64
}

type LeafRequest struct {
	Message
	Signature       *[SignatureSize]byte
	VerificationKey *[VerificationKeySize]byte
	DomainHint      string
}

type CosignatureRequest struct {
	SigIdent
}

// Sign signs the tree head using the log's signature scheme
func (th *TreeHead) Sign(signer crypto.Signer) (*SignedTreeHead, error) {
	sig, err := signer.Sign(nil, th.Marshal(), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("Sign: %v", err)
	}

	sth := &SignedTreeHead{
		TreeHead:  *th,
		Signature: &[SignatureSize]byte{},
	}
	copy(sth.Signature[:], sig)
	return sth, nil
}

// Verify verifies the tree head signature using the log's signature scheme
func (th *TreeHead) Verify(vk *[VerificationKeySize]byte, sig *[SignatureSize]byte) error {
	if !ed25519.Verify(ed25519.PublicKey(vk[:]), th.Marshal(), sig[:]) {
		return fmt.Errorf("invalid tree head signature")
	}
	return nil
}

// Verify checks if a leaf is included in the log
func (p *InclusionProof) Verify(leaf *Leaf, th *TreeHead) error { // TODO
	return nil
}

// Verify checks if two tree heads are consistent
func (p *ConsistencyProof) Verify(oldTH, newTH *TreeHead) error { // TODO
	return nil
}
