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

// Leaf is the log's Merkle tree leaf.
type Leaf struct {
	Message
	SigIdent
}

// Message is composed of a shard hint and a checksum.  The submitter selects
// these values to fit the log's shard interval and the opaque data in question.
type Message struct {
	ShardHint uint64
	Checksum  *[HashSize]byte
}

// SigIdent is composed of a signature-signer pair.  The signature is computed
// over the Trunnel-serialized leaf message.  KeyHash identifies the signer.
type SigIdent struct {
	Signature *[SignatureSize]byte
	KeyHash   *[HashSize]byte
}

// SignedTreeHead is composed of a tree head and a list of signature-signer
// pairs.  Each signature is computed over the Trunnel-serialized tree head.
type SignedTreeHead struct {
	TreeHead
	SigIdent []*SigIdent
}

// TreeHead is the log's tree head.
type TreeHead struct {
	Timestamp uint64
	TreeSize  uint64
	RootHash  *[HashSize]byte
}

// ConsistencyProof is a consistency proof that proves the log's append-only
// property.
type ConsistencyProof struct {
	NewSize uint64
	OldSize uint64
	Path    []*[HashSize]byte
}

// InclusionProof is an inclusion proof that proves a leaf is included in the
// log.
type InclusionProof struct {
	TreeSize  uint64
	LeafIndex uint64
	Path      []*[HashSize]byte
}

// LeafList is a list of leaves
type LeafList []*Leaf

// ConsistencyProofRequest is a get-consistency-proof request
type ConsistencyProofRequest struct {
	NewSize uint64
	OldSize uint64
}

// InclusionProofRequest is a get-proof-by-hash request
type InclusionProofRequest struct {
	LeafHash *[HashSize]byte
	TreeSize uint64
}

// LeavesRequest is a get-leaves request
type LeavesRequest struct {
	StartSize uint64
	EndSize   uint64
}

// LeafRequest is an add-leaf request
type LeafRequest struct {
	Message
	Signature       *[SignatureSize]byte
	VerificationKey *[VerificationKeySize]byte
	DomainHint      string
}

// CosignatureRequest is an add-cosignature request
type CosignatureRequest struct {
	SigIdent
}

// Sign signs the tree head using the log's signature scheme
func (th *TreeHead) Sign(signer crypto.Signer) (*SignedTreeHead, error) {
	sig, err := signer.Sign(nil, th.Marshal(), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("Sign: %v", err)
	}

	sigident := SigIdent{
		KeyHash:   Hash(signer.Public().(ed25519.PublicKey)[:]),
		Signature: &[SignatureSize]byte{},
	}
	copy(sigident.Signature[:], sig)
	return &SignedTreeHead{
		TreeHead: *th,
		SigIdent: []*SigIdent{
			&sigident,
		},
	}, nil
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
