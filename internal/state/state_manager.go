package state

import (
	"context"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

// StateManager coordinates access to a nodes tree heads and (co)signatures.
type StateManager interface {
	// ToCosignTreeHead returns the node's to-cosign tree head
	ToCosignTreeHead() *types.SignedTreeHead

	// CosignedTreeHead returns the node's cosigned tree head
	CosignedTreeHead() (*types.CosignedTreeHead, error)

	// AddCosignature verifies that a cosignature is valid for the to-cosign
	// tree head before adding it
	AddCosignature(*crypto.Hash, *crypto.Signature) error

	// Run peridically rotates the node's to-cosign and cosigned tree heads
	Run(context.Context)
}
