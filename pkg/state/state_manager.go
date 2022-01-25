package state

import (
	"context"

	"git.sigsum.org/sigsum-lib-go/pkg/types"
)

// StateManager coordinates access to a log's tree heads and (co)signatures.
type StateManager interface {
	// ToCosignTreeHead returns the log's to-cosign tree head
	ToCosignTreeHead(context.Context) (*types.SignedTreeHead, error)

	// CosignedTreeHead returns the log's cosigned tree head
	CosignedTreeHead(context.Context) (*types.CosignedTreeHead, error)

	// AddCosignature verifies that a cosignature is valid for the to-cosign
	// tree head before adding it
	AddCosignature(context.Context, *types.PublicKey, *types.Signature) error

	// Run peridically rotates the log's to-cosign and cosigned tree heads
	Run(context.Context)
}

// event is a verified cosignature request
type event struct {
	keyHash     *types.Hash
	cosignature *types.Signature
}
