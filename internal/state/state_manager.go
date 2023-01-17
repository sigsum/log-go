package state

import (
	"context"
	"time"

	"sigsum.org/sigsum-go/pkg/types"
)

// StateManager coordinates access to a nodes tree heads and (co)signatures.
type StateManager interface {
	// NextHead returns the node's to-cosign tree head
	NextTreeHead() types.SignedTreeHead

	// CosignedTreeHead returns the node's cosigned tree head
	CosignedTreeHead() types.CosignedTreeHead

	// AddCosignature verifies that a cosignature is valid for the to-cosign
	// tree head before adding it
	AddCosignature(*types.Cosignature) error

	// Run peridically rotates the node's to-cosign and cosigned tree heads
	Run(context.Context, time.Duration)
}
