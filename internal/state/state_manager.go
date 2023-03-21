package state

import (
	"context"
	"time"

	"sigsum.org/sigsum-go/pkg/types"
)

// StateManager coordinates access to a nodes tree heads and (co)signatures.
type StateManager interface {
	// SignedTreeHead returns the node's sign tree head
	SignedTreeHead() types.SignedTreeHead

	// Run peridically rotates the node's to-cosign and cosigned tree heads
	Run(context.Context, time.Duration)
}
