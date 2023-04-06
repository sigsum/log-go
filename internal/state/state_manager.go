package state

import (
	"context"
	"time"

	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/types"
)

// StateManager coordinates access to a nodes tree heads and (co)signatures.
type StateManager interface {
	// SignedTreeHead returns the node's (co)signed tree head
	SignedTreeHead() types.CosignedTreeHead

	// Run peridically rotates the node's to-cosign and cosigned tree heads
	Run(context.Context, []policy.Entity, time.Duration)
}
