package state

import (
	"context"
	"time"

	"sigsum.org/log-go/internal/witness"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/types"
)

// StateManager coordinates access to a nodes tree heads and (co)signatures.
type StateManager interface {
	// Treehead that we have committed to publishing, i.e.,
	// properly replicated, and distributed to witnesses.
	SignedTreeHead() types.SignedTreeHead
	// Currently published tree.
	CosignedTreeHead() types.CosignedTreeHead

	// Run periodically rotates the node's tree heads and queries witnesses.
	Run(context.Context, *policy.Policy, time.Duration, witness.WitnessMetrics)
}
