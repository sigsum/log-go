package state

import (
	"context"

	"git.sigsum.org/sigsum-lib-go/pkg/types"
)

// StateManager coordinates access to a log's tree heads and (co)signatures
type StateManager interface {
	Latest(context.Context) (*types.SignedTreeHead, error)
	ToSign(context.Context) (*types.SignedTreeHead, error)
	Cosigned(context.Context) (*types.CosignedTreeHead, error)
	AddCosignature(context.Context, *types.PublicKey, *types.Signature) error
	Run(context.Context)
}
