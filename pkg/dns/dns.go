package dns

import (
	"context"
	"fmt"
	"net"

	"encoding/hex"

	"git.sigsum.org/sigsum-log-go/pkg/types"
)

// Verifier can verify that a domain name is aware of a public key
type Verifier interface {
	Verify(ctx context.Context, name string, key *[types.VerificationKeySize]byte) error
}

// DefaultResolver implements the Verifier interface with Go's default resolver
type DefaultResolver struct {
	resolver net.Resolver
}

func NewDefaultResolver() Verifier {
	return &DefaultResolver{}
}

func (dr *DefaultResolver) Verify(ctx context.Context, name string, key *[types.VerificationKeySize]byte) error {
	rsp, err := dr.resolver.LookupTXT(ctx, name)
	if err != nil {
		return fmt.Errorf("domain name look-up failed: %v", err)
	}

	want := hex.EncodeToString(types.Hash(key[:])[:])
	for _, got := range rsp {
		if got == want {
			return nil
		}
	}
	return fmt.Errorf("%q is not aware of key hash %q", name, want)
}
