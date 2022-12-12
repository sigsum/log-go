package state

import (
	"fmt"
	"os"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

type sthFile struct {
	name string
}

func (s sthFile) Load(pub *crypto.PublicKey) (types.SignedTreeHead, error) {
	f, err := os.Open(s.name)
	if err != nil {
		return types.SignedTreeHead{}, err
	}
	defer f.Close()
	var sth types.SignedTreeHead
	if err := sth.FromASCII(f); err != nil {
		return types.SignedTreeHead{}, err
	}
	if !sth.VerifyLogSignature(pub) {
		return types.SignedTreeHead{}, fmt.Errorf("invalid signature in file %q", s.name)
	}
	return sth, nil
}

func (s sthFile) Store(sth *types.SignedTreeHead) error {
	tmpName := s.name + ".new"
	f, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	// In case Close is called explictly below, the deferred call
	// will fail, and error ignored.
	defer f.Close()

	if err := sth.ToASCII(f); err != nil {
		return err
	}
	// Explicit Close, to check for error.
	if err := f.Close(); err != nil {
		return err
	}
	// Atomically replace old file with new.
	return os.Rename(tmpName, s.name)
}
