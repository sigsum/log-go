package trillian

import (
	"fmt"

	trillian "github.com/google/trillian/types"
	sigsum "git.sigsum.org/sigsum-log-go/pkg/types"
)

func treeHeadFromLogRoot(lr *trillian.LogRootV1) *sigsum.TreeHead {
	var hash [sigsum.HashSize]byte
	th := sigsum.TreeHead{
		Timestamp: uint64(lr.TimestampNanos / 1000 / 1000 / 1000),
		TreeSize:  uint64(lr.TreeSize),
		RootHash:  &hash,
	}
	copy(th.RootHash[:], lr.RootHash)
	return &th
}

func nodePathFromHashes(hashes [][]byte) ([]*[sigsum.HashSize]byte, error) {
	var path []*[sigsum.HashSize]byte
	for _, hash := range hashes {
		if len(hash) != sigsum.HashSize {
			return nil, fmt.Errorf("unexpected hash length: %v", len(hash))
		}

		var h [sigsum.HashSize]byte
		copy(h[:], hash)
		path = append(path, &h)
	}
	return path, nil
}
