package state

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	// Needs extended version with CommitIfNotExists, see
	// https://git.glasklar.is/sigsum/dependencies/safefile
	"github.com/dchest/safefile"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

type sthFile struct {
	name string
}

type StartupMode int

const (
	// Use previously saved sth file.
	StartupSaved StartupMode = iota
	// Create sth file representing an empty tree
	StartupEmpty
	// Create sth file representing latest local tree head.
	StartupLocalTree

	StartupFileSuffix = ".startup"
)

func (s sthFile) startupFileName() string {
	return s.name + StartupFileSuffix
}

func parseStartupFile(f io.Reader) (StartupMode, error) {
	// TODO: Add a GetString method to sigsum-go's ascii.Parser?
	scanner := bufio.NewScanner(f)
	// Only read first line.
	if !scanner.Scan() {
		err := scanner.Err()
		if err == nil {
			err = fmt.Errorf("startup file empty")
		}
		return StartupSaved, err
	}

	line := strings.SplitN(
		strings.TrimSpace(scanner.Text()),
		"=", 2)
	if len(line) != 2 || line[0] != "startup" {
		return StartupSaved, fmt.Errorf("missing startup= keyword in startup file")
	}
	mode := line[1]
	switch mode {
	case "empty":
		return StartupEmpty, nil
	case "local-tree":
		return StartupLocalTree, nil
	default:
		return StartupSaved, fmt.Errorf("invalid startup mode %q", mode)
	}
}

func (s sthFile) Startup() (StartupMode, error) {
	name := s.startupFileName()
	f, err := os.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return StartupSaved, nil
	}
	if err != nil {
		return StartupSaved, err
	}
	defer f.Close()
	return parseStartupFile(f)
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
	if !sth.Verify(pub) {
		// Accept version 0 signature, to support upgrades.
		if !sth.VerifyVersion0(pub) {
			return types.SignedTreeHead{}, fmt.Errorf("invalid signature in file %q", s.name)
		}
		log.Info("Loading sth file %q with version 0 tree head signature")
	}
	return sth, nil
}

// Creates a new sth file. Fails if sth file already exists. On
// success, any startup file is deleted.
func (s sthFile) Create(sth *types.SignedTreeHead) error {
	f, err := safefile.Create(s.name, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := sth.ToASCII(f); err != nil {
		return err
	}

	// Ensure startup file is deleted before we create the sth
	// file.
	if err := os.Remove(s.startupFileName()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Atomically create file, or fail if file already exists.
	return f.CommitIfNotExists()
}

func (s sthFile) Store(sth *types.SignedTreeHead) error {
	f, err := safefile.Create(s.name, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := sth.ToASCII(f); err != nil {
		return err
	}

	// Atomically replace old file with new.
	return f.Commit()
}
