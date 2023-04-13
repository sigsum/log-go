package state

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

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

func (s sthFile) newFileName() string {
	return s.name + ".new"
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

// Writes the sth file to a new temporary file. Caller should move it
// to the final name.
func (s sthFile) write(name string, sth *types.SignedTreeHead) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
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
	return f.Close()
}

// Creates a new sth file. Fails if sth file already exists. On
// success, any startup file is deleted.
func (s sthFile) Create(sth *types.SignedTreeHead) error {
	tmpName := s.newFileName()
	if err := s.write(tmpName, sth); err != nil {
		return err
	}
	defer os.Remove(tmpName) // Ignore error

	// Ensure startup file is deleted before we create the sth
	// file.
	if err := os.Remove(s.startupFileName()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Unlike os.Rename, os.Link fails if the file already exists.
	return os.Link(tmpName, s.name)
}

func (s sthFile) Store(sth *types.SignedTreeHead) error {
	tmpName := s.newFileName()
	if err := s.write(tmpName, sth); err != nil {
		return err
	}
	defer os.Remove(tmpName) // Ignore error

	// Atomically replace old file with new.
	return os.Rename(tmpName, s.name)
}
