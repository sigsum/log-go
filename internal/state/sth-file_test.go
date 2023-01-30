package state

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestParseStartup(t *testing.T) {
	// Valid inputs, with and without trailing data.
	for _, table := range []struct {
		input  string
		output startupMode
	}{
		{"startup=empty", startupEmpty},
		{"startup=empty\nother line", startupEmpty},
		{"startup=local-tree\n", startupLocalTree},
	} {
		mode, err := parseStartupFile(bytes.NewBufferString(table.input))
		if err != nil {
			t.Errorf("parsing input %q failed: %v", table.input, err)
		} else if mode != table.output {
			t.Errorf("unexpected result for input %q, got %d, wanted %d",
				table.input, mode, table.output)
		}
	}
	// Invalid inputs.
	for _, table := range []string{
		"", "no-equal", "key=", "startup=",
		"startup=other", "key=foo=bar",
	} {
		mode, err := parseStartupFile(bytes.NewBufferString(table))
		if err == nil {
			t.Errorf("parsing didn't reject invalid input %q, returned mode %d",
				table, mode)
		}
	}
}

func TestStartupNoFile(t *testing.T) {
	withTmpDir(t, func(dir string) {
		sthFile := sthFile{dir + "foo"}
		mode, err := sthFile.Startup()
		if err != nil {
			t.Errorf("error with missing startup file: %v", err)
		} else if mode != startupSaved {
			t.Errorf("got unexpected mode %d with missing startup file",
				mode)
		}
		if os.Geteuid() == 0 {
			t.Skip("skipping test with supposedly unreadable file, because we appear to run with root privileges")
		}
		// Create a file that can't be read.
		os.WriteFile(dir+"foo.startup", []byte{}, 0)
		mode, err = sthFile.Startup()
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("unexpected result for unreadable file, expected permission error, got mode: %d, err: %v",
				mode, err)
		}
	})
}

func TestStore(t *testing.T) {
	withTmpDir(t, func(dir string) {
		sthFile := sthFile{dir + "foo"}
		signer := crypto.NewEd25519Signer(&crypto.PrivateKey{7})
		pub := signer.Public()
		sth0 := mustSignTh(t, &types.TreeHead{}, signer)
		sth1 := mustSignTh(t, &types.TreeHead{Size: 1}, signer)
		invalidSth := sth1
		invalidSth.Size++ // Invalidates signature
		for _, table := range []struct {
			sth    *types.SignedTreeHead
			expErr bool
		}{
			{&sth0, false},
			{&sth1, false},
			{&invalidSth, true},
		} {
			if err := sthFile.Store(table.sth); err != nil {
				t.Fatalf("storing sth, size %d, failed", table.sth.Size)
			}
			sth, err := sthFile.Load(&pub)
			if table.expErr {
				if err == nil {
					t.Errorf("unexpected success loading invalid sth")
				}
			} else if err != nil {
				t.Errorf("loading sth, size %d, failed: %v",
					table.sth.Size, err)
			} else if sth != *table.sth {
				t.Errorf("loading sth incorrectly, got: %v, wanted: %v",
					sth, *table.sth)
			}
		}
	})
}

func TestCreate(t *testing.T) {
	withTmpDir(t, func(dir string) {
		sthFile := sthFile{dir + "foo"}
		startupFileName := dir + "foo.startup"
		// Create file to be deleted.
		if err := os.WriteFile(startupFileName, []byte("foo"), 0666); err != nil {
			t.Fatalf("creating startup file %q failed: %v", startupFileName, err)
		}
		if _, err := os.ReadFile(startupFileName); err != nil {
			t.Fatalf("reading startup file %q failed: %v", startupFileName, err)
		}
		signer := crypto.NewEd25519Signer(&crypto.PrivateKey{7})
		pub := signer.Public()
		sth0 := mustSignTh(t, &types.TreeHead{}, signer)
		sth1 := mustSignTh(t, &types.TreeHead{Size: 1}, signer)
		if err := sthFile.Create(&sth0); err != nil {
			t.Fatalf("creating sth file failed: %v", err)
		}
		if _, err := os.ReadFile(startupFileName); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("startup file is still around after sth was created, err: %v", err)
		}
		if sth, err := sthFile.Load(&pub); err != nil || sth != sth0 {
			if err != nil {
				t.Errorf("loading sth, failed: %v", err)
			} else if sth != sth0 {
				t.Errorf("loading sth incorrectly, got: %v, wanted: %v",
					sth, sth0)
			}
		}
		if err := sthFile.Create(&sth1); err == nil || !errors.Is(err.(*os.LinkError).Unwrap(), fs.ErrExist) {
			t.Fatalf("creating sth should have failed with EEXIST, got err: %v", err)
		}
	})
}

// Creates temporary directory, runs function, end then removes files
// and directory.
func withTmpDir(t *testing.T, f func(dir string)) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "log-go-sthfile-test")
	if err != nil {
		t.Fatalf("failed to create temporary directory for test")
	}
	defer os.RemoveAll(dir)
	f(fmt.Sprintf("%s%c", dir, os.PathSeparator))
}

func mustSignTh(t *testing.T, th *types.TreeHead, signer crypto.Signer) types.SignedTreeHead {
	sth, err := th.Sign(signer)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	return sth
}
