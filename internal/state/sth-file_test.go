package state

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"
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
		// Create a file that can't be read.
		os.WriteFile(dir+"foo.startup", []byte{}, 0)
		mode, err = sthFile.Startup()
		if !errors.Is(err, fs.ErrPermission) {
			t.Errorf("unexpected result for unreadable file, expected permission error, got mode: %d, err: %v",
				mode, err)
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
