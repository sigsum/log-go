package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/pborman/getopt/v2"

	"sigsum.org/log-go/internal/config"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/log-go/internal/version"
)

func ParseFlags(c *config.Config) state.StartupMode {
	mode := "empty"
	help := false
	versionFlag := false
	getopt.SetParameters("")
	getopt.FlagLong(&c.Primary.SthFile, "sth-file", 0, "File where latest published STH is being stored.", "file")
	getopt.FlagLong(&mode, "mode", 0, "Mode of operation, 'empty', 'local-tree', or 'saved' (no change, only check that a saved file exists)", "mode")
	getopt.FlagLong(&help, "help", '?', "Display help.")
	getopt.FlagLong(&versionFlag, "version", 0, "Display version.")
	getopt.Parse()
	if help {
		getopt.PrintUsage(os.Stdout)
		os.Exit(0)
	}
	if versionFlag {
		fmt.Printf("log-go version: %s\n", version.ModuleVersion())
		os.Exit(0)
	}

	switch mode {
	case "empty":
		return state.StartupEmpty
	case "local-tree":
		return state.StartupLocalTree
	case "saved":
		return state.StartupSaved
	default:
		log.Fatalf("unknown mode %q, must be one of \"empty\", \"local-tree\", or \"saved\"", mode)
		return state.StartupEmpty
	}
}

func main() {
	log.SetFlags(0)
	var conf *config.Config
	// Read default values from the Config struct
	confFile, err := config.OpenConfigFile()
	if err != nil {
		log.Printf("didn't find configuration file, using defaults: %v", err)
		conf = config.NewConfig()
	} else {
		conf, err = config.LoadConfig(confFile)
		if err != nil {
			log.Fatalf("failed to parse config file: %v", err)
		}
	}

	startupMode := ParseFlags(conf)
	startupFile := conf.SthFile + state.StartupFileSuffix
	switch startupMode {
	case state.StartupSaved:
		if _, err := os.Stat(conf.SthFile); err != nil {
			log.Fatalf("Signed tree head file %q doesn't exist: %v",
				conf.SthFile, err)
		}
		checkNotExists(startupFile)

	case state.StartupEmpty:
		checkNotExists(conf.SthFile)
		writeStartupFile(startupFile, "empty")

	case state.StartupLocalTree:
		checkNotExists(conf.SthFile)
		writeStartupFile(startupFile, "local-tree")
	}
}

func checkNotExists(file string) {
	if _, err := os.Stat(file); err == nil || !errors.Is(err, fs.ErrNotExist) {
		log.Fatalf("Unexpected file %q, inconsistent with specified startup state.", file)
	}
}

// Writing is not atomic, user is expected to not run this tool under
// the feet of log server startup.
func writeStartupFile(name string, mode string) {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Fatalf("creating startup file failed: %v", err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "startup=%s", mode)
	// Explicit close, to catch errors.
	if err == nil {
		err = f.Close()
	}
	if err != nil {
		log.Fatalf("writing startup file failed: %v", err)
	}

}
