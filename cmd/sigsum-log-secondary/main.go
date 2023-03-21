// Package main provides a sigsum-log-secondary binary
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	getopt "github.com/pborman/getopt/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"sigsum.org/log-go/internal/config"
	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/secondary"
	"sigsum.org/log-go/internal/utils"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
)

var (
	gitCommit = "unknown"
)

func ParseFlags(c *config.Config) {
	help := false
	getopt.SetParameters("")
	getopt.FlagLong(&c.Secondary.PrimaryURL, "primary-url", 0, "primary node endpoint for fetching leaves")
	getopt.Parse()
	if help {
		getopt.PrintUsage(os.Stdout)
		os.Exit(0)
	}
}

func main() {
	var conf *config.Config

	// Read default values from the Config struct
	confFile, err := config.OpenConfigFile()
	if err != nil {
		log.Info("didn't find configuration file, using defaults: %v", err)
		conf = config.NewConfig()
	} else {
		conf, err = config.LoadConfig(confFile)
		if err != nil {
			log.Fatal("failed to parse config file: %v", err)
		}
	}

	// Allow flags to override them
	conf.ServerFlags(getopt.CommandLine)
	ParseFlags(conf)

	if err := utils.LogToFile(conf.LogFile); err != nil {
		log.Fatal("open log file failed: %v", err)
	}
	if err := log.SetLevelFromString(conf.LogLevel); err != nil {
		log.Fatal("setup logging: %v", err)
	}
	log.Info("log-go git-commit %s", gitCommit)

	// wait for clean-up before exit
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Debug("configuring log-go-secondary")
	node, err := setupSecondaryFromFlags(conf)
	if err != nil {
		log.Fatal("setup secondary: %v", err)
	}

	log.Debug("starting periodic routine")
	go func() {
		wg.Add(1)
		defer wg.Done()
		node.Run(ctx)
		log.Debug("periodic routine shutdown")
		cancel() // must have periodic running
	}()

	// No external endpoints but we want to return 404.
	server := &http.Server{Addr: conf.ExternalEndpoint, Handler: http.NewServeMux()}
	// Register HTTP endpoints.
	internalMux := node.InternalHTTPMux(conf.Prefix)
	log.Debug("adding prometheus handler to internal mux, on path: /metrics")
	internalMux.Handle("/metrics", promhttp.Handler())
	intserver := &http.Server{Addr: conf.InternalEndpoint, Handler: internalMux}

	log.Debug("starting await routine")
	go await(ctx, func() {
		wg.Add(1)
		defer wg.Done()
		ctxInner, _ := context.WithTimeout(ctx, time.Second*60)
		log.Info("stopping http server, please wait...")
		server.Shutdown(ctxInner)
		log.Info("... done")
		log.Info("stopping internal api server, please wait...")
		intserver.Shutdown(ctxInner)
		log.Info("... done")
		log.Info("stopping go routines, please wait...")
		cancel()
		log.Info("... done")
	})

	go func() {
		wg.Add(1)
		defer wg.Done()
		log.Info("serving log nodes on %v/%v", conf.InternalEndpoint, conf.Prefix)
		if err = intserver.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("serve(intserver): %v", err)
		}
		log.Debug("internal endpoints server shut down")
		cancel()
	}()

	log.Info("serving clients on %v/%v", conf.ExternalEndpoint, conf.Prefix)
	if err = server.ListenAndServe(); err != http.ErrServerClosed {
		log.Error("serve(server): %v", err)
	}

}

// setupSecondaryFromFlags() sets up a new sigsum secondary node from flags.
func setupSecondaryFromFlags(conf *config.Config) (*secondary.Secondary, error) {
	var s secondary.Secondary
	var err error

	// Setup logging configuration.
	s.Signer, err = key.ReadPrivateKeyFile(conf.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("newLogIdentity: %v", err)
	}
	publicKey := s.Signer.Public()

	s.Config.LogID = hex.EncodeToString(publicKey[:])
	s.Config.Timeout = conf.Timeout
	s.Interval = conf.Interval

	switch conf.Backend {
	default:
		return nil, fmt.Errorf("unknown backend %q, must be \"trillian\" (default) or \"ephemeral\"", conf.Backend)
	case "ephemeral":
		s.DbClient = db.NewMemoryDb()
	case "trillian":
		trillianClient, err := db.DialTrillian(conf.TrillianRpcServer, s.Config.Timeout, db.SecondaryTree, conf.TrillianTreeIDFile)
		if err != nil {
			return nil, err
		}
		s.DbClient = trillianClient
	}
	// Setup primary node configuration.
	s.Primary = client.New(client.Config{LogURL: conf.Secondary.PrimaryURL})

	// Register HTTP endpoints.
	return &s, nil
}

// await waits for a shutdown signal and then runs a clean-up function
func await(ctx context.Context, done func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigs:
	case <-ctx.Done():
	}
	log.Debug("received shutdown signal")
	done()
}
