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

	"github.com/pborman/getopt/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"sigsum.org/log-go/internal/config"
	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/metrics"
	"sigsum.org/log-go/internal/node/secondary"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/server"
)

var (
	gitCommit = "unknown"
)

func ParseFlags(c *config.Config) {
	help := false
	getopt.SetParameters("")
	getopt.FlagLong(&c.Secondary.PrimaryURL, "primary-url", 0, "Primary node endpoint for fetching leaves.", "url")
	getopt.FlagLong(&help, "help", '?', "Display help.")
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

	if len(conf.LogFile) > 0 {
		if err := log.SetLogFile(conf.LogFile); err != nil {
			log.Fatal("open log file failed: %v", err)
		}
	}
	if err := log.SetLevelFromString(conf.LogLevel); err != nil {
		log.Fatal("setup logging: %v", err)
	}
	log.Info("log-go git-commit %s", gitCommit)

	log.Debug("configuring log-go-secondary")
	node, publicKey, err := setupSecondaryFromFlags(conf)
	if err != nil {
		log.Fatal("setup secondary: %v", err)
	}

	// wait for clean-up before exit
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Debug("starting periodic routine")
	wg.Add(1)
	go func() {
		defer wg.Done()
		node.Run(ctx)
		log.Debug("periodic routine shutdown")
		cancel() // must have periodic running
	}()

	// No external endpoints but we want to return 404.
	extserver := &http.Server{Addr: conf.ExternalEndpoint, Handler: http.NewServeMux()}
	// Register HTTP endpoints.
	internalMux := http.NewServeMux()
	internalMux.Handle("/", server.NewSecondary(&server.Config{
		Prefix:  conf.Prefix,
		Timeout: conf.Timeout,
		Metrics: metrics.NewServerMetrics(hex.EncodeToString(publicKey[:])),
	}, node))
	log.Debug("adding prometheus handler to internal mux, on path: /metrics")
	internalMux.Handle("/metrics", promhttp.Handler())
	intserver := &http.Server{Addr: conf.InternalEndpoint, Handler: internalMux}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("serving log nodes on %v/%v", conf.InternalEndpoint, conf.Prefix)
		if err = intserver.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("serve(intserver): %v", err)
		}
		log.Debug("internal endpoints server shut down")
		cancel()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("serving clients on %v/%v", conf.ExternalEndpoint, conf.Prefix)
		if err = extserver.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("serve(server): %v", err)
		}
		log.Debug("public endpoints server shut down")
		cancel()
	}()

	<-ctx.Done()

	log.Debug("received shutdown signal")
	shutdownCtx, _ := context.WithTimeout(context.Background(), time.Second*60)

	log.Info("stopping http server, please wait...")
	extserver.Shutdown(shutdownCtx)
	log.Info("... done")
	log.Info("stopping internal api server, please wait...")
	intserver.Shutdown(shutdownCtx)
	log.Info("... done")
}

// setupSecondaryFromFlags() sets up a new sigsum secondary node from flags.
func setupSecondaryFromFlags(conf *config.Config) (*secondary.Secondary, crypto.PublicKey, error) {
	var s secondary.Secondary
	var err error

	// Setup logging configuration.
	s.Signer, err = key.ReadPrivateKeyFile(conf.KeyFile)
	if err != nil {
		return nil, crypto.PublicKey{}, fmt.Errorf("newLogIdentity: %v", err)
	}

	s.Interval = conf.Interval

	switch conf.Backend {
	default:
		return nil, crypto.PublicKey{}, fmt.Errorf("unknown backend %q, must be \"trillian\" (default) or \"ephemeral\"", conf.Backend)
	case "ephemeral":
		s.DbClient = db.NewMemoryDb()
	case "trillian":
		trillianClient, err := db.DialTrillian(conf.TrillianRpcServer, conf.Timeout, db.SecondaryTree, conf.TrillianTreeIDFile)
		if err != nil {
			return nil, crypto.PublicKey{}, err
		}
		s.DbClient = trillianClient
	}
	// Setup primary node configuration.
	s.Primary = client.New(client.Config{URL: conf.Secondary.PrimaryURL})

	return &s, s.Signer.Public(), nil
}
