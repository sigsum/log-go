// Package main provides a sigsum-log-primary binary
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
	"sigsum.org/log-go/internal/node/primary"
	rateLimit "sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/log-go/internal/utils"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	token "sigsum.org/sigsum-go/pkg/submit-token"
)

var (
	gitCommit = "unknown"
)

func ParseFlags(c *config.Config) {
	help := false
	getopt.SetParameters("")
	getopt.FlagLong(&c.Primary.RateLimitFile, "rate-limit-file", 0, "enable rate limiting, based on given config file")
	getopt.FlagLong(&c.Primary.AllowTestDomain, "allow-test-domain", 0, "allow submit tokens from test.sigsum.org")
	getopt.FlagLong(&c.Primary.SecondaryURL, "secondary-url", 0, "secondary node endpoint for fetching latest replicated tree head")
	getopt.FlagLong(&c.Primary.SecondaryPubkeyFile, "secondary-pubkey-file", 0, "public key file for secondary node")
	getopt.FlagLong(&c.Primary.SthFile, "sth-file", 0, "file where latest published STH is being stored")
	getopt.FlagLong(&help, "help", '?', "display help")
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

	log.Debug("configuring log-go-primary")
	node, err := setupPrimaryFromFlags(conf)
	if err != nil {
		log.Fatal("setup primary: %v", err)
	}

	log.Debug("starting primary state manager routine")
	go func() {
		wg.Add(1)
		defer wg.Done()
		node.Stateman.Run(ctx, conf.Interval)
		log.Debug("state manager shutdown")
		cancel() // must have state manager running
	}()

	// Register HTTP endpoints.
	log.Debug("adding external handler under prefix: %s", conf.Prefix)
	server := &http.Server{Addr: conf.ExternalEndpoint, Handler: node.PublicHTTPMux(conf.Prefix)}
	log.Debug("adding internal handler under prefix: %s", conf.Prefix)
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

// setupPrimaryFromFlags() sets up a new sigsum primary node from flags.
func setupPrimaryFromFlags(conf *config.Config) (*primary.Primary, error) {
	var p primary.Primary

	// Setup logging configuration.
	signer, err := key.ReadPrivateKeyFile(conf.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("newLogIdentity: %v", err)
	}
	publicKey := signer.Public()

	// Proxy over values from config.Config to the old Config struct
	// TODO: Refactor this handling
	p.Config.LogID = hex.EncodeToString(publicKey[:])
	p.Config.Timeout = conf.Timeout
	p.MaxRange = conf.MaxRange

	switch conf.Backend {
	default:
		return nil, fmt.Errorf("unknown backend %q, must be \"trillian\" (default) or \"ephemeral\"", conf.Backend)
	case "ephemeral":
		p.DbClient = db.NewMemoryDb()
	case "trillian":
		trillianClient, err := db.DialTrillian(conf.TrillianRpcServer, p.Config.Timeout, db.PrimaryTree, conf.TrillianTreeIDFile)
		if err != nil {
			return nil, err
		}
		p.DbClient = trillianClient
	}
	// Setup secondary node configuration.
	var secondary client.Client
	var secondaryPub crypto.PublicKey
	if conf.Primary.SecondaryURL != "" && conf.Primary.SecondaryPubkeyFile != "" {
		var err error
		secondaryPub, err = key.ReadPublicKeyFile(conf.Primary.SecondaryPubkeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read secondary node pubkey: %v", err)
		}
		secondary = client.New(client.Config{LogURL: conf.Primary.SecondaryURL})
	}

	// Setup state manager.
	p.Stateman, err = state.NewStateManagerSingle(p.DbClient, signer, p.Config.Timeout,
		secondary, &secondaryPub, conf.Primary.SthFile)
	if err != nil {
		return nil, fmt.Errorf("NewStateManagerSingle: %v", err)
	}

	p.TokenVerifier = token.NewDnsVerifier(&publicKey)
	if len(conf.Primary.RateLimitFile) > 0 {
		f, err := os.Open(conf.Primary.RateLimitFile)
		if err != nil {
			return nil, fmt.Errorf("opening rate limit config file failed: %v", err)
		}
		p.RateLimiter, err = rateLimit.NewLimiter(f, conf.Primary.AllowTestDomain)
		if err != nil {
			return nil, fmt.Errorf("initializing rate limiter failed: %v", err)
		}
	} else {
		p.RateLimiter = rateLimit.NoLimit{}
	}

	return &p, nil
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
