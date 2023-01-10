// Package main provides a sigsum-log-secondary binary
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/trillian"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"

	"sigsum.org/log-go/internal/config"
	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/secondary"
	"sigsum.org/log-go/internal/utils"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
)

var (
	gitCommit = "unknown"
)

func ParseFlags(c *config.Config) {
	flag.StringVar(&c.Secondary.PrimaryURL, "primary-url", c.Secondary.PrimaryURL, "primary node endpoint for fetching leaves")
	flag.StringVar(&c.Secondary.PrimaryPubkey, "primary-pubkey", c.Secondary.PrimaryPubkey, "hex-encoded Ed25519 public key for primary node")
	flag.BoolVar(&c.Secondary.TestMode, "test-mode", c.Secondary.TestMode, "run in test mode (Default: false)")
	flag.Parse()
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
	config.ServerFlags(conf)
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
	var publicKey crypto.PublicKey

	// Setup logging configuration.
	publicKey, s.Signer, err = utils.ReadKeyFile(conf.Key)
	if err != nil {
		return nil, fmt.Errorf("newLogIdentity: %v", err)
	}
	s.Config.LogID = hex.EncodeToString(publicKey[:])
	s.Config.Timeout = conf.Timeout
	s.Interval = conf.Interval

	if conf.EphemeralBackend {
		s.DbClient = db.NewMemoryDb()
	} else {
		// Setup trillian client.
		dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(s.Config.Timeout)}
		conn, err := grpc.Dial(conf.RpcBackend, dialOpts...)
		if err != nil {
			return nil, fmt.Errorf("Dial: %v", err)
		}
		s.DbClient = &db.TrillianClient{
			TreeID: conf.TrillianID,
			GRPC:   trillian.NewTrillianLogClient(conn),
		}
	}
	// Setup primary node configuration.
	pubkey, err := crypto.PublicKeyFromHex(conf.Secondary.PrimaryPubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid primary node pubkey: %v", err)
	}
	s.Primary = client.New(client.Config{
		LogURL: conf.Secondary.PrimaryURL,
		LogPub: pubkey,
	})

	// TODO: verify that GRPC.TreeType() == PREORDERED_LOG.

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
