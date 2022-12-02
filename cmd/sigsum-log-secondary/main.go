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

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/secondary"
	"sigsum.org/log-go/internal/utils"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
)

var (
	externalEndpoint = flag.String("external-endpoint", "localhost:6965", "host:port specification of where sigsum-log-secondary serves clients")
	internalEndpoint = flag.String("internal-endpoint", "localhost:6967", "host:port specification of where sigsum-log-secondary serves other log nodes")
	rpcBackend       = flag.String("trillian-rpc-server", "localhost:6962", "host:port specification of where Trillian serves clients")
	ephemeralBackend = flag.Bool("ephemeral-test-backend", false, "if set, enables in-memory backend, with NO persistent storage")
	prefix           = flag.String("url-prefix", "", "a prefix that preceeds /<endpoint>")
	trillianID       = flag.Int64("tree-id", 0, "log identifier in the Trillian database")
	timeout          = flag.Duration("timeout", time.Second*10, "timeout for backend requests")
	key              = flag.String("key", "", "path to file with hex-encoded Ed25519 private key")
	interval         = flag.Duration("interval", time.Second*30, "interval used to rotate the node's STH")
	testMode         = flag.Bool("test-mode", false, "run in test mode (Default: false)")
	logFile          = flag.String("log-file", "", "file to write logs to (Default: stderr)")
	logLevel         = flag.String("log-level", "info", "log level (Available options: debug, info, warning, error. Default: info)")
	primaryURL       = flag.String("primary-url", "", "primary node endpoint for fetching leaves")
	primaryPubkey    = flag.String("primary-pubkey", "", "hex-encoded Ed25519 public key for primary node")

	gitCommit = "unknown"
)

func main() {
	flag.Parse()

	if err := utils.LogToFile(*logFile); err != nil {
		log.Fatal("open log file failed: %v", err)
	}
	if err := log.SetLevelFromString(*logLevel); err != nil {
		log.Fatal("setup logging: %v", err)
	}
	log.Info("log-go git-commit %s", gitCommit)

	// wait for clean-up before exit
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Debug("configuring log-go-secondary")
	node, err := setupSecondaryFromFlags()
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

	server := &http.Server{Addr: *externalEndpoint, Handler: node.PublicHTTPMux}
	intserver := &http.Server{Addr: *internalEndpoint, Handler: node.InternalHTTPMux}
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
		log.Info("serving log nodes on %v/%v", *internalEndpoint, *prefix)
		if err = intserver.ListenAndServe(); err != http.ErrServerClosed {
			log.Error("serve(intserver): %v", err)
		}
		log.Debug("internal endpoints server shut down")
		cancel()
	}()

	log.Info("serving clients on %v/%v", *externalEndpoint, *prefix)
	if err = server.ListenAndServe(); err != http.ErrServerClosed {
		log.Error("serve(server): %v", err)
	}

}

// setupSecondaryFromFlags() sets up a new sigsum secondary node from flags.
func setupSecondaryFromFlags() (*secondary.Secondary, error) {
	var s secondary.Secondary
	var err error
	var publicKey crypto.PublicKey

	// Setup logging configuration.
	publicKey, s.Signer, err = utils.ReadKeyFile(*key)
	if err != nil {
		return nil, fmt.Errorf("newLogIdentity: %v", err)
	}
	s.Config.LogID = hex.EncodeToString(publicKey[:])
	s.Config.Timeout = *timeout
	s.Config.Interval = *interval

	if *ephemeralBackend {
		s.DbClient = db.NewMemoryDb()
	} else {
		// Setup trillian client.
		dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(s.Config.Timeout)}
		conn, err := grpc.Dial(*rpcBackend, dialOpts...)
		if err != nil {
			return nil, fmt.Errorf("Dial: %v", err)
		}
		s.DbClient = &db.TrillianClient{
			TreeID: *trillianID,
			GRPC:   trillian.NewTrillianLogClient(conn),
		}
	}
	// Setup primary node configuration.
	pubkey, err := crypto.PublicKeyFromHex(*primaryPubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid primary node pubkey: %v", err)
	}
	s.Primary = client.New(client.Config{
		LogURL: *primaryURL,
		LogPub: pubkey,
	})

	// TODO: verify that GRPC.TreeType() == PREORDERED_LOG.

	// Register HTTP endpoints.
	mux := http.NewServeMux()
	s.PublicHTTPMux = mux // No external endpoints but we want to return 404.

	mux = http.NewServeMux()
	for _, h := range s.InternalHTTPHandlers() {
		path := h.Path(*prefix)
		log.Debug("adding internal handler: %s", path)
		mux.Handle(path, h)
	}
	s.InternalHTTPMux = mux

	log.Debug("adding prometheus handler to internal mux, on path: /metrics")
	http.Handle("/metrics", promhttp.Handler())

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
