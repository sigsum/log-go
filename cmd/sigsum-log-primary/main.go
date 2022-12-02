// Package main provides a sigsum-log-primary binary
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/trillian"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"

	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/primary"
	"sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/log-go/internal/utils"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/submit-token"
)

var (
	externalEndpoint = flag.String("external-endpoint", "localhost:6965", "host:port specification of where sigsum-log-primary serves clients")
	internalEndpoint = flag.String("internal-endpoint", "localhost:6967", "host:port specification of where sigsum-log-primary serves other log nodes")
	rpcBackend       = flag.String("trillian-rpc-server", "localhost:6962", "host:port specification of where Trillian serves clients")
	ephemeralBackend = flag.Bool("ephemeral-test-backend", false, "if set, enables in-memory backend, with NO persistent storage")
	prefix           = flag.String("url-prefix", "", "a prefix that precedes /<endpoint>")
	trillianID       = flag.Int64("tree-id", 0, "tree identifier in the Trillian database")
	timeout          = flag.Duration("timeout", time.Second*10, "timeout for backend requests")
	key              = flag.String("key", "", "path to file with hex-encoded Ed25519 private key")
	witnesses        = flag.String("witnesses", "", "comma-separated list of trusted witness public keys in hex")
	maxRange         = flag.Int64("max-range", 10, "maximum number of entries that can be retrived in a single request")
	interval         = flag.Duration("interval", time.Second*30, "interval used to rotate the log's cosigned STH")
	rateLimitConfig  = flag.String("rate-limit-config", "", "enable rate limiting, based on given config file")
	allowTestDomain  = flag.Bool("allow-test-domain", false, "allow submit tokens from test.sigsum.org")
	logFile          = flag.String("log-file", "", "file to write logs to (Default: stderr)")
	logLevel         = flag.String("log-level", "info", "log level (Available options: debug, info, warning, error. Default: info)")
	secondaryURL     = flag.String("secondary-url", "", "secondary node endpoint for fetching latest replicated tree head")
	secondaryPubkey  = flag.String("secondary-pubkey", "", "hex-encoded Ed25519 public key for secondary node")
	sthStorePath     = flag.String("sth-path", "/var/lib/sigsum-log/sth", "path to file where latest published STH is being stored")

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

	log.Debug("configuring log-go-primary")
	sthFile, err := os.OpenFile(*sthStorePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal("opening STH file: %v", err)
	}
	defer sthFile.Close()
	node, err := setupPrimaryFromFlags(sthFile)
	if err != nil {
		log.Fatal("setup primary: %v", err)
	}

	log.Debug("starting primary state manager routine")
	go func() {
		wg.Add(1)
		defer wg.Done()
		node.Stateman.Run(ctx)
		log.Debug("state manager shutdown")
		cancel() // must have state manager running
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

// setupPrimaryFromFlags() sets up a new sigsum primary node from flags.
func setupPrimaryFromFlags(sthFile *os.File) (*primary.Primary, error) {
	var p primary.Primary
	var err error
	var publicKey crypto.PublicKey

	// Setup logging configuration.
	publicKey, p.Signer, err = utils.ReadKeyFile(*key)
	if err != nil {
		return nil, fmt.Errorf("newLogIdentity: %v", err)
	}

	p.Config.LogID = hex.EncodeToString(publicKey[:])
	p.Config.Prefix = *prefix
	p.Config.MaxRange = *maxRange
	p.Config.Timeout = *timeout
	witnessMap, err := newWitnessMap(*witnesses)
	if err != nil {
		return nil, fmt.Errorf("newWitnessMap: %v", err)
	}

	if *ephemeralBackend {
		p.DbClient = db.NewMemoryDb()
	} else {
		// Setup trillian client.
		dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(p.Config.Timeout)}
		conn, err := grpc.Dial(*rpcBackend, dialOpts...)
		if err != nil {
			return nil, fmt.Errorf("Dial: %v", err)
		}
		p.DbClient = &db.TrillianClient{
			TreeID: *trillianID,
			GRPC:   trillian.NewTrillianLogClient(conn),
		}
	}
	// Setup secondary node configuration.
	var secondary client.Client
	if *secondaryURL != "" && *secondaryPubkey != "" {
		pubkey, err := crypto.PublicKeyFromHex(*secondaryPubkey)
		if err != nil {
			return nil, fmt.Errorf("invalid secondary node pubkey: %v", err)
		}
		secondary = client.New(client.Config{
			LogURL: *secondaryURL,
			LogPub: pubkey,
		})
	}

	// Setup state manager.
	p.Stateman, err = state.NewStateManagerSingle(p.DbClient, p.Signer, *interval, p.Config.Timeout,
		secondary, sthFile, witnessMap)
	if err != nil {
		return nil, fmt.Errorf("NewStateManagerSingle: %v", err)
	}

	p.TokenVerifier = token.NewDnsVerifier(&publicKey)
	if len(*rateLimitConfig) > 0 {
		f, err := os.Open(*rateLimitConfig)
		if err != nil {
			return nil, fmt.Errorf("opening rate limit config file failed: %v", err)
		}
		p.RateLimiter, err = rateLimit.NewLimiter(f, *allowTestDomain)
		if err != nil {
			return nil, fmt.Errorf("initializing rate limiter failed: %v", err)
		}
	} else {
		p.RateLimiter = rateLimit.NoLimit{}
	}

	// TODO: verify that GRPC.TreeType() == LOG.

	// Register HTTP endpoints.
	mux := http.NewServeMux()
	for _, h := range p.PublicHTTPHandlers() {
		log.Debug("adding external handler: %s", h.Path())
		mux.Handle(h.Path(), h)
	}
	p.PublicHTTPMux = mux

	mux = http.NewServeMux()
	for _, h := range p.InternalHTTPHandlers() {
		log.Debug("adding internal handler: %s", h.Path())
		mux.Handle(h.Path(), h)
	}
	p.InternalHTTPMux = mux

	log.Debug("adding prometheus handler to internal mux, on path: /metrics")
	http.Handle("/metrics", promhttp.Handler())

	return &p, nil
}

// newWitnessMap creates a new map of trusted witnesses
func newWitnessMap(witnesses string) (map[crypto.Hash]crypto.PublicKey, error) {
	w := make(map[crypto.Hash]crypto.PublicKey)
	if len(witnesses) > 0 {
		for _, witness := range strings.Split(witnesses, ",") {
			b, err := hex.DecodeString(witness)
			if err != nil {
				return nil, fmt.Errorf("DecodeString: %v", err)
			}

			var vk crypto.PublicKey
			if n := copy(vk[:], b); n != crypto.PublicKeySize {
				return nil, fmt.Errorf("Invalid public key size: %v", n)
			}
			w[crypto.HashBytes(vk[:])] = vk
		}
	}
	return w, nil
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
