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

	"git.sigsum.org/log-go/internal/db"
	"git.sigsum.org/log-go/internal/node/primary"
	"git.sigsum.org/log-go/internal/state"
	"git.sigsum.org/log-go/internal/utils"
	"git.sigsum.org/sigsum-go/pkg/client"
	"git.sigsum.org/sigsum-go/pkg/dns"
	"git.sigsum.org/sigsum-go/pkg/log"
	"git.sigsum.org/sigsum-go/pkg/merkle"
	"git.sigsum.org/sigsum-go/pkg/types"
)

var (
	externalEndpoint = flag.String("external-endpoint", "localhost:6965", "host:port specification of where sigsum-log-primary serves clients")
	internalEndpoint = flag.String("internal-endpoint", "localhost:6967", "host:port specification of where sigsum-log-primary serves other log nodes")
	rpcBackend       = flag.String("trillian-rpc-server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix           = flag.String("url-prefix", "", "a prefix that precedes /sigsum/v0/<endpoint>")
	trillianID       = flag.Int64("tree-id", 0, "tree identifier in the Trillian database")
	deadline         = flag.Duration("deadline", time.Second*10, "deadline for backend requests")
	key              = flag.String("key", "", "path to file with hex-encoded Ed25519 private key")
	witnesses        = flag.String("witnesses", "", "comma-separated list of trusted witness public keys in hex")
	maxRange         = flag.Int64("max-range", 10, "maximum number of entries that can be retrived in a single request")
	interval         = flag.Duration("interval", time.Second*30, "interval used to rotate the log's cosigned STH")
	shardStart       = flag.Int64("shard-interval-start", 0, "start of shard interval since the UNIX epoch in seconds")
	testMode         = flag.Bool("test-mode", false, "run in test mode (Default: false)")
	logFile          = flag.String("log-file", "", "file to write logs to (Default: stderr)")
	logLevel         = flag.String("log-level", "info", "log level (Available options: debug, info, warning, error. Default: info)")
	logColor         = flag.Bool("log-color", false, "colored logging output (Default: false)")
	secondaryURL     = flag.String("secondary-url", "", "secondary node endpoint for fetching latest replicated tree head")
	secondaryPubkey  = flag.String("secondary-pubkey", "", "hex-encoded Ed25519 public key for secondary node")

	gitCommit = "unknown"
)

func main() {
	flag.Parse()

	if err := utils.SetupLogging(*logFile, *logLevel, *logColor); err != nil {
		log.Fatal("setup logging: %v", err)
	}
	log.Info("log-go git-commit %s", gitCommit)

	// wait for clean-up before exit
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Debug("configuring log-go-primary")
	node, err := setupPrimaryFromFlags()
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
func setupPrimaryFromFlags() (*primary.Primary, error) {
	var p primary.Primary
	var err error

	// Setup logging configuration.
	p.Signer, p.Config.LogID, err = utils.NewLogIdentity(*key)
	if err != nil {
		return nil, fmt.Errorf("newLogIdentity: %v", err)
	}

	p.Config.TreeID = *trillianID
	p.Config.Prefix = *prefix
	p.Config.MaxRange = *maxRange
	p.Config.Deadline = *deadline
	p.Config.Interval = *interval
	p.Config.ShardStart = uint64(*shardStart)
	if *shardStart < 0 {
		return nil, fmt.Errorf("shard start must be larger than zero")
	}
	p.Config.Witnesses, err = newWitnessMap(*witnesses)
	if err != nil {
		return nil, fmt.Errorf("newWitnessMap: %v", err)
	}

	// Setup trillian client.
	dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(p.Config.Deadline)}
	conn, err := grpc.Dial(*rpcBackend, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("Dial: %v", err)
	}
	p.TrillianClient = &db.TrillianClient{
		TreeID: p.TreeID,
		GRPC:   trillian.NewTrillianLogClient(conn),
	}

	// Setup secondary node configuration.
	if *secondaryURL != "" && *secondaryPubkey != "" {
		pubkey, err := utils.PubkeyFromHexString(*secondaryPubkey)
		if err != nil {
			return nil, fmt.Errorf("invalid secondary node pubkey: %v", err)
		}
		p.Secondary = client.New(client.Config{
			LogURL: *secondaryURL,
			LogPub: *pubkey,
		})
	} else {
		p.Secondary = client.New(client.Config{})
	}

	// Setup state manager.
	p.Stateman, err = state.NewStateManagerSingle(p.TrillianClient, p.Signer, p.Config.Interval, p.Config.Deadline, p.Secondary)
	if err != nil {
		return nil, fmt.Errorf("NewStateManagerSingle: %v", err)
	}
	if *testMode == false {
		p.DNS = dns.NewDefaultResolver()
	} else {
		p.DNS = dns.NewDummyResolver()
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
func newWitnessMap(witnesses string) (map[merkle.Hash]types.PublicKey, error) {
	w := make(map[merkle.Hash]types.PublicKey)
	if len(witnesses) > 0 {
		for _, witness := range strings.Split(witnesses, ",") {
			b, err := hex.DecodeString(witness)
			if err != nil {
				return nil, fmt.Errorf("DecodeString: %v", err)
			}

			var vk types.PublicKey
			if n := copy(vk[:], b); n != types.PublicKeySize {
				return nil, fmt.Errorf("Invalid public key size: %v", n)
			}
			w[*merkle.HashFn(vk[:])] = vk
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
