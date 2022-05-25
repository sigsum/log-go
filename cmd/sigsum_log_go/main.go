// Package main provides a sigsum-log-go binary
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
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

	"git.sigsum.org/sigsum-go/pkg/log"
	"git.sigsum.org/sigsum-go/pkg/types"
	"git.sigsum.org/sigsum-go/pkg/dns"
	"git.sigsum.org/log-go/pkg/db"
	"git.sigsum.org/log-go/pkg/instance"
	"git.sigsum.org/log-go/pkg/state"
)

var (
	httpEndpoint = flag.String("http_endpoint", "localhost:6965", "host:port specification of where sigsum-log-go serves clients")
	rpcBackend   = flag.String("log_rpc_server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix       = flag.String("prefix", "", "a prefix that proceeds /sigsum/v0/<endpoint>")
	trillianID   = flag.Int64("trillian_id", 0, "log identifier in the Trillian database")
	deadline     = flag.Duration("deadline", time.Second*10, "deadline for backend requests")
	key          = flag.String("key", "", "path to file with hex-encoded Ed25519 private key")
	witnesses    = flag.String("witnesses", "", "comma-separated list of trusted witness public keys in hex")
	maxRange     = flag.Int64("max_range", 10, "maximum number of entries that can be retrived in a single request")
	interval     = flag.Duration("interval", time.Second*30, "interval used to rotate the log's cosigned STH")
	shardStart   = flag.Int64("shard_interval_start", 0, "start of shard interval since the UNIX epoch in seconds")
	logFile      = flag.String("log-file", "", "file to write logs to (Default: stderr)")
	logLevel     = flag.String("log-level", "info", "log level (Available options: debug, info, warning, error. Default: info)")
	logColor     = flag.Bool("log-color", false, "colored logging output (Default: off)")

	gitCommit = "unknown"
)

func main() {
	flag.Parse()

	if err := setupLogging(*logFile, *logLevel, *logColor); err != nil {
		log.Fatal("setup logging: %v", err)
	}
	log.Info("log-go git-commit %s", gitCommit)

	// wait for clean-up before exit
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Debug("configuring log-go instance")
	instance, err := setupInstanceFromFlags()
	if err != nil {
		log.Fatal("setup instance: %v", err)
	}

	log.Debug("starting state manager routine")
	go func() {
		wg.Add(1)
		defer wg.Done()
		instance.Stateman.Run(ctx)
		log.Debug("state manager shutdown")
		cancel() // must have state manager running
	}()

	log.Debug("starting await routine")
	server := http.Server{Addr: *httpEndpoint}
	go await(ctx, func() {
		wg.Add(1)
		defer wg.Done()
		ctxInner, _ := context.WithTimeout(ctx, time.Second*60)
		log.Info("stopping http server, please wait...")
		server.Shutdown(ctxInner)
		log.Info("stopping go routines, please wait...")
		cancel()
	})

	log.Info("serving on %v/%v", *httpEndpoint, *prefix)
	if err = server.ListenAndServe(); err != http.ErrServerClosed {
		log.Error("serve: %v", err)
	}
}

func setupLogging(logFile, logLevel string, logColor bool) error {
	if len(logFile) != 0 {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		log.SetOutput(f)
	}

	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warning":
		log.SetLevel(log.WarningLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		return fmt.Errorf("invalid logging level %s", logLevel)
	}

	log.SetColor(logColor)
	return nil
}

// SetupInstance sets up a new sigsum-log-go instance from flags
func setupInstanceFromFlags() (*instance.Instance, error) {
	var i instance.Instance
	var err error

	// Setup log configuration
	i.Signer, i.LogID, err = newLogIdentity(*key)
	if err != nil {
		return nil, fmt.Errorf("newLogIdentity: %v", err)
	}
	i.TreeID = *trillianID
	i.Prefix = *prefix
	i.MaxRange = *maxRange
	i.Deadline = *deadline
	i.Interval = *interval
	i.ShardStart = uint64(*shardStart)
	if *shardStart < 0 {
		return nil, fmt.Errorf("shard start must be larger than zero")
	}
	i.Witnesses, err = newWitnessMap(*witnesses)
	if err != nil {
		return nil, fmt.Errorf("newWitnessMap: %v", err)
	}

	// Setup log client
	dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(i.Deadline)}
	conn, err := grpc.Dial(*rpcBackend, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("Dial: %v", err)
	}
	i.Client = &db.TrillianClient{
		TreeID: i.TreeID,
		GRPC:   trillian.NewTrillianLogClient(conn),
	}

	// Setup state manager
	i.Stateman, err = state.NewStateManagerSingle(i.Client, i.Signer, i.Interval, i.Deadline)
	if err != nil {
		return nil, fmt.Errorf("NewStateManagerSingle: %v", err)
	}

	// Setup DNS verifier
	i.DNS = dns.NewDefaultResolver()

	// Register HTTP endpoints
	mux := http.NewServeMux()
	http.Handle("/", mux)
	for _, handler := range i.Handlers() {
		log.Debug("adding handler: %s", handler.Path())
		mux.Handle(handler.Path(), handler)
	}
	log.Debug("adding prometheus handler on path: /metrics")
	http.Handle("/metrics", promhttp.Handler())

	return &i, nil
}

func newLogIdentity(keyFile string) (crypto.Signer, string, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, "", err
	}
	if buf, err = hex.DecodeString(strings.TrimSpace(string(buf))); err != nil {
		return nil, "", fmt.Errorf("DecodeString: %v", err)
	}
	sk := crypto.Signer(ed25519.PrivateKey(buf))
	vk := sk.Public().(ed25519.PublicKey)
	return sk, hex.EncodeToString([]byte(vk[:])), nil
}

// newWitnessMap creates a new map of trusted witnesses
func newWitnessMap(witnesses string) (map[types.Hash]types.PublicKey, error) {
	w := make(map[types.Hash]types.PublicKey)
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
			w[*types.HashFn(vk[:])] = vk
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
