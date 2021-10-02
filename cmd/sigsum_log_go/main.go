// Package main provides a sigsum-log-go binary
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
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

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"

	sigsum "git.sigsum.org/sigsum-log-go/pkg/instance"
	"git.sigsum.org/sigsum-log-go/pkg/state"
	trillianWrapper "git.sigsum.org/sigsum-log-go/pkg/trillian"
	"git.sigsum.org/sigsum-log-go/pkg/types"
	"git.sigsum.org/sigsum-log-go/pkg/dns"
)

var (
	httpEndpoint = flag.String("http_endpoint", "localhost:6965", "host:port specification of where sigsum-log-go serves clients")
	rpcBackend   = flag.String("log_rpc_server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix       = flag.String("prefix", "", "a prefix that proceeds /sigsum/v0/<endpoint>")
	trillianID   = flag.Int64("trillian_id", 0, "log identifier in the Trillian database")
	deadline     = flag.Duration("deadline", time.Second*10, "deadline for backend requests")
	key          = flag.String("key", "", "hex-encoded Ed25519 signing key")
	witnesses    = flag.String("witnesses", "", "comma-separated list of trusted witness verification keys in hex")
	maxRange     = flag.Int64("max_range", 10, "maximum number of entries that can be retrived in a single request")
	interval     = flag.Duration("interval", time.Second*30, "interval used to rotate the log's cosigned STH")
	shardStart   = flag.Int64("shard_interval_start", 0, "start of shard interval since the UNIX epoch in seconds")
	shardEnd     = flag.Int64("shard_interval_end", 0, "end of shard interval since the UNIX epoch in seconds")

	gitCommit = "unknown"
)

func main() {
	flag.Parse()
	defer glog.Flush()
	glog.Infof("sigsum-log-go git-commit %s", gitCommit)

	// wait for clean-up before exit
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	glog.V(3).Infof("configuring sigsum-log-go instance...")
	instance, err := setupInstanceFromFlags()
	if err != nil {
		glog.Errorf("setupInstance: %v", err)
		return
	}

	glog.V(3).Infof("spawning state manager")
	go func() {
		wg.Add(1)
		defer wg.Done()
		instance.Stateman.Run(ctx)
		glog.Errorf("state manager shutdown")
		cancel() // must have state manager running
	}()

	glog.V(3).Infof("spawning await")
	server := http.Server{Addr: *httpEndpoint}
	go await(ctx, func() {
		wg.Add(1)
		defer wg.Done()
		ctxInner, _ := context.WithTimeout(ctx, time.Second*60)
		glog.Infof("Shutting down HTTP server...")
		server.Shutdown(ctxInner)
		glog.V(3).Infof("HTTP server shutdown")
		glog.Infof("Shutting down spawned go routines...")
		cancel()
	})

	glog.Infof("Serving on %v/%v", *httpEndpoint, *prefix)
	if err = server.ListenAndServe(); err != http.ErrServerClosed {
		glog.Errorf("ListenAndServe: %v", err)
	}
}

// SetupInstance sets up a new sigsum-log-go instance from flags
func setupInstanceFromFlags() (*sigsum.Instance, error) {
	var i sigsum.Instance
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
	i.ShardEnd = uint64(*shardEnd)
	if *shardEnd < *shardStart {
		return nil, fmt.Errorf("shard end must be larger than shard start")
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
	i.Client = &trillianWrapper.TrillianClient{
		TreeID: i.TreeID,
		GRPC:   trillian.NewTrillianLogClient(conn),
	}

	// Setup state manager
	i.Stateman, err = state.NewStateManagerSingle(i.Client, i.Signer, i.Interval, i.Deadline)
	if err != nil {
		return nil, fmt.Errorf("NewStateManager: %v", err)
	}

	// Setup DNS verifier
	i.DNS = dns.NewDefaultResolver()

	// Register HTTP endpoints
	mux := http.NewServeMux()
	http.Handle("/", mux)
	for _, handler := range i.Handlers() {
		glog.V(3).Infof("adding handler: %s", handler.Path())
		mux.Handle(handler.Path(), handler)
	}
	glog.V(3).Infof("Adding prometheus handler on path: /metrics")
	http.Handle("/metrics", promhttp.Handler())

	return &i, nil
}

func newLogIdentity(key string) (crypto.Signer, string, error) {
	buf, err := hex.DecodeString(key)
	if err != nil {
		return nil, "", fmt.Errorf("DecodeString: %v", err)
	}
	sk := crypto.Signer(ed25519.PrivateKey(buf))
	vk := sk.Public().(ed25519.PublicKey)
	return sk, hex.EncodeToString([]byte(vk[:])), nil
}

// newWitnessMap creates a new map of trusted witnesses
func newWitnessMap(witnesses string) (map[[types.HashSize]byte][types.VerificationKeySize]byte, error) {
	w := make(map[[types.HashSize]byte][types.VerificationKeySize]byte)
	if len(witnesses) > 0 {
		for _, witness := range strings.Split(witnesses, ",") {
			b, err := hex.DecodeString(witness)
			if err != nil {
				return nil, fmt.Errorf("DecodeString: %v", err)
			}

			var vk [types.VerificationKeySize]byte
			if n := copy(vk[:], b); n != types.VerificationKeySize {
				return nil, fmt.Errorf("Invalid verification key size: %v", n)
			}
			w[*types.Hash(vk[:])] = vk
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
	glog.V(3).Info("received shutdown signal")
	done()
}
