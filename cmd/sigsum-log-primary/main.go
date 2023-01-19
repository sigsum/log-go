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

	"sigsum.org/log-go/internal/config"
	"sigsum.org/log-go/internal/db"
	"sigsum.org/log-go/internal/node/primary"
	rateLimit "sigsum.org/log-go/internal/rate-limit"
	"sigsum.org/log-go/internal/state"
	"sigsum.org/log-go/internal/utils"
	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	token "sigsum.org/sigsum-go/pkg/submit-token"
)

var (
	gitCommit = "unknown"
)

func ParseFlags(c *config.Config) {
	flag.StringVar(&c.Primary.Witnesses, "witnesses", c.Primary.Witnesses, "comma-separated list of trusted witness public keys in hex")
	flag.StringVar(&c.Primary.RateLimitConfig, "rate-limit-config", c.Primary.RateLimitConfig, "enable rate limiting, based on given config file")
	flag.BoolVar(&c.Primary.AllowTestDomain, "allow-test-domain", c.Primary.AllowTestDomain, "allow submit tokens from test.sigsum.org")
	flag.StringVar(&c.Primary.SecondaryURL, "secondary-url", c.Primary.SecondaryURL, "secondary node endpoint for fetching latest replicated tree head")
	flag.StringVar(&c.Primary.SecondaryPubkey, "secondary-pubkey", c.Primary.SecondaryPubkey, "hex-encoded Ed25519 public key for secondary node")
	flag.StringVar(&c.Primary.SthStorePath, "sth-path", c.Primary.SthStorePath, "path to file where latest published STH is being stored")
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
	publicKey, signer, err := utils.ReadKeyFile(conf.Key)
	if err != nil {
		return nil, fmt.Errorf("newLogIdentity: %v", err)
	}

	// Proxy over values from config.Config to the old Config struct
	// TODO: Refactor this handling
	p.Config.LogID = hex.EncodeToString(publicKey[:])
	p.Config.Timeout = conf.Timeout
	p.MaxRange = conf.MaxRange
	witnessMap, err := newWitnessMap(conf.Primary.Witnesses)
	if err != nil {
		return nil, fmt.Errorf("newWitnessMap: %v", err)
	}

	if conf.EphemeralBackend {
		p.DbClient = db.NewMemoryDb()
	} else {
		// Setup trillian client.
		dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(p.Config.Timeout)}
		conn, err := grpc.Dial(conf.RpcBackend, dialOpts...)
		if err != nil {
			return nil, fmt.Errorf("Dial: %v", err)
		}
		p.DbClient = &db.TrillianClient{
			TreeID: conf.TreeID,
			GRPC:   trillian.NewTrillianLogClient(conn),
		}
	}
	// Setup secondary node configuration.
	var secondary client.Client
	if conf.Primary.SecondaryURL != "" && conf.Primary.SecondaryPubkey != "" {
		pubkey, err := crypto.PublicKeyFromHex(conf.Primary.SecondaryPubkey)
		if err != nil {
			return nil, fmt.Errorf("invalid secondary node pubkey: %v", err)
		}
		secondary = client.New(client.Config{
			LogURL: conf.Primary.SecondaryURL,
			LogPub: pubkey,
		})
	}

	// Setup state manager.
	p.Stateman, err = state.NewStateManagerSingle(p.DbClient, signer, p.Config.Timeout,
		secondary, conf.Primary.SthStorePath, witnessMap)
	if err != nil {
		return nil, fmt.Errorf("NewStateManagerSingle: %v", err)
	}

	p.TokenVerifier = token.NewDnsVerifier(&publicKey)
	if len(conf.Primary.RateLimitConfig) > 0 {
		f, err := os.Open(conf.Primary.RateLimitConfig)
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

	// TODO: verify that GRPC.TreeType() == LOG.

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
