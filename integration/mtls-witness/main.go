// A dummy "witness" that exits successfully if it sees something on the
// add-checkpoint endpoint, which means mTLS was configured successfully.
// Otherwise this dummy "witness" does a non-zero exit after a timeout.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/server"
)

type witness struct {
	received chan struct{}
}

func (w *witness) AddCheckpoint(context.Context, requests.AddCheckpoint) ([]checkpoint.CosignatureLine, error) {
	select {
	case w.received <- struct{}{}:
	default:
	}
	return nil, nil
}

func run() error {
	certFile := flag.String("cert", "", "Server certificate chain (PEM)")
	keyFile := flag.String("key", "", "Server private key (PEM)")
	caFile := flag.String("ca", "", "Trusted client CA certificates (PEM)")
	timeout := flag.Duration("timeout", 10*time.Second, "Time to wait for a checkpoint")
	flag.Parse()

	ca, err := os.ReadFile(*caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("no CA certificates in %q", *caFile)
	}
	w := &witness{received: make(chan struct{}, 1)}
	srv := &http.Server{
		Addr:    "127.0.0.1:7777",
		Handler: server.NewWitness(&server.Config{}, w),
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  roots,
		},
	}
	defer srv.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServeTLS(*certFile, *keyFile) }()

	select {
	case <-w.received:
		return nil
	case err := <-serveErr:
		return err
	case <-time.After(*timeout):
		return fmt.Errorf("timed out waiting for an mTLS add-checkpoint request")
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
