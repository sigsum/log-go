package main

import (
	"flag"
	"os"
	"time"

	"sigsum.org/log-go/internal/utils"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

var (
	key          = flag.String("key", "", "path to file with hex-encoded Ed25519 private key")
	sthStorePath = flag.String("sth-path", "/var/lib/sigsum-log/sth", "path to file where latest published STH is being stored")
)

func main() {
	flag.Parse()
	publicKey, signer, err := utils.ReadKeyFile(*key)

	if err != nil {
		log.Fatal("failed to read private key: %v", err)
	}

	kh := crypto.HashBytes(publicKey[:])

	emptyTh := types.TreeHead{RootHash: crypto.HashBytes([]byte(""))}
	emptySth, err := emptyTh.Sign(signer, &kh, uint64(time.Now().Unix()))
	if err != nil {
		log.Fatal("signing tree head failed: %v", err)
	}

	f, err := os.OpenFile(*sthStorePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Fatal("opening sth file failed: %v", err)
	}
	// Use explicit Close rather then defer, since we want to
	// check for errors and remove file if we fail to successfully write it.
	if err := emptySth.ToASCII(f); err != nil {
		f.Close()
		os.Remove(*sthStorePath)
		log.Fatal("writing sth file failed: %v", err)
	}
	// Explicit Close, to check for error.
	if err := f.Close(); err != nil {
		os.Remove(*sthStorePath)
		log.Fatal("closing sth file failed: %v", err)
	}
}
