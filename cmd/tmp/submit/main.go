package main

// go run . | bash

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"git.sigsum.org/sigsum-log-go/pkg/types"
)

var (
	shardHint  = flag.Uint64("shard_hint", 0, "shard hint (decimal)")
	checksum   = flag.String("checksum", "", "checksum (hex)")
	sk         = flag.String("sk", "", "secret key (hex)")
	domainHint = flag.String("domain_hint", "example.com", "domain hint (string)")
	base_url   = flag.String("base_url", "localhost:6965", "base url (string)")
)

func main() {
	flag.Parse()

	var privBuf [64]byte
	var priv ed25519.PrivateKey = ed25519.PrivateKey(privBuf[:])
	mustDecodeHex(*sk, priv[:])

	var c [types.HashSize]byte
	if *checksum != "" {
		mustDecodeHex(*checksum, c[:])
	} else {
		mustPutRandom(c[:])
	}

	msg := types.Message{
		ShardHint: *shardHint,
		Checksum:  &c,
	}
	sig := ed25519.Sign(priv, msg.Marshal())

	fmt.Printf("echo \"shard_hint=%d\nchecksum=%x\nsignature=%x\nverification_key=%x\ndomain_hint=%s\" | curl --data-binary @- %s/sigsum/v0/add-leaf\n",
		msg.ShardHint,
		msg.Checksum[:],
		sig,
		priv.Public().(ed25519.PublicKey)[:],
		*domainHint,
		*base_url,
	)
}

func mustDecodeHex(s string, buf []byte) {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	if len(b) != len(buf) {
		log.Fatal("bad flag: invalid buffer length")
	}
	copy(buf, b)
}

func mustPutRandom(buf []byte) {
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
}
