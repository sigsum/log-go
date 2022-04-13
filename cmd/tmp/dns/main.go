package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"git.sigsum.org/sigsum-go/pkg/hex"
	"git.sigsum.org/sigsum-go/pkg/types"
	"git.sigsum.org/sigsum-log-go/pkg/dns"
)

var (
	vk          = flag.String("vk", "5aed7ffc3bc088221f6579567b2e6e3c4ac3579bd5e77670755179052c68d5d3", "verification key (hex)")
	domain_hint = flag.String("domain_hint", "example.com", "domain name that is aware of public key hash in hex")
)

func main() {
	flag.Parse()

	var key types.PublicKey
	mustDecodeHex(*vk, key[:])

	vf := dns.NewDefaultResolver()
	if err := vf.Verify(context.Background(), *domain_hint, &key); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Success!")
}

func mustDecodeHex(s string, buf []byte) {
	b, err := hex.Deserialize(s)
	if err != nil {
		log.Fatal(err)
	}
	if len(b) != len(buf) {
		log.Fatal("bad flag: invalid buffer length")
	}
	copy(buf, b)
}
