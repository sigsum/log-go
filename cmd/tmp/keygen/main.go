package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"

	"git.sigsum.org/sigsum-go/pkg/types"
)

func main() {
	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("GenerateKey: %v", err)
	}
	fmt.Printf("sk: %x\n", sk[:])
	fmt.Printf("vk: %x\n", vk[:])
	fmt.Printf("kh: %x\n", types.HashFn(vk[:])[:])
}
