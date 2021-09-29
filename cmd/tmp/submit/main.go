package main

// go run . | bash

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"git.sigsum.org/sigsum-log-go/pkg/types"
)

func main() {
	checksum := [32]byte{}
	msg := types.Message{
		ShardHint: 0,
		Checksum:  &checksum,
	}

	vk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("ed25519.GenerateKey: %v\n", err)
		return
	}
	sig := ed25519.Sign(sk, msg.Marshal())
	//fmt.Printf("sk: %x\nvk: %x\n", sk[:], vk[:])

	fmt.Printf("echo \"shard_hint=%d\nchecksum=%x\nsignature=%x\nverification_key=%x\ndomain_hint=%s\" | curl --data-binary @- localhost:6965/sigsum/v0/add-leaf\n", msg.ShardHint, msg.Checksum[:], sig, vk[:], "example.com")
}
