package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"

	"golang.sigsum.org/sigsum-log-go/pkg/types"
)

var (
	url = flag.String("url", "http://localhost:6965/sigsum/v0", "base url")
	sk  = flag.String("sk", "e1d7c494dacb0ddf809a17e4528b01f584af22e3766fa740ec52a1711c59500d711090dd2286040b50961b0fe09f58aa665ccee5cb7ee042d819f18f6ab5046b", "hex key")
)

func main() {
	priv, err := hex.DecodeString(*sk)
	if err != nil {
		log.Fatalf("DecodeString: %v", err)
	}
	sk := ed25519.PrivateKey(priv)
	vk := sk.Public().(ed25519.PublicKey)
	fmt.Printf("sk: %x\nvk: %x\n", sk, vk)

	rsp, err := http.Get(*url + "/get-tree-head-to-sign")
	if err != nil {
		log.Fatalf("Get: %v", err)
	}
	var sth types.SignedTreeHead
	if err := sth.UnmarshalASCII(rsp.Body); err != nil {
		log.Fatalf("UnmarshalASCII: %v", err)
	}
	fmt.Printf("%+v\n", sth)

	msg := sth.TreeHead.Marshal()
	sig := ed25519.Sign(sk, msg)
	sigident := &types.SigIdent{
		KeyHash:   types.Hash(vk[:]),
		Signature: &[types.SignatureSize]byte{},
	}
	copy(sigident.Signature[:], sig)

	buf := bytes.NewBuffer(nil)
	if err := sigident.MarshalASCII(buf); err != nil {
		log.Fatalf("MarshalASCII: %v", err)
	}
	rsp, err = http.Post(*url+"/add-cosignature", "type/sigsum", buf)
	if err != nil {
		log.Fatalf("Post: %v", err)
	}
	fmt.Printf("Status: %v\n", rsp.StatusCode)
}
