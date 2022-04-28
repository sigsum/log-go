package main

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"net/http"

	"git.sigsum.org/sigsum-go/pkg/hex"
	"git.sigsum.org/sigsum-go/pkg/requests"
	"git.sigsum.org/sigsum-go/pkg/types"
)

var (
	url    = flag.String("url", "http://localhost:6965/testonly/sigsum/v0", "base url")
	sk     = flag.String("sk", "e1d7c494dacb0ddf809a17e4528b01f584af22e3766fa740ec52a1711c59500d711090dd2286040b50961b0fe09f58aa665ccee5cb7ee042d819f18f6ab5046b", "witness secret key (hex)")
	log_vk = flag.String("log_vk", "cc0e7294a9d002c33aaa828efba6622ab1ce8ebdb8a795902555c2813133cfe8", "log public key (hex)")
)

func main() {
	flag.Parse()

	log_vk, err := hex.Deserialize(*log_vk)
	if err != nil {
		log.Fatalf("Deserialize: %v", err)
	}

	priv, err := hex.Deserialize(*sk)
	if err != nil {
		log.Fatal(err)
	}
	sk := ed25519.PrivateKey(priv)
	vk := sk.Public().(ed25519.PublicKey)
	fmt.Printf("sk: %x\nvk: %x\n", sk, vk)

	rsp, err := http.Get(*url + "/get-tree-head-to-cosign")
	if err != nil {
		log.Fatal(err)
	}
	var sth types.SignedTreeHead
	if err := sth.FromASCII(rsp.Body); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%+v\n\n", sth)

	namespace := types.HashFn(log_vk)
	witSTH, err := sth.TreeHead.Sign(sk, namespace)
	if err != nil {
		log.Fatal(err)
	}

	req := requests.Cosignature{
		KeyHash:     *types.HashFn(vk[:]),
		Cosignature: witSTH.Signature,
	}
	buf := bytes.NewBuffer(nil)
	if err := req.ToASCII(buf); err != nil {
		log.Fatal(err)
	}

	rsp, err = http.Post(*url+"/add-cosignature", "type/sigsum", buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Status: %v\n", rsp.StatusCode)
}
