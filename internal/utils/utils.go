package utils

import (
	stdcrypto "crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func LogToFile(logFile string) error {
	if len(logFile) != 0 {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		log.SetOutput(f)
	}
	return nil
}

func ReadKeyFile(keyFile string) (stdcrypto.Signer, *crypto.PublicKey, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	if buf, err = hex.DecodeString(strings.TrimSpace(string(buf))); err != nil {
		return nil, nil, fmt.Errorf("DecodeString: %v", err)
	}
	sk := stdcrypto.Signer(ed25519.NewKeyFromSeed(buf))
	vk := sk.Public().(ed25519.PublicKey)
	var pub crypto.PublicKey
	copy(pub[:], vk)
	return sk, &pub, nil
}
