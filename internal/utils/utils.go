package utils

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/types"
)

func LogToFile(logFile string) error {
	if len(logFile) != 0 {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err;
		}
		log.SetOutput(f)
	}
	return nil
}

func PubkeyFromHexString(pkhex string) (*types.PublicKey, error) {
	pkbuf, err := hex.DecodeString(pkhex)
	if err != nil {
		return nil, fmt.Errorf("DecodeString: %v", err)
	}

	var pk types.PublicKey
	if n := copy(pk[:], pkbuf); n != types.PublicKeySize {
		return nil, fmt.Errorf("invalid pubkey size: %v", n)
	}

	return &pk, nil
}

func NewLogIdentity(keyFile string) (crypto.Signer, string, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, "", err
	}
	if buf, err = hex.DecodeString(strings.TrimSpace(string(buf))); err != nil {
		return nil, "", fmt.Errorf("DecodeString: %v", err)
	}
	sk := crypto.Signer(ed25519.NewKeyFromSeed(buf))
	vk := sk.Public().(ed25519.PublicKey)
	return sk, hex.EncodeToString([]byte(vk[:])), nil
}
