package utils

import (
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

func ReadKeyFile(keyFile string) (crypto.PublicKey, crypto.Signer, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return crypto.PublicKey{}, nil, err
	}
	sk, err := crypto.SignerFromHex(strings.TrimSpace(string(buf)))
	if err != nil {
		return crypto.PublicKey{}, nil, fmt.Errorf("invalid private key: %v", err)
	}
	return sk.Public(), sk, nil
}
