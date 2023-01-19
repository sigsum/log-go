package utils

import (
	"fmt"
	"log"
	"os"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
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

func ReadPrivateKeyFile(keyFile string) (crypto.PublicKey, crypto.Signer, error) {
	buf, err := os.ReadFile(keyFile)
	if err != nil {
		return crypto.PublicKey{}, nil, err
	}
	sk, err := key.ParsePrivateKey(string(buf))
	if err != nil {
		return crypto.PublicKey{}, nil, fmt.Errorf("invalid private key: %v", err)
	}
	return sk.Public(), sk, nil
}

func ReadPublicKeyFile(keyFile string) (crypto.PublicKey, error) {
	buf, err := os.ReadFile(keyFile)
	if err != nil {
		return crypto.PublicKey{}, err
	}
	pub, err := key.ParsePublicKey(string(buf))
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("invalid public key: %v", err)
	}
	return pub, nil
}
