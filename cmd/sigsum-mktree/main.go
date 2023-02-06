package main

import (
	"flag"
	"os"

	"sigsum.org/log-go/internal/config"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/log"
	"sigsum.org/sigsum-go/pkg/types"
)

func ParseFlags(c *config.Config) {
	flag.StringVar(&c.Key, "key", "", "key file (openssh format), either unencrypted private key, or a public key, with corresponding private key accessed via ssh-agent")
	flag.StringVar(&c.Primary.SthStorePath, "sth-path", c.Primary.SthStorePath, "path to file where latest published STH is being stored")
	flag.Parse()
}

func main() {
	var conf *config.Config
	// Read default values from the Config struct
	confFile, err := config.OpenConfigFile()
	if err != nil {
		log.Info("didn't find configuration file, using defaults: %v", err)
		conf = config.NewConfig()
	} else {
		conf, err = config.LoadConfig(confFile)
		if err != nil {
			log.Fatal("failed to parse config file: %v", err)
		}
	}

	ParseFlags(conf)

	signer, err := key.ReadPrivateKeyFile(conf.Key)
	if err != nil {
		log.Fatal("failed to read private key: %v", err)
	}

	emptyTh := types.TreeHead{RootHash: crypto.HashBytes([]byte(""))}
	emptySth, err := emptyTh.Sign(signer)
	if err != nil {
		log.Fatal("signing tree head failed: %v", err)
	}

	f, err := os.OpenFile(conf.SthStorePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Fatal("opening sth file failed: %v", err)
	}
	// Use explicit Close rather then defer, since we want to
	// check for errors and remove file if we fail to successfully write it.
	if err := emptySth.ToASCII(f); err != nil {
		f.Close()
		os.Remove(conf.SthStorePath)
		log.Fatal("writing sth file failed: %v", err)
	}
	// Explicit Close, to check for error.
	if err := f.Close(); err != nil {
		os.Remove(conf.SthStorePath)
		log.Fatal("closing sth file failed: %v", err)
	}
}
