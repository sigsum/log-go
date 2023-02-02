package config

import (
	"flag"
	"io"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Primary Config
type Primary struct {
	Witnesses       string `toml:"witnesses"`
	RateLimitConfig string `toml:"rate-limit-config"`
	AllowTestDomain bool   `toml:"allow-test-domain"`
	SecondaryURL    string `toml:"secondary-url"`
	SecondaryPubkey string `toml:"secondary-pubkey"`
	SthStorePath    string `toml:"sth-path"`
}

// Secondary Config
type Secondary struct {
	PrimaryURL    string `toml:"primary-url"`
	PrimaryPubkey string `toml:"primary-pubkey"`
}

type Config struct {
	Prefix           string        `toml:"url-prefix"`
	MaxRange         int           `toml:"max-range"`
	Timeout          time.Duration `toml:"timeout"`
	Interval         time.Duration `toml:"interval"`
	LogFile          string        `toml:"log-file"`
	LogLevel         string        `toml:"log-level"`
	ExternalEndpoint string        `toml:"external-endpoint"`
	InternalEndpoint string        `toml:"internal-endpoint"`
	RpcBackend       string        `toml:"rpc-backend"`
	EphemeralBackend bool          `toml:"ephemeral-backend"`
	TreeID           int64         `toml:"tree-id"`
	Key              string        `toml:"key"`
	Primary          `toml:"primary"`
	Secondary        `toml:"secondary"`
}

func NewConfig() *Config {
	// Initialize default configuration
	return &Config{
		ExternalEndpoint: "localhost:6965",
		InternalEndpoint: "localhost:6967",
		RpcBackend:       "localhost:6962",
		EphemeralBackend: false,
		Prefix:           "",
		TreeID:           0,
		Timeout:          time.Second * 10,
		Key:              "",
		Interval:         time.Second * 30,
		LogFile:          "",
		LogLevel:         "info",
		MaxRange:         10,
		Primary: Primary{
			Witnesses:       "",
			RateLimitConfig: "",
			AllowTestDomain: false,
			SecondaryURL:    "",
			SecondaryPubkey: "",
			SthStorePath:    "/var/lib/sigsum-log/sth",
		},
		Secondary: Secondary{
			PrimaryURL:    "",
			PrimaryPubkey: "",
		},
	}
}

func LoadConfig(f io.Reader) (*Config, error) {
	conf := NewConfig()
	if _, err := toml.NewDecoder(f).Decode(&conf); err != nil {
		return nil, err
	}
	return conf, nil
}

func OpenConfigFile() (io.Reader, error) {
	var f io.Reader
	var err error
	if conf, b := os.LookupEnv("SIGSUM_LOGSERVER_CONFIG"); b {
		if f, err = os.Open(conf); err == nil {
			return f, nil
		} else {
			return f, err
		}
	}
	default_config := "/etc/sigsum/config.toml"
	if f, err = os.Open(default_config); err == nil {
		return f, nil
	} else {
		return f, err
	}
}

func ServerFlags(c *Config) {
	flag.StringVar(&c.ExternalEndpoint, "external-endpoint", c.ExternalEndpoint, "host:port specification of where sigsum-log-primary serves clients")
	flag.StringVar(&c.InternalEndpoint, "internal-endpoint", c.InternalEndpoint, "host:port specification of where sigsum-log-primary serves other log nodes")
	flag.StringVar(&c.RpcBackend, "trillian-rpc-server", c.RpcBackend, "host:port specification of where Trillian serves clients")
	flag.BoolVar(&c.EphemeralBackend, "ephemeral-test-backend", c.EphemeralBackend, "if set, enables in-memory backend, with NO persistent storage")
	flag.StringVar(&c.Prefix, "url-prefix", c.Prefix, "a prefix that precedes /<endpoint>")
	flag.Int64Var(&c.TreeID, "tree-id", c.TreeID, "tree identifier in the Trillian database")
	flag.DurationVar(&c.Timeout, "timeout", c.Timeout, "timeout for backend requests")
	flag.StringVar(&c.Key, "key", c.Key, "key file (openssh format), either unencrypted private key, or a public key (accessed via ssh-agent)")
	flag.DurationVar(&c.Interval, "interval", c.Interval, "interval used to rotate the log's cosigned STH")
	flag.StringVar(&c.LogFile, "log-file", c.LogFile, "file to write logs to (Default: stderr)")
	flag.StringVar(&c.LogLevel, "log-level", c.LogLevel, "log level (Available options: debug, info, warning, error. Default: info)")
	flag.IntVar(&c.MaxRange, "max-range", c.MaxRange, "maximum number of entries that can be retrived in a single request")
}
