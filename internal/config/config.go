package config

import (
	"io"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	getopt "github.com/pborman/getopt/v2"
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
	PrimaryURL string `toml:"primary-url"`
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
			PrimaryURL: "",
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

func (c *Config) ServerFlags(set *getopt.Set) {
	set.FlagLong(&c.ExternalEndpoint, "external-endpoint", 0, "host:port specification of where sigsum-log-primary serves clients")
	set.FlagLong(&c.InternalEndpoint, "internal-endpoint", 0, "host:port specification of where sigsum-log-primary serves other log nodes")
	set.FlagLong(&c.RpcBackend, "trillian-rpc-server", 0, "host:port specification of where Trillian serves clients")
	set.FlagLong(&c.EphemeralBackend, "ephemeral-test-backend", 0, "if set, enables in-memory backend, with NO persistent storage")
	set.FlagLong(&c.Prefix, "url-prefix", 0, "a prefix that precedes /<endpoint>")
	set.FlagLong(&c.TreeID, "tree-id", 0, "tree identifier in the Trillian database")
	set.FlagLong(&c.Timeout, "timeout", 0, "timeout for backend requests")
	set.FlagLong(&c.Key, "key", 0, "key file (openssh format), either unencrypted private key, or a public key (accessed via ssh-agent)")
	set.FlagLong(&c.Interval, "interval", 0, "interval used to rotate the log's cosigned STH")
	set.FlagLong(&c.LogFile, "log-file", 0, "file to write logs to (Default: stderr)")
	set.FlagLong(&c.LogLevel, "log-level", 0, "log level (Available options: debug, info, warning, error. Default: info)")
	set.FlagLong(&c.MaxRange, "max-range", 0, "maximum number of entries that can be retrived in a single request")
}
