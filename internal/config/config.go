package config

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	getopt "github.com/pborman/getopt/v2"
)

// Primary Config
type Primary struct {
	RateLimitFile       string `toml:"rate-limit-file"`
	AllowTestDomain     bool   `toml:"allow-test-domain"`
	SecondaryURL        string `toml:"secondary-url"`
	SecondaryPubkeyFile string `toml:"secondary-pubkey-file"`
	SthFile             string `toml:"sth-file"`
	MaxRange            int    `toml:"max-range"`
}

// Secondary Config
type Secondary struct {
	PrimaryURL string `toml:"primary-url"`
}

type Config struct {
	Prefix            string        `toml:"url-prefix"`
	Timeout           time.Duration `toml:"timeout"`
	Interval          time.Duration `toml:"interval"`
	LogFile           string        `toml:"log-file"`
	LogLevel          string        `toml:"log-level"`
	ExternalEndpoint  string        `toml:"external-endpoint"`
	InternalEndpoint  string        `toml:"internal-endpoint"`
	TrillianRpcServer string        `toml:"trillian-rpc-server"`
	Backend           string        `toml:"backend"`
	TrillianIDFile    string        `toml:"trillian-id-file"`
	KeyFile           string        `toml:"key-file"`
	Primary           `toml:"primary"`
	Secondary         `toml:"secondary"`
}

func NewConfig() *Config {
	// Initialize default configuration
	return &Config{
		ExternalEndpoint:  "localhost:6965",
		InternalEndpoint:  "localhost:6967",
		TrillianRpcServer: "localhost:6962",
		Backend:           "trillian",
		Prefix:            "",
		TrillianIDFile:    "/var/lib/sigsum-log/tree-id",
		Timeout:           time.Second * 10,
		KeyFile:           "",
		Interval:          time.Second * 30,
		LogFile:           "",
		LogLevel:          "info",
		Primary: Primary{
			RateLimitFile:       "",
			AllowTestDomain:     false,
			SecondaryURL:        "",
			SecondaryPubkeyFile: "",
			SthFile:             "/var/lib/sigsum-log/sth",
			MaxRange:            10,
		},
		Secondary: Secondary{
			PrimaryURL: "",
		},
	}
}

func LoadConfig(f io.Reader) (*Config, error) {
	conf := NewConfig()
	metadata, err := toml.NewDecoder(f).Decode(&conf)
	if err != nil {
		return nil, err
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown keywords: %v", undecoded)
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
	set.FlagLong(&c.TrillianRpcServer, "trillian-rpc-server", 0, "host:port specification of where Trillian serves clients")
	set.FlagLong(&c.Backend, "backend", 0, "if set to \"ephemeral\", enables in-memory backend, with NO persistent storage")
	set.FlagLong(&c.Prefix, "url-prefix", 0, "a prefix that precedes /<endpoint>")
	set.FlagLong(&c.TrillianIDFile, "trillian-id-file", 0, "tree identifier in the Trillian database")
	set.FlagLong(&c.Timeout, "timeout", 0, "timeout for backend requests")
	set.FlagLong(&c.KeyFile, "key-file", 0, "key file (openssh format), either unencrypted private key, or a public key (accessed via ssh-agent)")
	set.FlagLong(&c.Interval, "interval", 0, "interval used to rotate the log's cosigned STH")
	set.FlagLong(&c.LogFile, "log-file", 0, "file to write logs to (Default: stderr)")
	set.FlagLong(&c.LogLevel, "log-level", 0, "log level (Available options: debug, info, warning, error. Default: info)")
	set.FlagLong(&c.MaxRange, "max-range", 0, "maximum number of entries that can be retrived in a single request")
}
