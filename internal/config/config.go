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
	Prefix             string        `toml:"url-prefix"`
	Timeout            time.Duration `toml:"timeout"`
	Interval           time.Duration `toml:"interval"`
	LogFile            string        `toml:"log-file"`
	LogLevel           string        `toml:"log-level"`
	ExternalEndpoint   string        `toml:"external-endpoint"`
	InternalEndpoint   string        `toml:"internal-endpoint"`
	TrillianRpcServer  string        `toml:"trillian-rpc-server"`
	Backend            string        `toml:"backend"`
	TrillianTreeIDFile string        `toml:"trillian-tree-id-file"`
	KeyFile            string        `toml:"key-file"`
	Primary            `toml:"primary"`
	Secondary          `toml:"secondary"`
}

func NewConfig() *Config {
	// Initialize default configuration
	return &Config{
		ExternalEndpoint:   "localhost:6965",
		InternalEndpoint:   "localhost:6967",
		TrillianRpcServer:  "localhost:6962",
		Backend:            "trillian",
		Prefix:             "",
		TrillianTreeIDFile: "/var/lib/sigsum-log/tree-id",
		Timeout:            time.Second * 10,
		KeyFile:            "",
		Interval:           time.Second * 30,
		LogFile:            "",
		LogLevel:           "info",
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
	set.FlagLong(&c.ExternalEndpoint, "external-endpoint", 0, "TCP listen port for serving clients.", "host:port")
	set.FlagLong(&c.InternalEndpoint, "internal-endpoint", 0, "Internal TCP listen port, for stats and replication with other nodes.", "host:port")
	set.FlagLong(&c.TrillianRpcServer, "trillian-rpc-server", 0, "TCP port used by the Trillian backend server.", "host:port")
	set.FlagLong(&c.Backend, "backend", 0, "If set to \"ephemeral\", enables in-memory backend, with NO persistent storage.")
	set.FlagLong(&c.Prefix, "url-prefix", 0, "A prefix that precedes /<endpoint>.", "string")
	set.FlagLong(&c.TrillianTreeIDFile, "trillian-tree-id-file", 0, "tree identifier in the Trillian database.", "file")
	set.FlagLong(&c.Timeout, "timeout", 0, "Timeout for outgoing requests.")
	set.FlagLong(&c.KeyFile, "key-file", 0, "Key file (openssh format), either unencrypted private key, or a public key (accessed via ssh-agent).", "file")
	set.FlagLong(&c.Interval, "interval", 0, "Interval used to rotate the log's cosigned tree head.")
	set.FlagLong(&c.LogFile, "log-file", 0, "File to write logs to, or stderr if unset.", "file")
	set.FlagLong(&c.LogLevel, "log-level", 0, "Log level (Available options: debug, info, warning, error).", "level")
	set.FlagLong(&c.MaxRange, "max-range", 0, "Maximum number of leaves that can be retrived in a single request.")
}
