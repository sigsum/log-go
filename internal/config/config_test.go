package config

import (
	"os"
	"strings"
	"testing"
)

var testConfig = `
external-endpoint = "localhost:6965"
internal-endpoint = "localhost:6967"
trillian-rpc-server = "localhost:6962"
backend = "trillian"
url-prefix = ""
trillian-tree-id-file = "/var/lib/sigsum-log/tree-id"
timeout = "10s"
interval = "30s"
key-file = "test"
log-file = ""
log-level = "info"

[primary]
max-range = 10
rate-limit-file = ""
allow-test-domain = false
secondary-url = ""
secondary-pubkey-file = ""
sth-file = "/var/lib/sigsum-log/sth"

[secondary]
primary-url = "http://localhost:9091"
`

func TestReadConfig(t *testing.T) {
	r := strings.NewReader(testConfig)
	conf, err := LoadConfig(r)
	if err != nil {
		t.Fatalf("Failed read configuration: %v", err)
	}
	if conf.Primary.SthFile != "/var/lib/sigsum-log/sth" {
		t.Fatalf("Failed to parse primary configuration")
	}
	if conf.Secondary.PrimaryURL != "http://localhost:9091" {
		t.Fatalf("Failed to parse primary configuration")
	}
}

func TestReadExampleConfigFile(t *testing.T) {
	example_config := "../../doc/config.toml.example"
	confFile, err := os.Open(example_config)
	if err != nil {
		t.Fatalf("Failed to open example_config file")
	}
	_, err = LoadConfig(confFile)
	if err != nil {
		t.Fatalf("Failed read configuration: %v", err)
	}
}
