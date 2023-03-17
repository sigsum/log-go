package config

import (
	"strings"
	"testing"
)

var testConfig = `
external-endpoint = "localhost:6965"
internal-endpoint = "localhost:6967"
trillian-rpc-server = "localhost:6962"
ephemeral-backend = false
url-prefix = ""
tree-id = 0
timeout = "10s"
interval = "30s"
key = "test"
log-file = ""
log-level = "info"

[primary]
witnesses = ""
max-range = 10
rate-limit-config = ""
allow-test-domain = false
secondary-url = ""
secondary-pubkey = ""
sth-path = "/var/lib/sigsum-log/sth"

[secondary]
primary-url = "http://localhost:9091"
`

func TestReadConfig(t *testing.T) {
	r := strings.NewReader(testConfig)
	conf, err := LoadConfig(r)
	if err != nil {
		t.Fatalf("Failed read configuration: %v", err)
	}
	if conf.Primary.SthStorePath != "/var/lib/sigsum-log/sth" {
		t.Fatalf("Failed to parse primary configuration")
	}
	if conf.Secondary.PrimaryURL != "http://localhost:9091" {
		t.Fatalf("Failed to parse primary configuration")
	}
}
