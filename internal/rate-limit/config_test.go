package rateLimit

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func parseConfigString(s string) (Config, error) {
	return ParseConfig(bytes.NewBuffer([]byte(s)))
}

var key1 = crypto.HashBytes([]byte{1})
var key2 = crypto.HashBytes([]byte{2})

func keyLine(h *crypto.Hash, limit int) string {
	return fmt.Sprintf("key %x %d", *h, limit)
}
func domainLine(d string, limit int) string {
	return fmt.Sprintf("domain %s %d", d, limit)
}
func publicLine(f string, limit int) string {
	return fmt.Sprintf("public %s %d", f, limit)
}

func configFileForTest() string {
	return strings.Join([]string{
		keyLine(&key1, 10),
		" " + keyLine(&key2, 20),
		"\t" + domainLine("example.Net", 30) + "\t",
		"   # comment ",
		domainLine("WWW.example.org", 40) + " #comment",
	},
		"\n") + "\n"
}

func TestParseConfigWithPublic(t *testing.T) {
	configFile := configFileForTest() +
		publicLine("suffixes.dat", 50) + "\n"
	config, err := parseConfigString(configFile)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(config.AllowedKeys) != 2 {
		t.Errorf("got %d keys, expected 2", len(config.AllowedKeys))
	}
	if got := config.AllowedKeys[string(key1[:])]; got != 10 {
		t.Errorf("got limit %d for key1", got)
	}
	if got := config.AllowedKeys[string(key2[:])]; got != 20 {
		t.Errorf("got limit %d for key1", got)
	}

	if len(config.AllowedDomains) != 2 {
		t.Errorf("got %d domains, expected 2", len(config.AllowedKeys))
	}
	if d, got := "example.net", config.AllowedDomains["example.net"]; got != 30 {
		t.Errorf("got limit %d for domain %s", got, d)
	}
	if d, got := "www.example.org", config.AllowedDomains["www.example.org"]; got != 40 {
		t.Errorf("got limit %d for domain %s", got, d)
	}

	if got := config.AllowPublic; got != 50 {
		t.Errorf("got public limit %d, expected 50", got)
	}
	if got := config.PublicSuffixFile; got != "suffixes.dat" {
		t.Errorf("got unexpected suffix file name %q", got)
	}
}

func TestParseConfigWithoutPublic(t *testing.T) {
	configFile := configFileForTest()
	config, err := parseConfigString(configFile)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(config.AllowedKeys) != 2 {
		t.Errorf("got %d keys, expected 2", len(config.AllowedKeys))
	}
	if got := config.AllowedKeys[string(key1[:])]; got != 10 {
		t.Errorf("got limit %d for key1", got)
	}
	if got := config.AllowedKeys[string(key2[:])]; got != 20 {
		t.Errorf("got limit %d for key1", got)
	}

	if len(config.AllowedDomains) != 2 {
		t.Errorf("got %d domains, expected 2", len(config.AllowedKeys))
	}
	if d, got := "example.net", config.AllowedDomains["example.net"]; got != 30 {
		t.Errorf("got limit %d for domain %s", got, d)
	}
	if d, got := "www.example.org", config.AllowedDomains["www.example.org"]; got != 40 {
		t.Errorf("got limit %d for domain %s", got, d)
	}

	if got := config.AllowPublic; got != 0 {
		t.Errorf("got public limit %d, expected 00", got)
	}
}

func TestParseBadConfig(t *testing.T) {
	configFile := configFileForTest() +
		"public suffixes.dat 50\n"
	for _, s := range []string{
		keyLine(&key1, 0),
		domainLine("eXample.net", 7),
		publicLine("foo.dat", 10),
		domainLine("other.example.com", -10),
	} {
		badConfig := configFile + s + "\n"
		_, err := parseConfigString(badConfig)
		if err == nil {
			t.Errorf("parsing accepted bad input:\n---%s---", badConfig)
		}
	}
}
