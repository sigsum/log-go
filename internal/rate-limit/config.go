package rateLimit

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	submitToken "sigsum.org/sigsum-go/pkg/submit-token"
)

type Config struct {
	// Allowlists, and their daily request limit.
	AllowedKeys      map[string]int // map key is the binary key hash.
	AllowedDomains   map[string]int // map key lowercase domain.
	AllowPublic      int
	PublicSuffixFile string
}

// Config file syntax is
//   key <hash> <limit>
//   domain <name> <limit>
//   public <suffix file> <limit>
// with # used for comments.

// The type of config lines. None represent an empty or comment-only line.
type configToken int

const (
	configNone configToken = iota
	configKey
	configDomain
	configPublic
)

func parseToken(s []byte) (configToken, error) {
	switch {
	case bytes.Equal(s, []byte("key")):
		return configKey, nil
	case bytes.Equal(s, []byte("domain")):
		return configDomain, nil
	case bytes.Equal(s, []byte("public")):
		return configPublic, nil
	default:
		return configNone, fmt.Errorf("unknown config keyword %q", s)
	}
}

func parseLimit(s []byte) (int, error) {
	// Use ParseUint, to not accept leading +/-.
	i, err := strconv.ParseUint(string(s), 10, 32)
	if err != nil {
		return 0, err
	}
	// Limit to 32-bit, so we can always use int.
	if i >= (1 << 31) {
		return 0, fmt.Errorf("limit %q is too large", s)
	}
	return int(i), nil
}

func parseLine(line []byte) (configToken, string, int, error) {
	if comment := bytes.Index(line, []byte{'#'}); comment >= 0 {
		line = line[:comment]
	}
	// TODO: Support quoted file name for public.
	fields := bytes.Fields(line)
	if len(fields) == 0 {
		return configNone, "", 0, nil
	}

	if len(fields) != 3 {
		return 0, "", 0, fmt.Errorf("invalid config line %q", line)
	}
	token, err := parseToken(fields[0])
	if err != nil {
		return 0, "", 0, err
	}

	limit, err := parseLimit(fields[2])
	if err != nil {
		return 0, "", 0, err
	}

	item := string(fields[1])

	// Validate item format.
	switch token {
	case configKey:
		b, err := hex.DecodeString(item)
		if err != nil {
			return 0, "", 0, err
		}
		if len(b) != 32 {
			return 0, "", 0, fmt.Errorf("invalid length of key hash %q", item)
		}
		item = string(b)
	case configDomain:
		// Normalize, to be consistent with IDNA2008 (two
		// different-looking domains that will ultimately be
		// looked up to the same DNS records should be
		// normalized to the same string).
		var err error
		item, err = submitToken.NormalizeDomainName(item)
		if err != nil {
			return 0, "", 0, err
		}
	}
	return token, item, limit, nil
}

func ParseConfig(file io.Reader) (Config, error) {
	config := Config{
		AllowedKeys:    make(map[string]int),
		AllowedDomains: make(map[string]int),
	}
	publicSeen := false
	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		configType, item, limit, err := parseLine(scanner.Bytes())
		if err != nil {
			return Config{}, err
		}
		switch configType {
		case configNone:
			// Do nothing
		case configKey:
			if _, ok := config.AllowedKeys[item]; ok {
				return Config{}, fmt.Errorf("invalid multiple key %x", item)
			}
			config.AllowedKeys[item] = limit
		case configDomain:
			if _, ok := config.AllowedDomains[item]; ok {
				return Config{}, fmt.Errorf("invalid multiple domain %s", item)
			}
			config.AllowedDomains[item] = limit
		case configPublic:
			if publicSeen {
				return Config{}, fmt.Errorf("invalid multiple \"public\" lines in rate-limit configuration")
			}
			config.AllowPublic = limit
			config.PublicSuffixFile = item
			publicSeen = true
		default:
			panic("internal error in parsing rate limit config")
		}
	}
	return config, nil
}
