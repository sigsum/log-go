package rateLimit

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

type DomainDb struct {
	// The suffix sets are not modified after construction, hence need no locking.

	// Represents a plain rule, "example.com".
	suffixes map[string]bool
	// Represents a wildcard rule, "*.example.org", and
	// exceptions, "!foo.example.org".
	wildcards map[string]map[string]bool
}

func (db *DomainDb) getSuffix(domain string) (string, error) {
	s := domain
	for {
		if db.suffixes[s] {
			return s, nil
		}
		dot := strings.IndexByte(s, '.')
		if dot < 0 {
			return "", fmt.Errorf("no known suffix on domain: %q", domain)
		}
		label := s[:dot]
		next := s[dot+1:]

		if m := db.wildcards[next]; m != nil && !m[label] {
			return s, nil
		}
		s = next
	}
}

// The registered domain is the recognized suffix + one additional label.
func (db *DomainDb) GetRegisteredDomain(domain string) (string, error) {
	suffix, err := db.getSuffix(domain)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(domain, suffix) {
		panic(fmt.Sprintf("internal error, domain %q and supposed suffix %q",
			domain, suffix))
	}
	if domain == suffix {
		// There is no additional albel, return domain as is.
		return domain, nil
	}
	dot := strings.LastIndexByte(domain[:len(domain)-len(suffix)-1], '.')
	if dot < 0 {
		// Only one additional label.
		return domain, nil
	}
	// Omit additional labels.
	return domain[dot+1:], nil
}

type exception struct {
	label    string
	wildcard string
}

func parseException(b []byte, lineno int) (exception, error) {
	e := bytes.TrimPrefix(b, []byte{'!'})
	dot := bytes.Index(e, []byte{'.'})
	if dot < 0 {
		return exception{}, fmt.Errorf("invalid exception rule %q on line %d", b, lineno)
	}
	return exception{label: string(e[:dot]), wildcard: string(e[dot+1:])}, nil
}

func parseSuffixFile(suffixFile io.Reader) (map[string]bool, map[string]map[string]bool, error) {
	lineno := 0
	suffixes := make(map[string]bool)
	wildcards := make(map[string]map[string]bool)
	exceptions := []exception{}

	// Parse file, populate suffixes and wildcard mappings, and record exceptions for later.
	for scanner := bufio.NewScanner(suffixFile); scanner.Scan(); {
		lineno++
		b := bytes.TrimSpace(scanner.Bytes())

		if len(b) == 0 {
			continue
		}
		switch b[0] {
		case '/':
			if !bytes.HasPrefix(b, []byte("//")) {
				return nil, nil, fmt.Errorf("malformed comment on line %d", lineno)
			}
			continue
		case '!':
			exception, err := parseException(b[1:], lineno)
			if err != nil {
				return nil, nil, err
			}
			exceptions = append(exceptions, exception)
		case '*':
			if !bytes.HasPrefix(b, []byte("*.")) {
				return nil, nil, fmt.Errorf("invalid wildcard rule %q on line %d", b, lineno)
			}
			wildcards[string(b[2:])] = make(map[string]bool)
		default:
			suffixes[string(b)] = true
		}
	}
	for _, e := range exceptions {
		if wildcards[e.wildcard] == nil {
			return nil, nil, fmt.Errorf("exception for non-existent wildcard *.%q", e.wildcard)
		}
		wildcards[e.wildcard][e.label] = true
	}
	return suffixes, wildcards, nil
}

// The suffix file must be in the format of
// https://publicsuffix.org/list/.
func NewDomainDb(suffixFile io.Reader) (DomainDb, error) {
	suffixes, wildcards, err := parseSuffixFile(suffixFile)
	if err != nil {
		return DomainDb{}, err
	}
	return DomainDb{
		suffixes:  suffixes,
		wildcards: wildcards,
	}, nil
}
