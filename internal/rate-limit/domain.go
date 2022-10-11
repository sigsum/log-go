package rateLimit

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
)

type DomainDb interface {
	// Returns current access count for domain, as is.
	GetAccessCount(domain string) int
	// Checks if access count is < limit. If so increment count
	// and return true, otherwise, return false.
	AccessAllowed(domain string, limit int) bool
	// Undos increment from a previous AccessAllowed, in case no
	// resources were consumed.
	AccessRelax(domain string)

	// Like GetAccessCount above, but uses the domain's public
	// suffix, and fails if there's no known suffix.
	GetPublicAccessCount(domain string) (int, error)

	// Like AccessAllowed above, but uses the domain's public
	// suffix, and refuses acess if there's no known suffix.
	PublicAccessAllowed(domain string, limit int) bool
	PublicAccessRelax(domain string)

	// Resets all counts to zero (e.g., call daily).
	Reset()
}

type domainDb struct {
	// The suffix sets are not modified after construction, hence need no locking.

	// Represents a plain rule, "example.com".
	suffixes map[string]bool
	// Represents a wildcard rule, "*.example.org", and
	// exceptions, "!foo.example.org".
	wildcards map[string]map[string]bool

	// Protects the counts mapping.
	lock   sync.Mutex
	counts map[string]int
}

func (db *domainDb) GetAccessCount(domain string) int {
	db.lock.Lock()
	defer db.lock.Unlock()
	return db.counts[domain]
}

func (db *domainDb) AccessAllowed(domain string, limit int) bool {
	db.lock.Lock()
	defer db.lock.Unlock()
	if db.counts[domain] >= limit {
		return false
	}
	db.counts[domain]++
	return true
}

func (db *domainDb) AccessRelax(domain string) {
	db.lock.Lock()
	defer db.lock.Unlock()
	// Non-zero count is the expeced case, except if there were a
	// Reset call between AccessAllowed and AccessRelax.
	if db.counts[domain] > 0 {
		db.counts[domain]--
	}
}

func (db *domainDb) Reset() {
	db.lock.Lock()
	defer db.lock.Unlock()
	db.counts = make(map[string]int)
}

func (db *domainDb) getSuffix(domain string) (string, error) {
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
func (db *domainDb) getRegisteredDomain(domain string) (string, error) {
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

func (db *domainDb) GetPublicAccessCount(domain string) (int, error) {
	registeredDomain, err := db.getRegisteredDomain(domain)
	if err != nil {
		return 0, err
	}
	return db.GetAccessCount(registeredDomain), nil
}

func (db *domainDb) PublicAccessAllowed(domain string, limit int) bool {
	registeredDomain, err := db.getRegisteredDomain(domain)
	if err != nil {
		return false
	}
	return db.AccessAllowed(registeredDomain, limit)
}

func (db *domainDb) PublicAccessRelax(domain string) {
	registeredDomain, err := db.getRegisteredDomain(domain)
	if err != nil {
		return
	}
	db.AccessRelax(registeredDomain)
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
		return nil, err
	}
	return &domainDb{
		suffixes:  suffixes,
		wildcards: wildcards,
		counts:    make(map[string]int),
	}, nil
}
