package rateLimit

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/submit-token"
)

// This domain has the following registered rate limit key pair
//
//	private: 0000000000000000000000000000000000000000000000000000000000000001
//	public:  4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29
//
// for test purposes.
const testDomain = "test.sigsum.org"

type Limiter interface {
	// Checks if access count is < limit. If so increment count
	// and returns a function that can be called to undo the increment, in case no
	// resources were consumed. Otherwise, returns nil.
	AccessAllowed(domain *string, keyHash *crypto.Hash) func()
}

type NoLimit struct{}

func (l NoLimit) AccessAllowed(_ *string, _ *crypto.Hash) func() {
	return func() {}
}

var schedulePeriod = 24 * time.Hour

type clock interface {
	Now() time.Time
}

type wallTime struct{}

func (_ wallTime) Now() time.Time {
	return time.Now()
}

type schedule struct {
	clock clock
	sync.Mutex
	next time.Time
}

func (s *schedule) IsTime() bool {
	now := s.clock.Now()
	s.Lock()
	defer s.Unlock()
	if now.Before(s.next) {
		return false
	}
	s.next = s.next.Add(schedulePeriod)
	return true
}

type limiter struct {
	allowedKeys    map[string]int
	allowedDomains map[string]int
	allowPublic    int
	domainDb       DomainDb
	keyCounts      accessCounts
	domainCounts   accessCounts
	publicCounts   accessCounts

	resetSchedule schedule
}

// Checks if domain or a suffix of domain is allowed. Second return
// value is true if domain was matched by the allow list.
func (l *limiter) domainAllowed(domain string) (func(), bool) {
	s := domain
	for {
		if limit, ok := l.allowedDomains[s]; ok {
			return l.domainCounts.AccessAllowed(s, limit), true
		}
		dot := strings.Index(s, ".")
		if dot < 0 {
			return nil, false
		}
		s = s[dot+1:]
	}
}

func (l *limiter) AccessAllowed(submitDomain *string, keyHash *crypto.Hash) func() {
	if l.resetSchedule.IsTime() {
		l.keyCounts.Reset()
		l.domainCounts.Reset()
		l.publicCounts.Reset()
	}

	// TODO: Avoid conversion to string.
	keyHashString := string(keyHash[:])
	if limit, ok := l.allowedKeys[keyHashString]; ok {
		return l.keyCounts.AccessAllowed(keyHashString, limit)
	}
	if submitDomain == nil {
		// Skip all domain-based checks.
		return nil
	}
	domain, err := token.NormalizeDomainName(*submitDomain)
	if err != nil {
		return nil
	}
	if relax, ok := l.domainAllowed(domain); ok {
		return relax
	}
	if l.allowPublic <= 0 {
		return nil
	}

	domain, err = l.domainDb.GetRegisteredDomain(domain)
	if err != nil {
		// Reject unknown domains.
		return nil
	}
	return l.publicCounts.AccessAllowed(domain, l.allowPublic)
}

func newLimiter(configFile io.Reader, allowTestDomain bool, clock clock) (Limiter, error) {
	config, err := ParseConfig(configFile)
	if err != nil {
		return nil, err
	}
	var db DomainDb
	if config.AllowPublic > 0 {
		f, err := os.Open(config.PublicSuffixFile)
		if err != nil {
			return nil, err
		}
		db, err = NewDomainDb(f)
		if err != nil {
			return nil, err
		}
	}

	if !allowTestDomain {
		config.AllowedDomains[strings.ToLower(testDomain)] = 0
	}
	l := limiter{
		allowedKeys:    config.AllowedKeys,
		allowedDomains: config.AllowedDomains,
		allowPublic:    config.AllowPublic,
		domainDb:       db,
		resetSchedule: schedule{
			clock: clock,
			next:  clock.Now().Add(schedulePeriod),
		},
	}

	// Initialize the mappings.
	l.keyCounts.Reset()
	l.domainCounts.Reset()
	l.publicCounts.Reset()

	return &l, nil
}

func NewLimiter(configFile io.Reader, allowTestDomain bool) (Limiter, error) {
	return newLimiter(configFile, allowTestDomain, wallTime{})
}
