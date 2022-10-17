package rateLimit

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

type Limiter interface {
	// Checks if access count is < limit. If so increment count
	// and returns a function that can be called to undo the increment, in case no
	// resources were consumed. Otherwise, returns nil.
	AccessAllowed(domain *string, pub *types.PublicKey, now time.Time) func()
}

type NoLimit struct{}

func (l NoLimit) AccessAllowed(_ *string, _ *types.PublicKey, _ time.Time) func() {
	return func() {}
}

var schedulePeriod = 24 * time.Hour
var limitPerPeriod = 50

type schedule struct {
	sync.Mutex
	next time.Time
}

func (s *schedule) IsTime(now time.Time) bool {
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

func (l *limiter) AccessAllowed(submitDomain *string, pub *types.PublicKey, now time.Time) func() {
	if l.resetSchedule.IsTime(now) {
		l.keyCounts.Reset()
		l.domainCounts.Reset()
		l.publicCounts.Reset()
	}

	// TODO: Avoid conversion to string.
	keyHash := string((*merkle.HashFn((*pub)[:]))[:])
	if limit, ok := l.allowedKeys[keyHash]; ok {
		return l.keyCounts.AccessAllowed(keyHash, limit)
	}
	if submitDomain == nil {
		// Skip all domain-based checks.
		return nil
	}
	domain := strings.ToLower(*submitDomain)
	if relax, ok := l.domainAllowed(domain); ok {
		return relax
	}
	if l.allowPublic <= 0 {
		return nil
	}

	domain, err := l.domainDb.GetRegisteredDomain(domain)
	if err != nil {
		// TODO: Log error somehow?
		return nil
	}
	return l.publicCounts.AccessAllowed(domain, l.allowPublic)
}

func NewLimiter(configFile io.Reader, now time.Time) (Limiter, error) {
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

	l := limiter{
		allowedKeys:    config.AllowedKeys,
		allowedDomains: config.AllowedDomains,
		allowPublic:    config.AllowPublic,
		domainDb:       db,
		resetSchedule:  schedule{next: now.Add(schedulePeriod)},
	}

	// Initialize the mappings.
	l.keyCounts.Reset()
	l.domainCounts.Reset()
	l.publicCounts.Reset()

	return &l, nil
}
