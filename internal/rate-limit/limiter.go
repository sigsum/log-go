package rateLimit

import (
	"io"
	"sync"
	"time"
)

type Limiter interface {
	// Checks if access count is < limit. If so increment count
	// and return true, otherwise, return false.
	AccessAllowed(domain string, now time.Time) bool
	// Undos increment from a previous AccessAllowed, in case no
	// resources were consumed.
	AccessRelax(domain string)
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
	domainDb      DomainDb
	resetSchedule schedule
}

func (l *limiter) AccessAllowed(domain string, now time.Time) bool {
	if l.resetSchedule.IsTime(now) {
		l.domainDb.Reset()
	}
	return l.domainDb.PublicAccessAllowed(domain, limitPerPeriod)
}

func (l *limiter) AccessRelax(domain string) {
	l.domainDb.PublicAccessRelax(domain)
}

func NewLimiter(suffixFile io.Reader, now time.Time) (Limiter, error) {
	db, err := NewDomainDb(suffixFile)
	if err != nil {
		return nil, err
	}
	return &limiter{
		domainDb:      db,
		resetSchedule: schedule{next: now.Add(schedulePeriod)},
	}, nil
}
