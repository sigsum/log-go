package rateLimit

import (
	"testing"
)

func TestAccessAllowed(t *testing.T) {
	m := accessCounts{}
	m.Reset()

	checkCount := func(domain string, expected int) {
		if c := m.GetAccessCount(domain); c != expected {
			t.Errorf("expected access count (%q) = %d, got %d",
				domain, expected, c)
		}
	}
	checkAccess := func(desc, domain string, limit int, expected bool) {
		if res := m.AccessAllowed(domain, limit); (res != nil) != expected {
			t.Errorf("%v: unexpected access (%q, %d), got %v, expected %v, count = %d",
				desc, domain, limit, res != nil, expected, m.GetAccessCount(domain))
		}
	}
	checkCount("foo", 0)
	checkAccess("first", "foo", 2, true)
	checkCount("foo", 1)
	checkAccess("second", "foo", 2, true)
	checkAccess("third", "foo", 2, false)
	checkCount("foo", 2)

	checkCount("bar", 0)
	checkAccess("other domain", "bar", 2, true)
}

