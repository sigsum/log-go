package rateLimit

import (
	"strings"
	"testing"
)

const exampleSuffixFile = `
org
net
example.com
*.example.net
!foo.example.net
`

func createDb(t *testing.T, suffixFile string) DomainDb {
	db, err := NewDomainDb(strings.NewReader(suffixFile))
	if err != nil {
		t.Errorf("db init failed: %v", err)
	}
	return db
}

func TestGetSuffix(t *testing.T) {
	db := createDb(t, exampleSuffixFile)

	testOne := func(domain string, suffix string, expectSuccess bool) {
		res, err := db.getSuffix(domain)
		if err != nil {
			if expectSuccess {
				t.Errorf("getSuffix(%q) failed, got error %v, expected %q",
					domain, err, suffix)
			}
			return
		}
		if !expectSuccess {
			t.Errorf("getSuffix(%q) failed, got %q, expected error",
				domain, res)
		}
		if res != suffix {
			t.Errorf("getSuffix(%q) failed, got %q, expected %q",
				domain, res, suffix)
		}
	}
	testOne("example.org", "org", true)
	testOne("example.com", "example.com", true)
	testOne("foo.example.com", "example.com", true)
	testOne("foo.bar.example.com", "example.com", true)
	testOne("foo.bar.example.net", "bar.example.net", true)
	testOne("bar.foo.example.net", "net", true)
	testOne("bar.foo.example.mil", "", false)
}

func TestGetRegisteredDomain(t *testing.T) {
	db := createDb(t, exampleSuffixFile)

	testOne := func(domain string, registeredDomain string, expectSuccess bool) {
		res, err := db.GetRegisteredDomain(domain)
		if err != nil {
			if expectSuccess {
				t.Errorf("getRegisteredDomain(%q) failed, got error %v, expected %q",
					domain, err, registeredDomain)
			}
			return
		}
		if !expectSuccess {
			t.Errorf("getRegisteredDomain(%q) failed, got %q, expected error",
				domain, res)
		}
		if res != registeredDomain {
			t.Errorf("getRegisteredDomain(%q) failed, got %q, expected %q",
				domain, res, registeredDomain)
		}
	}
	testOne("example.org", "example.org", true)
	testOne("example.com", "example.com", true)
	testOne("foo.example.com", "foo.example.com", true)
	testOne("foo.bar.example.com", "bar.example.com", true)
	testOne("foo.bar.example.net", "foo.bar.example.net", true)
	testOne("bar.foo.example.net", "example.net", true)
	testOne("bar.foo.example.mil", "", false)
}

// Move test elsewhere
//func TestPublicAccessAllowed(t *testing.T) {
//	db := createDb(t, exampleSuffixFile)
//
//	// expected == -1 for expected failure
//	checkCount := func(domain string, expected int) {
//		t.Helper()
//		c, err := db.GetPublicAccessCount(domain)
//		if expected >= 0 && (err != nil || c != expected) {
//			t.Errorf("expected access count (%q) = %d, got %d, %v",
//				domain, expected, c, err)
//		}
//		if expected < 0 && err == nil {
//			t.Errorf("expected access count (%q) to fail, got %d",
//				domain, c)
//		}
//	}
//	checkAccess := func(desc, domain string, limit int, expected bool) {
//		t.Helper()
//		if res := db.PublicAccessAllowed(domain, limit); res != expected {
//			t.Errorf("%v: unexpected access (%q, %d), got %v, expected %v, count = %d",
//				desc, domain, limit, res, expected, db.GetAccessCount(domain))
//		}
//	}
//
//	checkCount("example.org", 0)
//	checkAccess("first", "example.org", 3, true)
//	checkAccess("second, subdomain", "foo.example.org", 3, true)
//	checkAccess("thirds, subdomain", "bar.foo.example.org", 3, true)
//	checkAccess("fourth, subdomain", "foo.example.org", 3, false)
//
//	checkAccess("long suffix", "foo.bar.example.net", 2, true)
//	checkAccess("longer suffix", "quux.foo.bar.example.net", 2, true)
//	checkAccess("short suffix", "bar.foo.example.net", 1, true)
//	checkCount("foo.bar.example.net", 2)
//	checkCount("example.net", 1)
//}
