package rateLimit

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"sigsum.org/sigsum-go/pkg/crypto"
)

type fakeClock struct {
	sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.Lock()
	defer c.Unlock()
	return c.now
}

func (c *fakeClock) Advance(delta time.Duration) {
	c.Lock()
	defer c.Unlock()
	c.now.Add(delta)
}

func newTestLimiter(config string, clock clocker) (Limiter, error) {
	return newLimiter(bytes.NewBuffer([]byte(config)), clock)
}

type request struct {
	domain  *string
	keyHash *crypto.Hash
	delay   time.Duration
}

// Returns the number of successful requests.
func repeatedAccess(t *testing.T, config string, count int, requests []request) int {
	t.Helper()
	clock := &fakeClock{}
	limiter, err := newTestLimiter(config, clock)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		r := &requests[i%len(requests)]
		if limiter.AccessAllowed(r.domain, r.keyHash) == nil {
			return i
		}
		clock.Advance(r.delay)
	}
	return count
}

func testNoConfig(t *testing.T) {
	keyHash := crypto.Hash{1}

	if repeatedAccess(t, "", 1, []request{request{domain: nil, keyHash: &keyHash, delay: time.Hour}}) != 0 {
		t.Errorf("access improperly allowed (no domain)")
	}

	domain := "foo.example.com"
	if repeatedAccess(t, "", 1, []request{request{domain: &domain, keyHash: &keyHash, delay: time.Hour}}) != 0 {
		t.Errorf("access improperly allowed (no domain)")
	}
}

func testKeyLimit(t *testing.T) {
	key1 := crypto.Hash{1}
	key2 := crypto.Hash{2}
	config := fmt.Sprintf("key %x 25 \nkey %x 23\n", key1, key2)
	if got := repeatedAccess(t, config, 100,
		[]request{request{domain: nil, keyHash: &key1, delay: time.Hour}}); got != 100 {
		t.Errorf("should sustain one request per hour, but failed after %d requests", got)
	}
	if got := repeatedAccess(t, config, 100,
		[]request{request{domain: nil, keyHash: &key2, delay: time.Hour}}); got != 23 {
		t.Errorf("limit of 23 request per 24 hours not enforced, %d requests were allowed", got)
	}
	if got := repeatedAccess(t, config, 100,
		[]request{
			request{domain: nil, keyHash: &key1, delay: time.Hour},
			request{domain: nil, keyHash: &key2, delay: time.Hour},
		}); got != 100 {
		t.Errorf("should sustain one request per hour, when alternating which key is used, but failed after %d requests", got)
	}
}

func testDomainLimit(t *testing.T) {
	A := func(s string) *string { return &s }
	key := crypto.Hash{}
	config := "domain foo.example.com 25\n" +
		"domain foo.example.org 23" +
		"domain www.foo.example.org 13\n"

	if got := repeatedAccess(t, config, 100,
		[]request{request{domain: A("foo.Example.com"), keyHash: &key, delay: time.Hour}}); got != 100 {
		t.Errorf("should sustain one request per hour, but failed after %d requests", got)
	}
	if got := repeatedAccess(t, config, 100,
		[]request{request{domain: A("foo.Example.ORG"), keyHash: &key, delay: time.Hour}}); got != 23 {
		t.Errorf("limit of 23 request per 24 hours not enforced, %d requests were allowed", got)
	}
	if got := repeatedAccess(t, config, 100,
		[]request{
			request{domain: A("foo.Example.com"), keyHash: &key, delay: time.Hour},
			request{domain: A("foo.Example.ORG"), keyHash: &key, delay: time.Hour},
		}); got != 100 {
		t.Errorf("should sustain one request per hour, when alternating which domain is used, but failed after %d requests", got)
	}
	if got := repeatedAccess(t, config, 100,
		[]request{
			request{domain: A("foo.Example.com"), keyHash: &key, delay: time.Hour},
			request{domain: A("www.foo.Example.COM"), keyHash: &key, delay: time.Hour},
		}); got != 25 {
		t.Errorf("limit of 25 request applies also to subdomains, but failed after %d requests", got)
	}
	if got := repeatedAccess(t, config, 100,
		[]request{
			request{domain: A("foo.Example.org"), keyHash: &key, delay: time.Hour},
			request{domain: A("www.foo.Example.org"), keyHash: &key, delay: time.Hour},
		}); got != 100 {
		t.Errorf("should sustain one request per hour, when subdomain has its own configured limit, but failed after %d requests", got)

	}
}
