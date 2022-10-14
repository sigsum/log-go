package rateLimit

import (
	"sync"
)

// A synchronized map of access counts.
type accessCounts struct {
	// Protects the counts mapping.
	sync.Mutex
	counts map[string]int
}

func (c *accessCounts) GetAccessCount(key string) int {
	c.Lock()
	defer c.Unlock()
	return c.counts[key]
}

func (c *accessCounts) AccessAllowed(key string, limit int) func() {
	c.Lock()
	defer c.Unlock()
	if c.counts[key] >= limit {
		return nil
	}
	c.counts[key]++
	return func() { c.accessRelax(key) }
}

func (c *accessCounts) accessRelax(key string) {
	c.Lock()
	defer c.Unlock()
	// Non-zero count is the expeced case, except if there were a
	// Reset call between AccessAllowed and AccessRelax.
	if c.counts[key] > 0 {
		c.counts[key]--
	}
}

func (c *accessCounts) Reset() {
	c.Lock()
	defer c.Unlock()
	c.counts = make(map[string]int)
}
