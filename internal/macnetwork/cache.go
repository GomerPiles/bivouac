package macnetwork

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// RefreshInterval bounds the age of an admission snapshot, including new flows.
const RefreshInterval = 250 * time.Millisecond

// Cache owns one immutable host policy snapshot per observation interval. A
// refresh failure replaces the old snapshot with denial, never stale success.
// It has no background worker and is owned by one stack or cache service.
type Cache struct {
	mu       sync.Mutex
	prefixes []netip.Prefix
	valid    bool
	until    time.Time
	read     func() (string, error)
	now      func() time.Time
}

func NewCache() *Cache { return &Cache{read: Policy, now: time.Now} }
func (c *Cache) Allows(address netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !now.Before(c.until) {
		c.refreshLocked(now)
	}
	// The representation supports both families; IPv6 remains denied until
	// Policy includes its scoped addresses, routes and reserved destinations.
	if !c.valid || !address.Is4() {
		return false
	}
	for _, prefix := range c.prefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
func (c *Cache) Public(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	return ok && c.Allows(address.Unmap())
}

// Refresh takes one snapshot for a complete existing-flow revalidation pass.
func (c *Cache) Refresh() { c.mu.Lock(); defer c.mu.Unlock(); c.refreshLocked(c.now()) }
func (c *Cache) refreshLocked(now time.Time) {
	c.until = now.Add(RefreshInterval)
	c.prefixes = nil
	c.valid = false
	policy, err := c.read()
	if err != nil {
		return
	}
	for _, rule := range strings.Split(policy, ",") {
		prefix, err := netip.ParsePrefix(rule)
		if err != nil {
			return
		}
		c.prefixes = append(c.prefixes, prefix)
	}
	c.valid = true
}
