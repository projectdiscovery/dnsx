package runner

import (
	"net"
	"strings"
	"sync"

	"github.com/rs/xid"
	"golang.org/x/net/publicsuffix"
)

// AutoWildcardDetector handles automatic wildcard detection
type AutoWildcardDetector struct {
	runner          *Runner
	wildcardRoots   map[string]bool
	wildcardRootsMu sync.RWMutex
}

// NewAutoWildcardDetector creates a new auto wildcard detector
func NewAutoWildcardDetector(r *Runner) *AutoWildcardDetector {
	return &AutoWildcardDetector{
		runner:        r,
		wildcardRoots: make(map[string]bool),
	}
}

// extractRootDomain extracts the root domain from a hostname.
// It normalizes the input by removing trailing dots, handling host:port format,
// and returning IPs as-is (they cannot be wildcards).
func (d *AutoWildcardDetector) extractRootDomain(host string) string {
	// Normalize: remove trailing dot
	host = strings.TrimSuffix(host, ".")
	
	// Handle host:port format
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	
	// If it's an IP address, return as-is (IPs cannot be wildcards)
	if net.ParseIP(host) != nil {
		return host
	}
	
	// Use publicsuffix to get the effective TLD+1
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: split by dots and take last two parts
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return host
	}
	return rootDomain
}

// IsAutoWildcard checks if a host is part of a wildcard domain automatically.
// It caches results per root domain to avoid redundant DNS queries.
// Thread-safe with double-checked locking to prevent duplicate wildcard tests.
// Returns false immediately for IP addresses (they cannot be wildcards).
func (d *AutoWildcardDetector) IsAutoWildcard(host string) bool {
	// Normalize and extract root domain
	rootDomain := d.extractRootDomain(host)
	
	// IP addresses cannot be wildcards
	if net.ParseIP(rootDomain) != nil {
		return false
	}
	
	// Check cache first (read lock)
	d.wildcardRootsMu.RLock()
	isWildcard, exists := d.wildcardRoots[rootDomain]
	d.wildcardRootsMu.RUnlock()
	
	if exists {
		return isWildcard
	}
	
	// Acquire write lock for double-checked locking
	d.wildcardRootsMu.Lock()
	defer d.wildcardRootsMu.Unlock()
	
	// Re-check after acquiring write lock (another goroutine may have populated it)
	if isWildcard, exists = d.wildcardRoots[rootDomain]; exists {
		return isWildcard
	}
	
	// Test if root domain has wildcard
	isWildcard = d.testWildcard(rootDomain)
	
	// Cache result
	d.wildcardRoots[rootDomain] = isWildcard
	
	return isWildcard
}

// testWildcard tests if a domain has wildcard DNS
func (d *AutoWildcardDetector) testWildcard(domain string) bool {
	// Generate random subdomain
	randomSub := xid.New().String() + "." + domain
	
	// Query the random subdomain
	result, err := d.runner.dnsx.QueryOne(randomSub)
	if err != nil || result == nil {
		return false
	}
	
	// If random subdomain resolves, it's likely a wildcard
	return len(result.A) > 0 || len(result.AAAA) > 0
}

// FilterWildcards filters out wildcard results from a slice of hosts.
// It returns only hosts that are NOT part of a wildcard domain.
// This is a convenience method for batch filtering when processing
// multiple hosts at once, such as post-processing results.
// Each host is checked via IsAutoWildcard which caches results per root domain.
func (d *AutoWildcardDetector) FilterWildcards(hosts []string) []string {
	var filtered []string
	for _, host := range hosts {
		if !d.IsAutoWildcard(host) {
			filtered = append(filtered, host)
		}
	}
	return filtered
}
