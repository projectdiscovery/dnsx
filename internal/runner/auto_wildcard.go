package runner

import (
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

// extractRootDomain extracts the root domain from a hostname
func (d *AutoWildcardDetector) extractRootDomain(host string) string {
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

// IsAutoWildcard checks if a host is part of a wildcard domain automatically
func (d *AutoWildcardDetector) IsAutoWildcard(host string) bool {
	rootDomain := d.extractRootDomain(host)
	
	// Check cache first
	d.wildcardRootsMu.RLock()
	isWildcard, exists := d.wildcardRoots[rootDomain]
	d.wildcardRootsMu.RUnlock()
	
	if exists {
		return isWildcard
	}
	
	// Test if root domain has wildcard
	isWildcard = d.testWildcard(rootDomain)
	
	// Cache result
	d.wildcardRootsMu.Lock()
	d.wildcardRoots[rootDomain] = isWildcard
	d.wildcardRootsMu.Unlock()
	
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

// FilterWildcards filters out wildcard results from a slice of hosts
func (d *AutoWildcardDetector) FilterWildcards(hosts []string) []string {
	var filtered []string
	for _, host := range hosts {
		if !d.IsAutoWildcard(host) {
			filtered = append(filtered, host)
		}
	}
	return filtered
}
