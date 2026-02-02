package runner

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/rs/xid"
	"golang.org/x/net/publicsuffix"
)

// AutoWildcardDetector handles automatic wildcard detection across multiple domains
type AutoWildcardDetector struct {
	dnsx           *dnsx.DNSX
	testCount      int
	mutex          sync.RWMutex
	wildcardRoots  map[string]map[string]struct{} // root domain -> set of wildcard IPs
	testedDomains  map[string]struct{}            // domains we've already tested for wildcards
	filteredCount  int                            // count of filtered wildcard subdomains
}

// NewAutoWildcardDetector creates a new auto wildcard detector
func NewAutoWildcardDetector(dnsxClient *dnsx.DNSX, testCount int) *AutoWildcardDetector {
	if testCount < 1 {
		testCount = 3
	}
	return &AutoWildcardDetector{
		dnsx:          dnsxClient,
		testCount:     testCount,
		wildcardRoots: make(map[string]map[string]struct{}),
		testedDomains: make(map[string]struct{}),
	}
}

// DetectAndFilter checks if a host is a wildcard subdomain
// Returns true if the host should be filtered (is wildcard), false otherwise
func (d *AutoWildcardDetector) DetectAndFilter(host string, hostIPs []string) bool {
	if len(hostIPs) == 0 {
		return false
	}

	// Extract parent domains to test for wildcards
	parents := getParentDomains(host)
	if len(parents) == 0 {
		return false
	}

	// Ensure wildcard detection is done for all parent levels
	for _, parent := range parents {
		d.ensureWildcardTested(parent)
	}

	// Check if any of the host's IPs match known wildcard IPs
	return d.isWildcardMatch(host, hostIPs)
}

// ensureWildcardTested tests a domain for wildcards if not already tested
func (d *AutoWildcardDetector) ensureWildcardTested(parent string) {
	d.mutex.RLock()
	_, tested := d.testedDomains[parent]
	d.mutex.RUnlock()

	if tested {
		return
	}

	// Mark as tested before actual test to prevent concurrent duplicate tests
	d.mutex.Lock()
	// Double-check after acquiring write lock
	if _, tested := d.testedDomains[parent]; tested {
		d.mutex.Unlock()
		return
	}
	d.testedDomains[parent] = struct{}{}
	d.mutex.Unlock()

	// Test for wildcard by querying random subdomains
	wildcardIPs := d.testWildcard(parent)

	if len(wildcardIPs) > 0 {
		d.mutex.Lock()
		d.wildcardRoots[parent] = wildcardIPs
		d.mutex.Unlock()
	}
}

// testWildcard tests if a domain has wildcard DNS by querying random subdomains
func (d *AutoWildcardDetector) testWildcard(parent string) map[string]struct{} {
	wildcardIPs := make(map[string]struct{})

	// Query multiple random subdomains
	for i := 0; i < d.testCount; i++ {
		randomHost := xid.New().String() + "." + parent
		result, err := d.dnsx.QueryOne(randomHost)
		if err != nil || result == nil {
			continue
		}

		// Add A record IPs directly to wildcardIPs
		for _, ip := range result.A {
			wildcardIPs[ip] = struct{}{}
		}

		// Also add AAAA record IPs for IPv6 wildcard detection
		for _, ip := range result.AAAA {
			wildcardIPs[ip] = struct{}{}
		}
	}

	return wildcardIPs
}

// isWildcardMatch checks if any of the host's IPs match wildcard patterns
func (d *AutoWildcardDetector) isWildcardMatch(host string, hostIPs []string) bool {
	parents := getParentDomains(host)

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	for _, parent := range parents {
		if wildcardIPs, ok := d.wildcardRoots[parent]; ok {
			for _, ip := range hostIPs {
				if _, isWildcard := wildcardIPs[ip]; isWildcard {
					return true
				}
			}
		}
	}

	return false
}

// GetWildcardRoots returns all detected wildcard root domains
func (d *AutoWildcardDetector) GetWildcardRoots() []string {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	roots := make([]string, 0, len(d.wildcardRoots))
	for root := range d.wildcardRoots {
		roots = append(roots, root)
	}
	return roots
}

// GetWildcardRootCount returns the number of wildcard roots detected
func (d *AutoWildcardDetector) GetWildcardRootCount() int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return len(d.wildcardRoots)
}

// IncrementFilteredCount increments the count of filtered wildcard subdomains
func (d *AutoWildcardDetector) IncrementFilteredCount() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.filteredCount++
}

// GetFilteredCount returns the count of filtered wildcard subdomains
func (d *AutoWildcardDetector) GetFilteredCount() int {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.filteredCount
}

// getParentDomains extracts all parent domain levels from a hostname
// stopping at the registrable domain boundary (eTLD+1)
// e.g., "sub.example.com" returns ["example.com"]
// e.g., "a.b.example.com" returns ["b.example.com", "example.com"]
// e.g., "sub.example.co.uk" returns ["example.co.uk"] (not "co.uk")
func getParentDomains(host string) []string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return nil // Already at apex or TLD
	}

	// Get the registrable domain (eTLD+1) to know where to stop
	registrableDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return nil // Cannot determine registrable domain
	}

	var parents []string
	// Start from the immediate parent and go up to (and including) the registrable domain
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		parents = append(parents, parent)
		// Stop when we reach the registrable domain
		if parent == registrableDomain {
			break
		}
	}

	return parents
}
