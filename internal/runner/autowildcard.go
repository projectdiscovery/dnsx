package runner

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
	"golang.org/x/net/publicsuffix"
)

// AutoWildcardDetector handles automatic wildcard detection for multiple domains
type AutoWildcardDetector struct {
	dnsx              *Runner
	mutex             sync.RWMutex
	wildcardCache     map[string][]string // domain -> wildcard IPs
	testedDomains     map[string]bool     // domains we've already tested
	pending           map[string]chan struct{} // domains currently being tested
	filteredCount     int
	wildcardDomainsCount int
}

// NewAutoWildcardDetector creates a new auto-wildcard detector
func NewAutoWildcardDetector(dnsxClient *Runner) *AutoWildcardDetector {
	return &AutoWildcardDetector{
		dnsx:          dnsxClient,
		wildcardCache: make(map[string][]string),
		testedDomains: make(map[string]bool),
		pending:       make(map[string]chan struct{}),
	}
}

// extractRootDomain extracts the root domain from a subdomain
// Example: sub.example.com -> example.com
func (awd *AutoWildcardDetector) extractRootDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))

	// Try using publicsuffix library for accurate eTLD+1 extraction
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: simple extraction (last two parts)
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return host
	}

	return rootDomain
}

// getParentDomains returns all parent domains for wildcard testing
// Example: a.b.c.example.com -> [example.com, c.example.com, b.c.example.com, a.b.c.example.com]
func (awd *AutoWildcardDetector) getParentDomains(host string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	rootDomain := awd.extractRootDomain(host)

	if host == rootDomain {
		return []string{rootDomain}
	}

	var parents []string
	parts := strings.Split(host, ".")
	rootParts := strings.Split(rootDomain, ".")

	// Generate parent domains from root up to the full subdomain
	for i := len(rootParts); i <= len(parts); i++ {
		parent := strings.Join(parts[len(parts)-i:], ".")
		parents = append(parents, parent)
	}

	return parents
}

// detectWildcard tests a domain for wildcard DNS by querying random subdomains
func (awd *AutoWildcardDetector) detectWildcard(domain string) []string {
	awd.mutex.Lock()

	// Check if already tested and cached
	if tested, exists := awd.testedDomains[domain]; exists && tested {
		if cached, hasCached := awd.wildcardCache[domain]; hasCached {
			awd.mutex.Unlock()
			return cached
		}
		// If tested but not in cache, it means detection is in progress
		// Wait for the pending channel
		if pendingCh, isPending := awd.pending[domain]; isPending {
			awd.mutex.Unlock()
			<-pendingCh // Wait for detection to complete
			awd.mutex.Lock()
			cached := awd.wildcardCache[domain]
			awd.mutex.Unlock()
			return cached
		}
	}

	// Mark as being tested and create pending channel
	awd.testedDomains[domain] = true
	pendingCh := make(chan struct{})
	awd.pending[domain] = pendingCh
	awd.mutex.Unlock()

	// Test with 3 random subdomains
	wildcardIPs := make(map[string]int)
	testCount := 3

	for i := 0; i < testCount; i++ {
		randomSubdomain := xid.New().String() + "." + domain

		// Apply rate limiting before querying
		if awd.dnsx.limiter != nil {
			awd.dnsx.limiter.Take()
		}

		// Query the random subdomain
		dnsData, err := awd.dnsx.dnsx.QueryOne(randomSubdomain)
		if err != nil || dnsData == nil {
			continue
		}

		// Collect A records (IPv4)
		for _, ip := range dnsData.A {
			wildcardIPs[ip]++
		}

		// Collect AAAA records (IPv6)
		for _, ip := range dnsData.AAAA {
			wildcardIPs[ip]++
		}
	}

	// IPs that appear in multiple random queries are likely wildcard IPs
	// Note: threshold of 2/3 may produce false positives for Anycast/CDN IPs
	threshold := 2
	var confirmedWildcardIPs []string
	for ip, count := range wildcardIPs {
		if count >= threshold { // Appear in at least 2 out of 3 random queries
			confirmedWildcardIPs = append(confirmedWildcardIPs, ip)
		}
	}

	// Cache the result and close pending channel
	awd.mutex.Lock()
	awd.wildcardCache[domain] = confirmedWildcardIPs
	if len(confirmedWildcardIPs) > 0 {
		awd.wildcardDomainsCount++
		gologger.Debug().Msgf("Wildcard detected for %s: %v", domain, confirmedWildcardIPs)

		// Warn about potential CDN/Anycast false positives
		if testCount == 3 && threshold == 2 {
			gologger.Warning().Msgf("Wildcard detection for %s uses 2/3 threshold - may produce false positives for CDN/Anycast IPs", domain)
		}
	}
	close(pendingCh)
	delete(awd.pending, domain)
	awd.mutex.Unlock()

	return confirmedWildcardIPs
}

// IsWildcardMatch checks if the given host and its IPs match wildcard patterns
func (awd *AutoWildcardDetector) IsWildcardMatch(host string, hostIPv4 []string, hostIPv6 []string) bool {
	// Combine IPv4 and IPv6 addresses
	hostIPs := append([]string{}, hostIPv4...)
	hostIPs = append(hostIPs, hostIPv6...)

	if len(hostIPs) == 0 {
		return false
	}

	// Get all parent domains to test
	parentDomains := awd.getParentDomains(host)

	// Collect all wildcard IPs from parent domains
	wildcardIPSet := make(map[string]struct{})
	for _, parent := range parentDomains {
		if parent == host {
			// Don't test the host itself, test its parents
			continue
		}

		wildcardIPs := awd.detectWildcard(parent)
		for _, ip := range wildcardIPs {
			wildcardIPSet[ip] = struct{}{}
		}
	}

	// Check if any of the host's IPs match wildcard IPs
	for _, hostIP := range hostIPs {
		if _, isWildcard := wildcardIPSet[hostIP]; isWildcard {
			awd.mutex.Lock()
			awd.filteredCount++
			awd.mutex.Unlock()
			return true
		}
	}

	return false
}

// GetStats returns statistics about wildcard detection
func (awd *AutoWildcardDetector) GetStats() (wildcardDomains int, filteredHosts int) {
	awd.mutex.RLock()
	defer awd.mutex.RUnlock()
	return awd.wildcardDomainsCount, awd.filteredCount
}
