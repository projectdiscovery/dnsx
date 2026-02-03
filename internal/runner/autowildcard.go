package runner

import (
	"strings"
	"sync"

	"github.com/rs/xid"
	"golang.org/x/net/publicsuffix"
)

// AutoWildcardDetector provides automatic detection and filtering of wildcard DNS records.
// It probes random subdomains to identify wildcard patterns and caches results per base domain.
// Thread-safe for concurrent use across multiple workers.
type AutoWildcardDetector struct {
	runner    *Runner
	cache     map[string][]string // domain -> wildcard IPs
	cacheLock sync.RWMutex
	threshold int
}

// NewAutoWildcardDetector creates a new AutoWildcardDetector instance.
// The threshold parameter controls how many random subdomain probes are made (default 5).
// Higher values increase accuracy but also increase DNS query count.
func NewAutoWildcardDetector(runner *Runner, threshold int) *AutoWildcardDetector {
	if threshold <= 0 {
		threshold = 5 // default threshold
	}
	return &AutoWildcardDetector{
		runner:    runner,
		cache:     make(map[string][]string),
		threshold: threshold,
	}
}

// GetBaseDomain extracts the base domain (eTLD+1) from a hostname.
// It handles both regular hostnames and FQDNs with trailing dots.
// For example, "www.google.com" and "www.google.com." both return "google.com".
func (a *AutoWildcardDetector) GetBaseDomain(host string) string {
	// Remove any leading and trailing dots (for FQDNs)
	host = strings.TrimPrefix(host, ".")
	host = strings.TrimSuffix(host, ".")

	// Try to get the eTLD+1 (effective top-level domain plus one)
	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: try to extract last two parts
		parts := strings.Split(host, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return host
	}
	return baseDomain
}

// DetectWildcard probes random subdomains of the given base domain to detect wildcard DNS.
// It returns a slice of IPs that appear in the majority of probe responses (indicating wildcards).
// Results are cached for efficiency on subsequent calls with the same base domain.
func (a *AutoWildcardDetector) DetectWildcard(baseDomain string) []string {
	a.cacheLock.RLock()
	if ips, ok := a.cache[baseDomain]; ok {
		a.cacheLock.RUnlock()
		return ips
	}
	a.cacheLock.RUnlock()

	// Guard against nil runner or dnsx to prevent panics in tests or future reuse
	if a.runner == nil || a.runner.dnsx == nil {
		return nil
	}

	// Generate random subdomains and query them
	wildcardIPs := make(map[string]int)
	successfulProbes := 0

	for i := 0; i < a.threshold; i++ {
		// Respect rate limits if limiter is configured
		if a.runner != nil && a.runner.limiter != nil {
			a.runner.limiter.Take()
		}

		randomSub := xid.New().String() + "." + baseDomain
		result, err := a.runner.dnsx.QueryOne(randomSub)
		if err != nil || result == nil {
			continue
		}

		successfulProbes++

		// Count occurrences of each IP (both A and AAAA records)
		for _, ip := range result.A {
			wildcardIPs[ip]++
		}
		for _, ip := range result.AAAA {
			wildcardIPs[ip]++
		}
	}

	// If no successful probes, don't cache and return empty
	if successfulProbes == 0 {
		return nil
	}

	// IPs that appear in the majority of successful probes are wildcard IPs
	var wildcards []string
	minOccurrences := (successfulProbes / 2) + 1 // majority threshold
	for ip, count := range wildcardIPs {
		if count >= minOccurrences {
			wildcards = append(wildcards, ip)
		}
	}

	// Cache the result
	a.cacheLock.Lock()
	// Double-check in case another goroutine cached while we were probing
	if existingIPs, ok := a.cache[baseDomain]; ok {
		a.cacheLock.Unlock()
		return existingIPs
	}
	a.cache[baseDomain] = wildcards
	a.cacheLock.Unlock()

	return wildcards
}

// IsWildcard checks if the given host's IPs match known wildcard IPs for its base domain.
// It accepts both IPv4 (A record) and IPv6 (AAAA record) addresses.
// Returns true if any of the provided IPs match the detected wildcard pattern.
func (a *AutoWildcardDetector) IsWildcard(host string, ips []string) bool {
	baseDomain := a.GetBaseDomain(host)

	// Get or detect wildcard IPs for this base domain
	wildcardIPs := a.DetectWildcard(baseDomain)
	if len(wildcardIPs) == 0 {
		return false
	}

	// Create a set of wildcard IPs for fast lookup
	wildcardSet := make(map[string]struct{})
	for _, wip := range wildcardIPs {
		wildcardSet[wip] = struct{}{}
	}

	// Check if any of the host's IPs match wildcard IPs
	for _, ip := range ips {
		if _, ok := wildcardSet[ip]; ok {
			return true
		}
	}

	return false
}

// GetWildcardDomains returns all detected wildcard domains and their associated IPs.
// Only domains with detected wildcard IPs are included in the result.
func (a *AutoWildcardDetector) GetWildcardDomains() map[string][]string {
	a.cacheLock.RLock()
	defer a.cacheLock.RUnlock()

	result := make(map[string][]string, len(a.cache))
	for k, v := range a.cache {
		if len(v) > 0 {
			copied := make([]string, len(v))
			copy(copied, v)
			result[k] = copied
		}
	}
	return result
}
