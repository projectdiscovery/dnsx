package runner

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
)

const (
	// defaultNumProbes is the number of random subdomain probes used to detect a wildcard.
	defaultNumProbes = 3
)

// wildcardCacheEntry stores the result of a wildcard probe for a parent domain.
type wildcardCacheEntry struct {
	isWildcard bool
	ips        map[string]struct{} // set of wildcard IPs (empty if not a wildcard)
}

// WildcardDetector performs automatic wildcard DNS detection by probing
// random subdomains of parent domains and caching the results.
type WildcardDetector struct {
	dnsClient *dnsx.DNSX
	cache     map[string]*wildcardCacheEntry
	mu        sync.RWMutex
	threshold int // minimum number of probes that must agree
	numProbes int
	filtered  atomic.Int64
}

// NewWildcardDetector creates a new automatic wildcard detector.
func NewWildcardDetector(dnsClient *dnsx.DNSX, threshold int) *WildcardDetector {
	if threshold < 2 {
		threshold = 2
	}
	return &WildcardDetector{
		dnsClient: dnsClient,
		cache:     make(map[string]*wildcardCacheEntry),
		threshold: threshold,
		numProbes: defaultNumProbes,
	}
}

// parentDomains returns the possible parent domains for a hostname.
// For "a.b.example.com" it returns ["b.example.com", "example.com"].
func parentDomains(host string) []string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		// Already a root domain (example.com) — no parent to check.
		return nil
	}
	var parents []string
	for i := 1; i < len(parts)-1; i++ {
		parents = append(parents, strings.Join(parts[i:], "."))
	}
	return parents
}

// detectWildcardForDomain probes a parent domain with random subdomains.
// Returns a cache entry indicating whether a wildcard was detected and which IPs it resolves to.
func (wd *WildcardDetector) detectWildcardForDomain(parentDomain string) *wildcardCacheEntry {
	ipCounts := make(map[string]int)
	successfulProbes := 0

	for i := 0; i < wd.numProbes; i++ {
		randomHost := xid.New().String() + "." + parentDomain
		result, err := wd.dnsClient.QueryOne(randomHost)
		if err != nil || result == nil {
			continue
		}
		// Collect both A and AAAA records
		allIPs := append(result.A, result.AAAA...)
		if len(allIPs) == 0 {
			continue
		}
		successfulProbes++
		for _, ip := range allIPs {
			ipCounts[ip]++
		}
	}

	entry := &wildcardCacheEntry{
		ips: make(map[string]struct{}),
	}

	// If at least 2 probes returned results, and common IPs are found, it's a wildcard.
	minAgreement := wd.threshold
	if minAgreement > wd.numProbes {
		minAgreement = wd.numProbes
	}
	if minAgreement < 2 {
		minAgreement = 2
	}
	if successfulProbes >= minAgreement {
		for ip, count := range ipCounts {
			if count >= minAgreement {
				entry.ips[ip] = struct{}{}
			}
		}
		if len(entry.ips) > 0 {
			entry.isWildcard = true
			gologger.Debug().Msgf("Wildcard detected for *.%s (IPs: %v)\n", parentDomain, mapsToSlice(entry.ips))
		}
	}

	return entry
}

// getOrDetect retrieves the cached wildcard entry for a parent domain,
// or probes and caches the result.
func (wd *WildcardDetector) getOrDetect(parentDomain string) *wildcardCacheEntry {
	wd.mu.RLock()
	entry, ok := wd.cache[parentDomain]
	wd.mu.RUnlock()
	if ok {
		return entry
	}

	// Probe and cache
	entry = wd.detectWildcardForDomain(parentDomain)
	wd.mu.Lock()
	// Double-check after acquiring write lock
	if existing, ok := wd.cache[parentDomain]; ok {
		wd.mu.Unlock()
		return existing
	}
	wd.cache[parentDomain] = entry
	wd.mu.Unlock()
	return entry
}

// IsWildcardResponse checks if a resolved host's IPs match a wildcard
// on any of its parent domains. Returns true if the response should be filtered out.
func (wd *WildcardDetector) IsWildcardResponse(host string, resolvedIPs []string) bool {
	if len(resolvedIPs) == 0 {
		return false
	}

	parents := parentDomains(host)
	for _, parent := range parents {
		entry := wd.getOrDetect(parent)
		if !entry.isWildcard {
			continue
		}
		// Check if ALL resolved IPs are wildcard IPs
		allMatch := true
		for _, ip := range resolvedIPs {
			if _, ok := entry.ips[ip]; !ok {
				allMatch = false
				break
			}
		}
		if allMatch {
			wd.filtered.Add(1)
			return true
		}
	}
	return false
}

// FilteredCount returns the number of wildcard responses that were filtered.
func (wd *WildcardDetector) FilteredCount() int64 {
	return wd.filtered.Load()
}

// mapsToSlice converts a map[string]struct{} to a string slice (for logging).
func mapsToSlice(m map[string]struct{}) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

// IsWildcard checks if a host is wildcard
func (r *Runner) IsWildcard(host string) bool {
	orig := make(map[string]struct{})
	wildcards := make(map[string]struct{})

	in, err := r.dnsx.QueryOne(host)
	if err != nil || in == nil {
		return false
	}
	for _, A := range in.A {
		orig[A] = struct{}{}
	}

	subdomainPart := strings.TrimSuffix(host, "."+r.options.WildcardDomain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	// Build an array by preallocating a slice of a length
	// and create the wildcard generation prefix.
	// We use a rand prefix at the beginning like %rand%.domain.tld
	// A permutation is generated for each level of the subdomain.
	var hosts []string
	hosts = append(hosts, r.options.WildcardDomain)

	if len(subdomainTokens) > 0 {
		for i := 1; i < len(subdomainTokens); i++ {
			newhost := strings.Join(subdomainTokens[i:], ".") + "." + r.options.WildcardDomain
			hosts = append(hosts, newhost)
		}
	}

	// Iterate over all the hosts generated for rand.
	for _, h := range hosts {
		r.wildcardscachemutex.Lock()
		listip, ok := r.wildcardscache[h]
		r.wildcardscachemutex.Unlock()
		if !ok {
			in, err := r.dnsx.QueryOne(xid.New().String() + "." + h)
			if err != nil || in == nil {
				continue
			}
			listip = in.A
			r.wildcardscachemutex.Lock()
			r.wildcardscache[h] = in.A
			r.wildcardscachemutex.Unlock()
		}

		// Get all the records and add them to the wildcard map
		for _, A := range listip {
			if _, ok := wildcards[A]; !ok {
				wildcards[A] = struct{}{}
			}
		}
	}

	// check if original ip are among wildcards
	for a := range orig {
		if _, ok := wildcards[a]; ok {
			return true
		}
	}

	return false
}
