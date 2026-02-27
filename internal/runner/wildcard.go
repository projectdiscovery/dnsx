package runner

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
)

const (
	// autoWildcardProbes is the number of random subdomain probes for auto detection
	autoWildcardProbes = 3
)

// autoWildcardResult stores the wildcard detection result for a domain
type autoWildcardResult struct {
	isWildcard bool
	ips        map[string]struct{}
}

// autoWildcardDetector handles automatic wildcard DNS detection
type autoWildcardDetector struct {
	runner *Runner
	cache  map[string]*autoWildcardResult
	mu     sync.RWMutex
}

// newAutoWildcardDetector creates a new auto wildcard detector
func newAutoWildcardDetector(r *Runner) *autoWildcardDetector {
	return &autoWildcardDetector{
		runner: r,
		cache:  make(map[string]*autoWildcardResult),
	}
}

// extractParentDomains returns all possible parent domains for a host.
// For "a.b.example.com" it returns ["b.example.com", "example.com"]
func extractParentDomains(host string) []string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return nil
	}

	var parents []string
	// Start from one level up, stop before the TLD
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		parents = append(parents, parent)
	}
	return parents
}

// detect probes a domain for wildcard DNS by querying random subdomains.
// Returns the cached result if already probed.
func (d *autoWildcardDetector) detect(domain string) *autoWildcardResult {
	d.mu.RLock()
	if result, ok := d.cache[domain]; ok {
		d.mu.RUnlock()
		return result
	}
	d.mu.RUnlock()

	// Probe with multiple random subdomains
	allIPs := make(map[string]int) // ip -> count of probes that returned it
	resolvedProbes := 0

	for i := 0; i < autoWildcardProbes; i++ {
		randomHost := xid.New().String() + "." + domain
		in, err := d.runner.dnsx.QueryOne(randomHost)
		if err != nil || in == nil || len(in.A) == 0 {
			continue
		}
		resolvedProbes++
		for _, a := range in.A {
			allIPs[a]++
		}
	}

	result := &autoWildcardResult{
		ips: make(map[string]struct{}),
	}

	// Domain is wildcard if at least 2 random probes resolved
	if resolvedProbes >= 2 {
		result.isWildcard = true
		// Collect IPs that appeared in at least 2 probes (consistent wildcard IPs)
		for ip, count := range allIPs {
			if count >= 2 {
				result.ips[ip] = struct{}{}
			}
		}
		// If no consistent IPs found but probes resolved, still mark as wildcard
		// using all observed IPs
		if len(result.ips) == 0 {
			for ip := range allIPs {
				result.ips[ip] = struct{}{}
			}
		}
		gologger.Verbose().Msgf("Auto-wildcard detected for %s (IPs: %d)\n", domain, len(result.ips))
	}

	d.mu.Lock()
	d.cache[domain] = result
	d.mu.Unlock()

	return result
}

// isWildcardMatch checks if a host's A records match auto-detected wildcard IPs.
// It checks all parent domain levels for wildcard matches.
func (d *autoWildcardDetector) isWildcardMatch(host string, aRecords []string) bool {
	if len(aRecords) == 0 {
		return false
	}

	parents := extractParentDomains(host)
	for _, parent := range parents {
		result := d.detect(parent)
		if !result.isWildcard {
			continue
		}

		// Check if all A records of the host are wildcard IPs
		allMatch := true
		for _, a := range aRecords {
			if _, ok := result.ips[a]; !ok {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true
		}
	}
	return false
}

// IsWildcard checks if a host is wildcard (used by -wd flag)
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
