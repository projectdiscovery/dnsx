package runner

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
)

// autoWildcardDetector detects and tracks wildcard DNS domains automatically.
// For each parent domain encountered during resolution, it sends a configurable
// number of random subdomain queries. If all probes resolve to the same set of
// IPs, the parent domain is marked as a wildcard and those IPs are stored.
// Subsequent results whose A records are a subset of the wildcard set are
// filtered (or annotated).
type autoWildcardDetector struct {
	// wildcardIPs maps parent domain -> set of wildcard IPs
	wildcardIPs map[string]map[string]struct{}
	// nonWildcardDomains tracks parent domains confirmed as not wildcard
	nonWildcardDomains map[string]struct{}
	mu                 sync.RWMutex

	numProbes int
	runner    *Runner

	filteredCount atomic.Int64
}

func newAutoWildcardDetector(r *Runner, numProbes int) *autoWildcardDetector {
	if numProbes < 2 {
		numProbes = 2
	}
	return &autoWildcardDetector{
		wildcardIPs:        make(map[string]map[string]struct{}),
		nonWildcardDomains: make(map[string]struct{}),
		numProbes:          numProbes,
		runner:             r,
	}
}

// extractParentDomain returns the parent domain of a given FQDN.
// For "foo.bar.example.com" it returns "bar.example.com".
// For "sub.example.com" it returns "example.com".
// For a bare domain like "example.com" it returns "" (nothing to check).
func extractParentDomain(host string) string {
	host = strings.TrimSuffix(host, ".")
	parts := strings.SplitN(host, ".", 2)
	if len(parts) < 2 {
		return ""
	}
	parent := parts[1]
	// The parent itself must have at least one dot to be a valid domain
	// (e.g. "example.com" is valid, "com" is not).
	if !strings.Contains(parent, ".") {
		return ""
	}
	return parent
}

// isWildcard checks whether the given domain's A records match a known wildcard
// set for its parent domain. It lazily probes parent domains on first encounter.
// Returns true if the result should be filtered.
func (d *autoWildcardDetector) isWildcard(host string, aRecords []string) bool {
	if len(aRecords) == 0 {
		return false
	}

	parent := extractParentDomain(host)
	if parent == "" {
		return false
	}

	d.mu.RLock()
	_, isNonWildcard := d.nonWildcardDomains[parent]
	wildcardSet, isKnownWildcard := d.wildcardIPs[parent]
	d.mu.RUnlock()

	if isNonWildcard {
		return false
	}

	if !isKnownWildcard {
		// First time seeing this parent: probe it
		wildcardSet = d.probeParent(parent)
	}

	if wildcardSet == nil {
		return false
	}

	// Check if all A records for this host are in the wildcard set
	for _, ip := range aRecords {
		if _, ok := wildcardSet[ip]; !ok {
			return false
		}
	}
	d.filteredCount.Add(1)
	return true
}

// probeParent sends random subdomain queries to the parent domain and determines
// if it has wildcard DNS configured. Thread-safe with double-checked locking.
func (d *autoWildcardDetector) probeParent(parent string) map[string]struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Double-check under write lock
	if _, ok := d.nonWildcardDomains[parent]; ok {
		return nil
	}
	if ips, ok := d.wildcardIPs[parent]; ok {
		return ips
	}

	// Send random subdomain queries
	var allProbeIPs []map[string]struct{}
	for i := 0; i < d.numProbes; i++ {
		randomSub := xid.New().String() + "." + parent
		result, err := d.runner.dnsx.QueryOne(randomSub)
		if err != nil || result == nil || len(result.A) == 0 {
			// If any probe fails to resolve, the domain is not wildcard
			d.nonWildcardDomains[parent] = struct{}{}
			gologger.Debug().Msgf("Auto-wildcard: %s is not wildcard (probe %d got no response)\n", parent, i+1)
			return nil
		}
		ipSet := make(map[string]struct{})
		for _, a := range result.A {
			ipSet[a] = struct{}{}
		}
		allProbeIPs = append(allProbeIPs, ipSet)
	}

	// Verify all probes returned the same set of IPs
	// Build the intersection of all probe results
	intersection := allProbeIPs[0]
	for i := 1; i < len(allProbeIPs); i++ {
		next := make(map[string]struct{})
		for ip := range intersection {
			if _, ok := allProbeIPs[i][ip]; ok {
				next[ip] = struct{}{}
			}
		}
		intersection = next
	}

	if len(intersection) == 0 {
		d.nonWildcardDomains[parent] = struct{}{}
		gologger.Debug().Msgf("Auto-wildcard: %s is not wildcard (no common IPs across probes)\n", parent)
		return nil
	}

	// Also verify the union is equal to the intersection (all probes returned the same set)
	union := make(map[string]struct{})
	for _, probeSet := range allProbeIPs {
		for ip := range probeSet {
			union[ip] = struct{}{}
		}
	}
	if len(union) != len(intersection) {
		d.nonWildcardDomains[parent] = struct{}{}
		gologger.Debug().Msgf("Auto-wildcard: %s is not wildcard (inconsistent IPs across probes)\n", parent)
		return nil
	}

	// This parent domain is a wildcard
	d.wildcardIPs[parent] = intersection
	ips := make([]string, 0, len(intersection))
	for ip := range intersection {
		ips = append(ips, ip)
	}
	gologger.Verbose().Msgf("Auto-wildcard: detected %s as wildcard domain (IPs: %v)\n", parent, ips)
	return intersection
}
