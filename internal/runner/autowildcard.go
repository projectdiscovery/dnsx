package runner

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

const (
	// autoWildcardProbes is the number of random subdomain probes per root domain
	autoWildcardProbes = 3
)

// autoWildcardFilter holds detected wildcard IPs per root domain
type autoWildcardFilter struct {
	// wildcardIPs maps root domain -> set of wildcard IP addresses
	wildcardIPs map[string]map[string]struct{}
	mu          sync.RWMutex
}

// newAutoWildcardFilter creates a new auto wildcard filter
func newAutoWildcardFilter() *autoWildcardFilter {
	return &autoWildcardFilter{
		wildcardIPs: make(map[string]map[string]struct{}),
	}
}

// extractRootDomain extracts the root domain from a hostname using publicsuffix
func extractRootDomain(hostname string) string {
	hostname = strings.TrimSuffix(hostname, ".")
	domain, err := publicsuffix.Domain(hostname)
	if err != nil {
		// fallback: use last two parts of the hostname
		parts := strings.Split(hostname, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return hostname
	}
	return domain
}

// detectWildcards probes root domains with random subdomains to identify wildcard DNS responses.
// It collects all unique root domains from the input, then queries random non-existent
// subdomains for each. IPs that consistently appear across probes are recorded as wildcard IPs.
func (r *Runner) detectWildcards() *autoWildcardFilter {
	awf := newAutoWildcardFilter()

	// Collect unique root domains from all input hosts
	rootDomains := make(map[string]struct{})
	r.hm.Scan(func(k, _ []byte) error {
		host := string(k)
		root := extractRootDomain(host)
		if root != "" {
			rootDomains[root] = struct{}{}
		}
		return nil
	})

	if len(rootDomains) == 0 {
		return awf
	}

	gologger.Info().Msgf("Auto-wildcard: probing %d root domain(s) for wildcard DNS", len(rootDomains))

	var wg sync.WaitGroup
	domainChan := make(chan string)

	// Use up to Threads workers, but not more than number of domains
	numWorkers := r.options.Threads
	if numWorkers > len(rootDomains) {
		numWorkers = len(rootDomains)
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rootDomain := range domainChan {
				r.probeWildcard(rootDomain, awf)
			}
		}()
	}

	for domain := range rootDomains {
		domainChan <- domain
	}
	close(domainChan)
	wg.Wait()

	// Log findings
	awf.mu.RLock()
	totalWildcardDomains := 0
	for domain, ips := range awf.wildcardIPs {
		if len(ips) > 0 {
			totalWildcardDomains++
			ipList := make([]string, 0, len(ips))
			for ip := range ips {
				ipList = append(ipList, ip)
			}
			gologger.Info().Msgf("Auto-wildcard: %s is a wildcard domain (IPs: %s)", domain, strings.Join(ipList, ", "))
		}
	}
	awf.mu.RUnlock()

	if totalWildcardDomains > 0 {
		gologger.Info().Msgf("Auto-wildcard: detected %d wildcard domain(s), results matching wildcard IPs will be filtered", totalWildcardDomains)
	} else {
		gologger.Info().Msgf("Auto-wildcard: no wildcard domains detected")
	}

	return awf
}

// probeWildcard queries random non-existent subdomains for a root domain.
// If all probes return A records, the intersection of IPs across probes
// is recorded as the wildcard fingerprint for that domain.
func (r *Runner) probeWildcard(rootDomain string, awf *autoWildcardFilter) {
	// ipCounts tracks how many probes returned each IP
	ipCounts := make(map[string]int)
	successfulProbes := 0

	for i := 0; i < autoWildcardProbes; i++ {
		randomSub := xid.New().String() + "." + rootDomain
		r.limiter.Take()
		result, err := r.dnsx.QueryOne(randomSub)
		if err != nil || result == nil {
			continue
		}

		if len(result.A) == 0 {
			// No A record means this domain does not have wildcard DNS
			return
		}

		successfulProbes++
		for _, ip := range result.A {
			ipCounts[ip]++
		}
	}

	// Only mark as wildcard if we got consistent results across multiple probes
	if successfulProbes < 2 {
		return
	}

	// IPs that appeared in ALL successful probes are wildcard IPs
	wildcardIPs := make(map[string]struct{})
	for ip, count := range ipCounts {
		if count >= successfulProbes {
			wildcardIPs[ip] = struct{}{}
		}
	}

	if len(wildcardIPs) > 0 {
		awf.mu.Lock()
		awf.wildcardIPs[rootDomain] = wildcardIPs
		awf.mu.Unlock()
	}
}

// isAutoWildcard checks if a DNS response matches detected wildcard IPs for its root domain.
// Returns true if ALL of the host's A records match the wildcard IPs (meaning it's a wildcard result).
func (awf *autoWildcardFilter) isAutoWildcard(host string, aRecords []string) bool {
	if len(aRecords) == 0 {
		return false
	}

	rootDomain := extractRootDomain(host)

	awf.mu.RLock()
	wildcardIPs, ok := awf.wildcardIPs[rootDomain]
	awf.mu.RUnlock()

	if !ok || len(wildcardIPs) == 0 {
		return false
	}

	// Check if ALL A records match known wildcard IPs
	for _, ip := range aRecords {
		if _, isWildcard := wildcardIPs[ip]; !isWildcard {
			return false
		}
	}

	return true
}
