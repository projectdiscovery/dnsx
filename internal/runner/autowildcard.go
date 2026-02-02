package runner

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// DomainWildcardInfo stores wildcard detection information for a domain
type DomainWildcardInfo struct {
	Domain        string
	IsWildcard    bool
	WildcardIPs   map[string]struct{}
	mutex         sync.RWMutex
}

// AutoWildcardDetector manages wildcard detection across multiple domains
type AutoWildcardDetector struct {
	domains map[string]*DomainWildcardInfo
	mutex   sync.RWMutex
	runner  *Runner
}

// NewAutoWildcardDetector creates a new auto wildcard detector
func NewAutoWildcardDetector(runner *Runner) *AutoWildcardDetector {
	return &AutoWildcardDetector{
		domains: make(map[string]*DomainWildcardInfo),
		runner:  runner,
	}
}

// ExtractBaseDomain extracts the base domain from a subdomain
// e.g., "api.example.com" -> "example.com"
func (awd *AutoWildcardDetector) ExtractBaseDomain(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	
	// Return the last two parts as the base domain
	// This is a simple heuristic and may not work for all TLDs (e.g., .co.uk)
	// For production, consider using a public suffix list
	return strings.Join(parts[len(parts)-2:], ".")
}

// DetectWildcard checks if a domain has wildcard DNS configured
func (awd *AutoWildcardDetector) DetectWildcard(domain string) (*DomainWildcardInfo, error) {
	awd.mutex.RLock()
	if info, exists := awd.domains[domain]; exists {
		awd.mutex.RUnlock()
		return info, nil
	}
	awd.mutex.RUnlock()

	info := &DomainWildcardInfo{
		Domain:      domain,
		IsWildcard:  false,
		WildcardIPs: make(map[string]struct{}),
	}

	// Test with multiple random subdomains to detect wildcard
	numTests := 3
	wildcardIPs := make(map[string]int)
	
	for i := 0; i < numTests; i++ {
		randomSubdomain := xid.New().String() + "." + domain
		
		dnsData, err := awd.runner.dnsx.QueryOne(randomSubdomain)
		if err != nil || dnsData == nil {
			continue
		}

		// If we get A records for a random subdomain, it might be a wildcard
		for _, ip := range dnsData.A {
			wildcardIPs[ip]++
		}
	}

	// If we consistently get the same IPs for random subdomains, it's a wildcard
	for ip, count := range wildcardIPs {
		if count >= 2 { // At least 2 out of 3 tests returned this IP
			info.IsWildcard = true
			info.WildcardIPs[ip] = struct{}{}
		}
	}

	awd.mutex.Lock()
	awd.domains[domain] = info
	awd.mutex.Unlock()

	if info.IsWildcard {
		gologger.Verbose().Msgf("Wildcard detected for domain: %s (IPs: %v)\n", domain, getKeys(info.WildcardIPs))
	}

	return info, nil
}

// IsWildcardSubdomain checks if a subdomain resolves to wildcard IPs
func (awd *AutoWildcardDetector) IsWildcardSubdomain(host string) bool {
	baseDomain := awd.ExtractBaseDomain(host)
	
	awd.mutex.RLock()
	domainInfo, exists := awd.domains[baseDomain]
	awd.mutex.RUnlock()

	if !exists {
		// Auto-detect wildcard for this domain
		var err error
		domainInfo, err = awd.DetectWildcard(baseDomain)
		if err != nil || domainInfo == nil {
			return false
		}
	}

	if !domainInfo.IsWildcard {
		return false
	}

	// Query the subdomain
	dnsData, err := awd.runner.dnsx.QueryOne(host)
	if err != nil || dnsData == nil {
		return false
	}

	// Check if any of the returned IPs match wildcard IPs
	domainInfo.mutex.RLock()
	defer domainInfo.mutex.RUnlock()
	
	for _, ip := range dnsData.A {
		if _, isWildcard := domainInfo.WildcardIPs[ip]; isWildcard {
			return true
		}
	}

	return false
}

// GetDomainInfo returns wildcard information for a domain
func (awd *AutoWildcardDetector) GetDomainInfo(domain string) *DomainWildcardInfo {
	awd.mutex.RLock()
	defer awd.mutex.RUnlock()
	return awd.domains[domain]
}

// GetAllDomains returns all detected domains
func (awd *AutoWildcardDetector) GetAllDomains() []string {
	awd.mutex.RLock()
	defer awd.mutex.RUnlock()
	
	domains := make([]string, 0, len(awd.domains))
	for domain := range awd.domains {
		domains = append(domains, domain)
	}
	return domains
}

// getKeys returns keys from a map as a slice
func getKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
