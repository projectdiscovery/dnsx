package runner

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
)

// autoWildcardDomains stores domains that have been detected as wildcard
var autoWildcardDomains = make(map[string]struct{})
var autoWildcardDomainsMutex sync.RWMutex

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

// getRootDomain extracts the root domain from a full domain.
// Note: this is a simple heuristic that takes the last two labels,
// which works for most TLDs (e.g. example.com) but not for multi-part
// TLDs like co.uk or com.au. A public suffix list could be used for
// more accurate extraction if needed.
func getRootDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// detectWildcardForDomain detects if a domain has wildcard DNS
func (r *Runner) detectWildcardForDomain(domain string) bool {
	// Query a random subdomain to see if we get a response
	randomID := xid.New().String()
	testHost := randomID + "." + domain

	in, err := r.dnsx.QueryOne(testHost)
	if err != nil || in == nil || len(in.A) == 0 {
		return false
	}

	// If we got a response, query the root domain
	rootResult, err := r.dnsx.QueryOne(domain)
	if err != nil || rootResult == nil {
		// Root domain doesn't resolve but subdomain does - likely wildcard
		return true
	}

	// Check if the same IPs are returned (indicating wildcard)
	rootIPs := make(map[string]struct{})
	for _, a := range rootResult.A {
		rootIPs[a] = struct{}{}
	}

	for _, a := range in.A {
		if _, ok := rootIPs[a]; !ok {
			// Different IP for random subdomain - not a wildcard at root level
			return false
		}
	}

	// Same IP returned - likely a wildcard
	return true
}

// AutoDetectWildcards automatically detects wildcard domains from the input
// and populates the wildcard detection data
func (r *Runner) AutoDetectWildcards() error {
	if !r.options.AutoWildcard {
		return nil
	}

	gologger.Info().Msgf("Starting automatic wildcard detection\n")

	// Collect all unique root domains from input
	domains := make(map[string]struct{})
	r.hm.Scan(func(k, v []byte) error {
		host := string(k)
		rootDomain := getRootDomain(host)
		domains[rootDomain] = struct{}{}
		return nil
	})

	gologger.Info().Msgf("Detected %d unique domains for wildcard check\n", len(domains))

	// Test each domain for wildcard
	for domain := range domains {
		if r.detectWildcardForDomain(domain) {
			autoWildcardDomainsMutex.Lock()
			autoWildcardDomains[domain] = struct{}{}
			autoWildcardDomainsMutex.Unlock()
			gologger.Info().Msgf("Wildcard detected for domain: %s\n", domain)
		}
	}

	gologger.Info().Msgf("Automatic wildcard detection complete. Found %d wildcard domains\n", len(autoWildcardDomains))

	return nil
}

// IsAutoWildcardDomain checks if a domain was detected as having wildcards
func IsAutoWildcardDomain(domain string) bool {
	autoWildcardDomainsMutex.RLock()
	defer autoWildcardDomainsMutex.RUnlock()
	_, ok := autoWildcardDomains[domain]
	return ok
}
