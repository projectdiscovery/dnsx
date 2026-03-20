package runner

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
)

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

// detectWildcardForDomain detects if a domain has wildcard DNS.
// Uses A-record lookups regardless of configured query types to ensure
// reliable detection even when the user queries non-A record types.
func (r *Runner) detectWildcardForDomain(domain string) bool {
	// Query a random subdomain using A-record lookup
	randomID := xid.New().String()
	testHost := randomID + "." + domain

	testIPs, err := r.dnsx.Lookup(testHost)
	if err != nil || len(testIPs) == 0 {
		return false
	}

	// If we got a response, query the root domain
	rootIPs, err := r.dnsx.Lookup(domain)
	if err != nil || len(rootIPs) == 0 {
		// Root domain doesn't resolve but random subdomain does - likely wildcard
		return true
	}

	// Check if the same IPs are returned (indicating wildcard)
	rootIPSet := make(map[string]struct{})
	for _, ip := range rootIPs {
		rootIPSet[ip] = struct{}{}
	}

	for _, ip := range testIPs {
		if _, ok := rootIPSet[ip]; !ok {
			// Different IP for random subdomain - not a wildcard
			return false
		}
	}

	// Same IPs returned - likely a wildcard
	return true
}

// AutoDetectWildcards automatically detects wildcard domains from the input
// and populates the runner's wildcard detection data
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
			r.autoWildcardDomainsMutex.Lock()
			r.autoWildcardDomains[domain] = struct{}{}
			r.autoWildcardDomainsMutex.Unlock()
			gologger.Info().Msgf("Wildcard detected for domain: %s\n", domain)
		}
	}

	gologger.Info().Msgf("Automatic wildcard detection complete. Found %d wildcard domains\n", len(r.autoWildcardDomains))

	return nil
}

// isAutoWildcardDomain checks if a domain was detected as having wildcards
func (r *Runner) isAutoWildcardDomain(domain string) bool {
	r.autoWildcardDomainsMutex.RLock()
	defer r.autoWildcardDomainsMutex.RUnlock()
	_, ok := r.autoWildcardDomains[domain]
	return ok
}

