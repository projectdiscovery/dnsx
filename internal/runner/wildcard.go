package runner

import (
	"strings"

	"github.com/rs/xid"
	"github.com/weppos/publicsuffix-go/publicsuffix"
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

// IsWildcardDomain checks if a domain has wildcard DNS records by querying a random subdomain
func (r *Runner) IsWildcardDomain(domain string) bool {
	// Check cache first
	if hasWildcard, ok := r.autoWildcardDomains.Get(domain); ok {
		return hasWildcard
	}

	// Generate a random subdomain to test for wildcards
	randomSubdomain := xid.New().String() + "." + domain
	
	in, err := r.dnsx.QueryOne(randomSubdomain)
	if err != nil || in == nil {
		// Random subdomain doesn't resolve, not a wildcard domain
		_ = r.autoWildcardDomains.Set(domain, false)
		return false
	}

	// Random subdomain resolved, this is a wildcard domain
	_ = r.autoWildcardDomains.Set(domain, true)
	return true
}

// GetBaseDomain extracts the base domain from a subdomain
func (r *Runner) GetBaseDomain(host string) string {
	// Trim trailing dot if present
	host = strings.TrimSuffix(host, ".")
	
	// Use publicsuffix library for accurate base domain extraction
	if domain, err := publicsuffix.Parse(host); err == nil {
		// domain has fields: TLD, SLD, TRD
		// For co.uk, TLD is "co.uk", SLD is "example", TRD is "sub"
		// We want eTLD+1: SLD + "." + TLD
		if domain.TLD != "" && domain.SLD != "" {
			return domain.SLD + "." + domain.TLD
		}
	}
	
	// Fallback to original logic if publicsuffix parsing fails
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	// Return the last two parts as the base domain
	return strings.Join(parts[len(parts)-2:], ".")
}

// IsWildcardAuto checks if a host is wildcard using auto detection
func (r *Runner) IsWildcardAuto(host string) bool {
	baseDomain := r.GetBaseDomain(host)
	
	// First check if this domain has wildcards
	if !r.IsWildcardDomain(baseDomain) {
		return false
	}

	// Domain has wildcards, now check if this specific host is a wildcard
	orig := make(map[string]struct{})
	wildcards := make(map[string]struct{})

	in, err := r.dnsx.QueryOne(host)
	if err != nil || in == nil {
		return false
	}
	for _, A := range in.A {
		orig[A] = struct{}{}
	}

	// Get wildcard IPs by querying random subdomains at each level
	subdomainPart := strings.TrimSuffix(host, "."+baseDomain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	var hosts []string
	hosts = append(hosts, baseDomain)

	if len(subdomainTokens) > 0 && subdomainTokens[0] != "" {
		for i := 1; i <= len(subdomainTokens); i++ {
			newhost := strings.Join(subdomainTokens[i:], ".") + "." + baseDomain
			if newhost != "" {
				hosts = append(hosts, newhost)
			}
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
